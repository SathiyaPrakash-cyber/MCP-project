"""
MCP Gateway - Policy-Based Access Control for Model Context Protocol
University of Roehampton MSc Advanced Computer Science

``POST /mcp`` speaks the Model Context Protocol at revision 2026-07-28
(JSON-RPC 2.0 over the Streamable HTTP transport; see ``mcp_protocol.py``
for the revision-specific validation rules). The custom REST adapter
``POST /mcp/v1/tools/call`` remains for the evaluation harness only and is
explicitly NOT MCP. Both endpoints share one enforcement path
(``_execute_tool_call``): one OPA policy decision, one fail-closed schema
pin, and the audit-before-execution ordering described in
``audit_logger.AuditRecord``.
"""

import asyncio
import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

import httpx
import structlog
import uvicorn
from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import jsonrpc
from . import mcp_protocol
from .auth import verify_token, TokenClaims
from .policy_engine import PolicyEngine, PolicyDecision
from .audit_logger import AuditLogger, AuditWriteError
from .models import MCPRequest, MCPResponse, GatewayConfig, AuditRecord
from .policy_versioning import PolicyVersionManager
from .schema_pinning import ToolSchemaPinning
from .mcp_protocol import McpValidationError, McpUpstreamError
from .admin_api import router as _admin_router, set_policy_manager

# Structured logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        structlog.processors.JSONRenderer(),
    ]
)
log = structlog.get_logger()

# Globals (initialized on startup)
policy_engine: PolicyEngine | None = None
audit_logger: AuditLogger | None = None
http_client: httpx.AsyncClient | None = None
config: GatewayConfig | None = None
schema_pinner: ToolSchemaPinning | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    global policy_engine, audit_logger, http_client, config, schema_pinner

    log.info("mcp_gateway.starting")

    # A2: fail-fast on missing/insecure JWT secret
    from .auth import _assert_secret_ok
    _assert_secret_ok()

    config = GatewayConfig()
    policy_engine = PolicyEngine(opa_url=config.opa_url)
    audit_logger = AuditLogger(log_dir=config.log_dir)
    http_client = httpx.AsyncClient(timeout=30.0)

    await audit_logger.initialize()

    pm = PolicyVersionManager(
        policy_dir="/app/policies",
        opa_url=config.opa_url,
    )
    set_policy_manager(pm)

    # A6: policy v1 seeded via policies/version_store.json (loaded by PolicyVersionManager above)
    if pm._versions:
        log.info("mcp_gateway.policy_seeded", count=len(pm._versions))
    else:
        log.warning("mcp_gateway.policy_seed_skipped", reason="version_store.json empty or missing")

    # E1: schema-pinning — per-upstream baselines via MCP tools/list.
    # Each upstream is sealed independently; an upstream whose baseline could
    # not be built stays unsealed and every call routed to it is denied
    # (fail-closed). Set SCHEMA_PIN_REQUIRED=1 to refuse to start in that case.
    schema_pinner = ToolSchemaPinning()
    _pin_required = os.getenv("SCHEMA_PIN_REQUIRED", "0") == "1"
    for upstream in _all_upstreams(config):
        sealed = await _pin_upstream_baseline(upstream)
        if not sealed and _pin_required:
            msg = f"Failed to pin schema baseline for upstream '{upstream}'"
            log.error("mcp_gateway.schema_pin_fatal", upstream=upstream)
            raise RuntimeError(msg)

    log.info("mcp_gateway.ready", opa_url=config.opa_url)

    yield

    await http_client.aclose()
    log.info("mcp_gateway.shutdown")


def _all_upstreams(cfg: GatewayConfig) -> list[str]:
    """Every distinct upstream base URL the gateway can route to."""
    bases = set(cfg.upstream_routes.values())
    bases.add(cfg.upstream_default)
    return sorted(bases)


async def _pin_upstream_baseline(upstream: str) -> bool:
    """Discover and seal one upstream's tool baseline over MCP (5 attempts)."""
    for attempt in range(1, 6):
        try:
            tools = await mcp_protocol.mcp_tools_list_all(http_client, upstream)
            if not tools:
                raise RuntimeError(
                    "upstream advertised an empty tool list; cannot distinguish "
                    "this from an outage, so no baseline was sealed"
                )
            schema_pinner.register_many(upstream, tools)
            schema_pinner.seal(upstream)
            log.info(
                "mcp_gateway.schema_pinned",
                upstream=upstream,
                count=len(tools),
                sealed=True,
            )
            return True
        except Exception as e:  # noqa: BLE001 - retry any failure
            log.warning(
                "mcp_gateway.schema_pin_attempt_failed",
                upstream=upstream,
                attempt=attempt,
                error=str(e),
            )
            await asyncio.sleep(2)
    log.error(
        "mcp_gateway.schema_pin_failed_deny_all",
        upstream=upstream,
        error="Failed to pin upstream tool schemas after 5 attempts; "
        "this upstream will deny all tool calls until a snapshot is sealed.",
    )
    return False


app = FastAPI(
    title="MCP Gateway",
    description="Policy-Based Access Control Gateway for Model Context Protocol",
    version="1.2.0",
    lifespan=lifespan,
)

# CORS is restricted to an explicit origin list. A wildcard here would let any
# page in the user's browser replay their bearer token against the gateway.
# The same list is enforced on ``POST /mcp`` as the MCP Origin check
# (DNS-rebinding defence required by the Streamable HTTP transport).
_cors_origins = [
    o.strip()
    for o in os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:8080").split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        mcp_protocol.HEADER_PROTOCOL_VERSION,
        mcp_protocol.HEADER_METHOD,
        mcp_protocol.HEADER_NAME,
    ],
)


# ─────────────────────────────────────────────────────────────────────────────
# Schema-pinning guard (E1) — fail closed, per upstream
# ─────────────────────────────────────────────────────────────────────────────

async def _schema_guard(upstream: str, tool_name: str) -> tuple[str | None, str]:
    """
    Verify a tool's live definition against the snapshot pinned at startup.

    Returns ``(None, "")`` when the call may proceed, or ``(reason, rule)``
    describing why it must be denied. Every failure path denies:

    * this upstream never completed a valid pinning pass       -> deny
    * the tool is absent from the pinned snapshot              -> deny
    * the tool has disappeared from the live upstream listing  -> deny
    * the upstream listing cannot be fetched or parsed         -> deny
    * the live definition differs from the pinned one (rug pull) -> deny
    """
    if schema_pinner is None or not schema_pinner.is_ready(upstream):
        return (
            f"Gateway has no verified tool-schema snapshot for upstream "
            f"'{upstream}'; refusing tool calls.",
            "schema_pinning_unavailable",
        )

    if not schema_pinner.is_pinned(upstream, tool_name):
        return (
            f"Tool '{tool_name}' is not present in the pinned schema snapshot "
            f"for upstream '{upstream}'.",
            "tool_not_pinned",
        )

    try:
        tools = await mcp_protocol.mcp_tools_list_all(http_client, upstream)
        live = {t.get("name"): t for t in tools}
    except Exception as exc:  # noqa: BLE001 - any failure must fail closed
        log.warning(
            "gateway.schema_lookup_failed",
            upstream=upstream,
            tool=tool_name,
            error=str(exc),
        )
        return (
            "Unable to verify the tool schema against the upstream server; "
            "the call was denied rather than forwarded unverified.",
            "schema_verification_unavailable",
        )

    current = live.get(tool_name)
    if current is None:
        return (
            f"Tool '{tool_name}' is pinned but no longer advertised by the "
            f"upstream server; the call was denied rather than forwarded.",
            "tool_withdrawn_upstream",
        )

    ok, msg = schema_pinner.verify(upstream, tool_name, current)
    if not ok:
        return (msg, "rug_pull_detected")

    return (None, "")


# ─────────────────────────────────────────────────────────────────────────────
# Core enforcement path (PEP) — shared by the REST adapter and POST /mcp
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/mcp/v1/tools/call")
async def gateway_tool_call(
    request: Request,
    claims: TokenClaims = Depends(verify_token),
):
    """
    Custom REST adapter (the shape used by the evaluation harness).

    This endpoint is NOT the Model Context Protocol — it is a REST shape of
    this project's own design. The standards-compliant MCP interface is
    ``POST /mcp``; both endpoints share the same enforcement path in
    ``_execute_tool_call``.
    """
    try:
        body: dict = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    return JSONResponse(
        content=await _execute_tool_call(
            request=request,
            claims=claims,
            tool_name=body.get("tool", {}).get("name", ""),
            tool_args=body.get("arguments", {}),
            session_id=body.get("session_id", ""),
            raw=body,
        )
    )


async def _execute_tool_call(
    request: Request,
    claims: TokenClaims,
    tool_name: str,
    tool_args: dict,
    session_id: str,
    raw: dict,
) -> dict:
    """
    Policy Enforcement Point (PEP) — shared by the REST adapter and POST /mcp.

    1. Build the policy input from the request and the caller's token claims
    2. Evaluate against OPA policy (RBAC + ABAC)
    3. If DENY: audit the denial (fail-loud if the log cannot be written) and
       refuse the request
    4. If ALLOW: write the durable ``authorization`` record FIRST — if that
       write fails the tool is NOT executed and the client gets a 503
    5. Verify the tool definition against the per-upstream pinned snapshot
       (fail closed) and refuse on any failure
    6. Forward to the upstream MCP server as a real MCP ``tools/call``
    7. Audit the ``completion`` (or failure) after the upstream returns
    """
    request_id = str(uuid.uuid4())
    start_ts = time.time()

    mcp_req = MCPRequest(
        tool_name=tool_name,
        tool_args=tool_args,
        session_id=session_id,
        raw=raw,
    )

    log.info(
        "gateway.request_received",
        request_id=request_id,
        tool=mcp_req.tool_name,
        user=claims.sub,
        role=claims.role,
    )

    # ── Policy Decision ─────────────────────────────────────────────────────
    policy_input = _build_policy_input(mcp_req, claims, request)
    decision: PolicyDecision = await policy_engine.evaluate(policy_input)

    latency_policy_ms = round((time.time() - start_ts) * 1000, 2)

    def _base_audit(**overrides) -> AuditRecord:
        fields: dict = dict(
            request_id=request_id,
            timestamp=start_ts,
            user_id=claims.sub,
            role=claims.role,
            tool_name=mcp_req.tool_name,
            policy_decision=decision.allow,
            policy_reason=decision.reason,
            policy_rule_matched=decision.rule_matched,
            latency_policy_ms=latency_policy_ms,
            source_ip=request.client.host if request.client else "unknown",
            session_id=mcp_req.session_id,
        )
        fields.update(overrides)
        return AuditRecord(**fields)

    if not decision.allow:
        # A denial is safe even if the log write fails — the request is
        # refused either way — but a failed denial write is still a lost
        # security event, so it is logged loudly rather than swallowed.
        try:
            await audit_logger.write(_base_audit(denied=True, event_type="denial"))
        except AuditWriteError as e:
            log.critical(
                "gateway.denial_audit_write_failed",
                request_id=request_id,
                tool=mcp_req.tool_name,
                user=claims.sub,
                error=str(e),
            )
        log.warning(
            "gateway.request_denied",
            request_id=request_id,
            tool=mcp_req.tool_name,
            user=claims.sub,
            reason=decision.reason,
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": "access_denied",
                "reason": decision.reason,
                "request_id": request_id,
                "gateway_meta": {"policy_latency_ms": latency_policy_ms},
            },
        )

    # ── Audit-before-execution: durable authorisation grant ────────────────
    # The ALLOW decision is written and fsynced BEFORE the upstream is
    # contacted. If the audit log cannot be written the request is refused:
    # executing a call whose authorisation was never recorded would break the
    # chain-of-custody property the audit mechanism exists to provide.
    try:
        await audit_logger.write(_base_audit(event_type="authorization"))
    except AuditWriteError as e:
        log.critical(
            "gateway.authorization_audit_failed_request_refused",
            request_id=request_id,
            tool=mcp_req.tool_name,
            user=claims.sub,
            error=str(e),
        )
        raise HTTPException(
            status_code=503,
            detail={
                "error": "audit_unavailable",
                "reason": "The audit log could not be written; the request "
                "was refused rather than executed without a durable record.",
                "request_id": request_id,
            },
        )

    upstream_base = _resolve_upstream_base(mcp_req.tool_name, config)

    # ── E1: rug-pull check — verify tool definition hasn't drifted ─────────
    # Fails CLOSED: a tool that is not in the pinned snapshot, a tool that has
    # disappeared upstream, and any error while fetching or comparing schemas
    # all deny the call.
    _reason, _rule = await _schema_guard(upstream_base, mcp_req.tool_name)
    if _reason is not None:
        try:
            await audit_logger.write(
                _base_audit(
                    denied=True,
                    policy_reason=_reason,
                    policy_rule_matched=_rule,
                    latency_total_ms=round((time.time() - start_ts) * 1000, 2),
                    event_type="denial",
                )
            )
        except AuditWriteError as e:
            log.critical(
                "gateway.schema_denial_audit_write_failed",
                request_id=request_id,
                tool=mcp_req.tool_name,
                error=str(e),
            )
        log.warning(
            "gateway.schema_guard_denied",
            request_id=request_id,
            tool=mcp_req.tool_name,
            rule=_rule,
            reason=_reason,
        )
        raise HTTPException(
            status_code=403,
            detail={"error": _rule, "reason": _reason, "request_id": request_id},
        )

    # ── Forward to upstream as a real MCP 2026-07-28 tools/call ────────────
    upstream_start = time.time()
    upstream_result: dict
    upstream_error: str | None = None

    try:
        upstream_result = await mcp_protocol.mcp_request(
            http_client,
            upstream_base,
            "tools/call",
            params={"name": mcp_req.tool_name, "arguments": mcp_req.tool_args},
            token=claims.raw_token,
            request_id=request_id,
        )
    except McpUpstreamError as e:
        upstream_error = str(e)
        try:
            await audit_logger.write(
                _base_audit(
                    upstream_error=upstream_error,
                    latency_upstream_ms=round((time.time() - upstream_start) * 1000, 2),
                    latency_total_ms=round((time.time() - start_ts) * 1000, 2),
                    event_type="completion",
                )
            )
        except AuditWriteError as aw:
            log.critical(
                "gateway.completion_audit_write_failed",
                request_id=request_id,
                tool=mcp_req.tool_name,
                error=str(aw),
            )
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "completion_audit_unavailable",
                    "message": "The upstream outcome is uncertain and its completion audit record could not be persisted.",
                    "request_id": request_id,
                    "tool_execution_may_have_succeeded": True,
                    "audit_recorded": False,
                    "upstream_error": upstream_error,
                },
            ) from aw
        raise HTTPException(
            status_code=502,
            detail=f"Upstream MCP server error: {upstream_error}",
        )

    # ── Completion audit ────────────────────────────────────────────────────
    latency_upstream_ms = round((time.time() - upstream_start) * 1000, 2)
    latency_total_ms = round((time.time() - start_ts) * 1000, 2)
    try:
        await audit_logger.write(
            _base_audit(
                latency_upstream_ms=latency_upstream_ms,
                latency_total_ms=latency_total_ms,
                event_type="completion",
            )
        )
    except AuditWriteError as e:
        log.critical(
            "gateway.completion_audit_write_failed",
            request_id=request_id,
            tool=mcp_req.tool_name,
            error=str(e),
        )
        # Execution already happened. Report the outcome honestly and fail the
        # request; the caller must not receive a normal success without the
        # required completion event.
        raise HTTPException(
            status_code=503,
            detail={
                "error": "completion_audit_unavailable",
                "message": "The tool executed, but its completion audit record could not be persisted.",
                "request_id": request_id,
                "tool_execution_may_have_succeeded": True,
                "audit_recorded": False,
            },
        ) from e

    log.info(
        "gateway.request_allowed",
        request_id=request_id,
        tool=mcp_req.tool_name,
        user=claims.sub,
        latency_ms=latency_total_ms,
    )

    return {
        "data": upstream_result,
        "gateway_meta": {
            "request_id": request_id,
            "policy_latency_ms": latency_policy_ms,
            "total_latency_ms": latency_total_ms,
        },
    }


@app.post("/mcp/v1/tools/list")
async def list_tools(
    request: Request,
    claims: TokenClaims = Depends(verify_token),
):
    """
    Custom REST adapter: returns only the tools the caller is permitted to
    see. Prevents information leakage about tools the user has no access to.
    """
    return JSONResponse(content={"tools": await _visible_tools(request, claims)})


async def _visible_tools(request: Request, claims: TokenClaims) -> list[dict]:
    """Policy-filtered upstream tool list — shared by the REST adapter and /mcp."""
    all_tools: list[dict] = []
    for upstream in _all_upstreams(config):
        try:
            all_tools.extend(
                await mcp_protocol.mcp_tools_list_all(http_client, upstream)
            )
        except Exception:
            log.warning("gateway.tools_list_upstream_failed", upstream=upstream)

    # Deduplicate by name (several prefixes may share one upstream).
    seen: dict[str, dict] = {}
    for tool in all_tools:
        name = tool.get("name")
        if name and name not in seen:
            seen[name] = tool

    visible_tools = []
    for name, tool in seen.items():
        policy_input = _build_policy_input(
            MCPRequest(tool_name=name, tool_args={}, session_id="", raw={}),
            claims,
            request,
        )
        decision = await policy_engine.evaluate(policy_input)
        if decision.allow:
            visible_tools.append(tool)

    return visible_tools


# ─────────────────────────────────────────────────────────────────────────────
# MCP endpoint — Model Context Protocol revision 2026-07-28
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/mcp")
async def mcp_endpoint(
    request: Request,
    claims: TokenClaims = Depends(verify_token),
):
    """
    Model Context Protocol endpoint at revision 2026-07-28.

    Validation order follows the specification: Origin, parse, envelope,
    per-request ``_meta``, HTTP metadata headers, then dispatch. Supported
    methods: ``server/discover``, ``tools/list``, ``tools/call``.

    Transport-level failures use the HTTP statuses the specification
    mandates (403 Origin, 400 malformed/mismatched metadata, 404 unknown
    method, 202 notification). Application-level outcomes — a policy denial,
    a schema-pin denial, an upstream error — are returned as JSON-RPC error
    envelopes with HTTP 200, because a conforming MCP client reads the
    envelope, not the transport.

    Enforcement is identical to the REST adapter: both call
    ``_execute_tool_call`` and therefore share one policy, schema-pinning,
    audit-before-execution and upstream path.
    """
    # ── 1. Origin (Streamable HTTP security requirement) ───────────────────
    try:
        mcp_protocol.validate_origin(request.headers.get("origin"), _cors_origins)
    except McpValidationError as e:
        return JSONResponse(
            status_code=e.http_status,
            content=jsonrpc.error(None, e.code, e.message, e.data),
        )

    # ── 2. Parse ───────────────────────────────────────────────────────────
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content=jsonrpc.error(None, jsonrpc.PARSE_ERROR, data="Parse error"),
        )

    # ── 3. Transport carries ONE request or notification per POST ──────────
    if isinstance(payload, list):
        return JSONResponse(
            status_code=400,
            content=jsonrpc.error(
                None,
                jsonrpc.INVALID_REQUEST,
                data="batch requests are not supported on this transport "
                "(MCP 2026-07-28, Streamable HTTP)",
            ),
        )

    # ── 4. JSON-RPC envelope ───────────────────────────────────────────────
    try:
        request_id, method, params = jsonrpc.validate(payload)
    except jsonrpc.JsonRpcError as e:
        # Malformed envelope: HTTP 400, null id (the id cannot be trusted).
        return JSONResponse(
            status_code=400, content=jsonrpc.error(None, e.code, e.message, e.data)
        )

    notification = jsonrpc.is_notification(payload)

    # ── 4a. Legacy ``initialize`` (checked before the _meta requirement) ────
    # A client on a pre-2026-07-28 revision opens with ``initialize`` and does
    # not send per-request ``_meta``. Answering it as an unknown method that
    # names the supported revisions is only helpful if it happens before the
    # ``_meta`` requirement is enforced — otherwise the legacy client gets a
    # confusing "missing metadata" error instead of the actionable one.
    if method == "initialize" and not notification:
        return JSONResponse(
            status_code=404,
            content=jsonrpc.error(
                request_id,
                jsonrpc.METHOD_NOT_FOUND,
                message=(
                    "initialize is not used in revision "
                    f"{mcp_protocol.MCP_PROTOCOL_VERSION}; this server implements "
                    f"{', '.join(mcp_protocol.SUPPORTED_VERSIONS)}. Send per-request "
                    "protocol metadata in params._meta instead."
                ),
                data={"supportedVersions": list(mcp_protocol.SUPPORTED_VERSIONS)},
            ),
        )

    # ── 5. Required per-request protocol metadata (params._meta) ───────────
    try:
        meta = mcp_protocol.validate_request_meta(params)
    except McpValidationError as e:
        return JSONResponse(
            status_code=e.http_status,
            content=jsonrpc.error(
                None if notification else request_id, e.code, e.message, e.data
            ),
        )

    # ── 6. HTTP request-metadata headers ───────────────────────────────────
    body_name = params.get("name") if isinstance(params.get("name"), str) else None
    try:
        mcp_protocol.validate_accept_header(request.headers.get("accept"))
        mcp_protocol.validate_protocol_headers(
            request.headers, method, meta[mcp_protocol.META_PROTOCOL_VERSION], body_name
        )
    except McpValidationError as e:
        return JSONResponse(
            status_code=e.http_status,
            content=jsonrpc.error(
                None if notification else request_id, e.code, e.message, e.data
            ),
        )

    # ── 7. Notifications are acknowledged with 202, empty body ─────────────
    if notification:
        return Response(status_code=202)

    # ── 8. Dispatch ────────────────────────────────────────────────────────
    try:
        result = await _invoke_mcp_method(request, claims, method, params)
    except jsonrpc.JsonRpcError as e:
        status = 404 if e.code == jsonrpc.METHOD_NOT_FOUND else 200
        return JSONResponse(
            status_code=status,
            content=jsonrpc.error(request_id, e.code, e.message, e.data),
        )
    except HTTPException as e:
        code, data = _http_to_jsonrpc(e)
        if e.status_code == 503:
            return JSONResponse(
                status_code=503,
                content=jsonrpc.error(request_id, code, data=data),
            )
        return JSONResponse(
            status_code=200, content=jsonrpc.error(request_id, code, data=data)
        )
    except Exception as e:  # noqa: BLE001
        log.error("mcp.unhandled", method=method, error=str(e))
        return JSONResponse(
            status_code=200,
            content=jsonrpc.error(request_id, jsonrpc.INTERNAL_ERROR, data=str(e)),
        )

    # ── 9. Every result carries resultType and serverInfo in _meta ────────
    result.setdefault("resultType", "complete")
    result_meta = result.setdefault("_meta", {})
    if isinstance(result_meta, dict):
        result_meta.setdefault(
            mcp_protocol.META_SERVER_INFO, mcp_protocol.SERVER_INFO
        )

    return JSONResponse(content=jsonrpc.success(request_id, result))


async def _invoke_mcp_method(
    request: Request, claims: TokenClaims, method: str, params: dict
) -> Any:
    """Route a validated MCP method to the gateway's enforcement path."""
    if method == "initialize":
        # Revision 2026-07-28 has no initialize handshake; a client still
        # sending one is on a legacy revision. Per the specification this is
        # answered as an unknown method naming the supported revisions.
        raise jsonrpc.JsonRpcError(
            jsonrpc.METHOD_NOT_FOUND,
            message=(
                "initialize is not used in revision 2026-07-28; this server "
                f"implements {', '.join(mcp_protocol.SUPPORTED_VERSIONS)}. "
                "Send per-request protocol metadata in params._meta instead."
            ),
            data={"supportedVersions": list(mcp_protocol.SUPPORTED_VERSIONS)},
        )

    if method == "server/discover":
        return {
            "supportedVersions": list(mcp_protocol.SUPPORTED_VERSIONS),
            "capabilities": {"tools": {"listChanged": False}},
            "instructions": "Policy-enforcing MCP gateway (PBAC).",
            "cacheScope": "private",
            "ttlMs": 0,
        }

    if method == "tools/list":
        return {
            "tools": await _visible_tools(request, claims),
            "cacheScope": "private",
            "ttlMs": 0,
        }

    if method == "tools/call":
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise jsonrpc.JsonRpcError(
                jsonrpc.INVALID_PARAMS, data="'name' is required and must be a string"
            )
        arguments = params.get("arguments", {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise jsonrpc.JsonRpcError(
                jsonrpc.INVALID_PARAMS, data="'arguments' must be an object"
            )

        meta = params.get("_meta", {}) or {}
        session_id = meta.get(mcp_protocol.GATEWAY_META_SESSION_ID) or meta.get(
            "sessionId", ""
        )

        outcome = await _execute_tool_call(
            request=request,
            claims=claims,
            tool_name=name,
            tool_args=arguments,
            session_id=str(session_id),
            raw={"tool": {"name": name}, "arguments": arguments},
        )
        return _to_mcp_result(outcome)

    raise jsonrpc.JsonRpcError(
        jsonrpc.METHOD_NOT_FOUND, data=f"unknown method '{method}'"
    )


def _to_mcp_result(outcome: dict) -> dict:
    """
    Translate the gateway's internal result into an MCP ``CallToolResult``.

    MCP expects a ``content`` array of typed blocks plus an ``isError`` flag
    (and ``resultType``/``_meta``, added by the endpoint). Gateway telemetry
    is carried in ``_meta`` under this gateway's own dotted namespace, which
    the specification reserves for implementation-specific data, so a
    standard client can ignore it.
    """
    data = outcome.get("data", {})
    content = data.get("content")
    if not isinstance(content, list):
        content = [{"type": "text", "text": json.dumps(data, default=str)}]
    meta = outcome.get("gateway_meta", {})
    return {
        "content": content,
        "isError": bool(data.get("isError", False)),
        "structuredContent": data.get("structuredContent"),
        "_meta": {
            mcp_protocol.GATEWAY_META_REQUEST_ID: meta.get("request_id"),
            mcp_protocol.GATEWAY_META_POLICY_MS: meta.get("policy_latency_ms"),
            mcp_protocol.GATEWAY_META_TOTAL_MS: meta.get("total_latency_ms"),
        },
    }


def _http_to_jsonrpc(exc: HTTPException) -> tuple[int, Any]:
    """Map an internal HTTPException onto a JSON-RPC error code."""
    detail = exc.detail if isinstance(exc.detail, dict) else {}
    kind = detail.get("error", "") if isinstance(detail, dict) else ""
    if kind == "audit_unavailable":
        return jsonrpc.AUDIT_UNAVAILABLE, detail
    if exc.status_code == 403:
        if kind in {
            "rug_pull_detected",
            "tool_not_pinned",
            "tool_withdrawn_upstream",
            "schema_pinning_unavailable",
            "schema_verification_unavailable",
        }:
            return jsonrpc.SCHEMA_DENIED, detail
        return jsonrpc.POLICY_DENIED, detail
    if exc.status_code in (502, 504):
        return jsonrpc.UPSTREAM_ERROR, detail
    if exc.status_code == 400:
        return jsonrpc.INVALID_PARAMS, detail
    return jsonrpc.INTERNAL_ERROR, detail


# ─────────────────────────────────────────────────────────────────────────────
# Admin / Health endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    opa_healthy = await policy_engine.health_check()
    return {
        "status": "ok" if opa_healthy else "degraded",
        "opa": "reachable" if opa_healthy else "unreachable",
        "timestamp": time.time(),
    }


@app.get("/metrics")
async def metrics(claims: TokenClaims = Depends(verify_token)):
    """Basic metrics endpoint. In prod, wire to Prometheus."""
    if claims.role not in ("admin", "security_analyst"):
        raise HTTPException(status_code=403, detail="Insufficient role")
    stats = await audit_logger.get_stats()
    return stats


@app.get("/audit/recent")
async def get_recent_audit(
    limit: int = 50,
    claims: TokenClaims = Depends(verify_token),
):
    """Return recent audit records. Admin/analyst only."""
    if claims.role not in ("admin", "security_analyst"):
        raise HTTPException(status_code=403, detail="Insufficient role")
    records = await audit_logger.get_recent(limit=limit)
    return {"records": records, "count": len(records)}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _build_policy_input(
    mcp_req: MCPRequest,
    claims: TokenClaims,
    request: Request,
) -> dict:
    """
    Constructs the OPA input document.
    Combines identity (RBAC) + context (ABAC) attributes.
    """
    return {
        "input": {
            # RBAC attributes
            "user": {
                "id": claims.sub,
                "role": claims.role,
                "groups": claims.groups,
                "email": claims.email,
            },
            # Tool attributes
            "tool": {
                "name": mcp_req.tool_name,
                "args": mcp_req.tool_args,
            },
            # ABAC context attributes
            "context": {
                "time_utc": time.strftime("%H:%M", time.gmtime()),
                "source_ip": request.client.host if request.client else "unknown",
                "session_id": mcp_req.session_id,
                "hour": int(time.strftime("%H", time.gmtime())),
            },
            # Environment
            "environment": {
                "gateway_version": "1.2.0",
            },
        }
    }


def _resolve_upstream_base(tool_name: str, cfg: GatewayConfig) -> str:
    """
    Route to the correct upstream MCP server based on tool-name prefix.
    Returns the upstream's BASE URL; the gateway always talks MCP at
    ``{base}/mcp``.
    """
    for prefix, url in cfg.upstream_routes.items():
        if tool_name.startswith(prefix):
            return url.rstrip("/")
    return cfg.upstream_default.rstrip("/")


if __name__ == "__main__":
    uvicorn.run("gateway.main:app", host="0.0.0.0", port=8080, reload=False)

# ── Phase 3: Admin API + Dashboard ──────────────────────────────────────────
from pathlib import Path as _Path
from pathlib import Path
from fastapi.responses import HTMLResponse as _HTMLResponse
from gateway.admin_api import router as _admin_router

app.include_router(_admin_router)

@app.get("/dashboard", response_class=_HTMLResponse, include_in_schema=False)
async def dashboard():
    html_file = _Path(__file__).parent / "dashboard.html"
    return _HTMLResponse(content=html_file.read_text(), status_code=200)
@app.exception_handler(401)
async def _auth_failure_audit(request, exc):
    if audit_logger:
        import uuid as _u, time as _t
        from .models import AuditRecord as _AR
        import asyncio as _a
        rec = _AR(
            request_id=str(_u.uuid4()),
            timestamp=_t.time(),
            user_id="unknown", role="unknown",
            tool_name=str(request.url.path),
            policy_decision=False,
            policy_reason="auth_failure: " + str(getattr(exc, "detail", "")),
            policy_rule_matched="auth_deny",
            latency_policy_ms=0.0,
            source_ip=request.client.host if request.client else "unknown",
            session_id="", denied=True,
            event_type="denial",
        )
        _a.create_task(audit_logger.write(rec))
    from fastapi.responses import JSONResponse as _J
    return _J(status_code=401, content={"detail": getattr(exc, "detail", "Unauthorized")})
