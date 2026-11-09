"""
MCP protocol constants and validation helpers — target revision 2026-07-28.

Revision 2026-07-28 is a *modern* (per-request-metadata) revision of the Model
Context Protocol. The changes that matter for this gateway, all taken from the
published specification at modelcontextprotocol.io/specification/2026-07-28:

* there is no ``initialize`` handshake and no protocol-level session. Every
  request is stateless and carries its own protocol metadata in
  ``params._meta`` under the reserved key
  ``io.modelcontextprotocol/protocolVersion``; ``io.modelcontextprotocol/
  clientCapabilities`` is required on every request as well. A request that
  omits a required field is malformed and must be rejected with JSON-RPC
  ``-32602`` and HTTP 400.
* on the Streamable HTTP transport every POST must carry the
  ``MCP-Protocol-Version`` header (which must equal the ``_meta`` version),
  the ``Mcp-Method`` header (which must equal the body's ``method``), and —
  for ``tools/call``, ``resources/read`` and ``prompts/get`` — the ``Mcp-Name``
  header. Mismatches and missing headers are rejected with JSON-RPC ``-32020``
  (``HeaderMismatch``) and HTTP 400.
* an unsupported protocol version is rejected with ``-32022``
  (``UnsupportedProtocolVersion``) listing the versions the server does
  implement, HTTP 400.
* servers MUST implement ``server/discover``.
* every result carries a ``resultType`` field (``"complete"`` for a finished
  request), and servers SHOULD echo ``io.modelcontextprotocol/serverInfo``
  in each result's ``_meta``.
* JSON-RPC request IDs MUST NOT be ``null``.
* the transport body MUST be a single JSON-RPC request or notification —
  JSON-RPC batching is not part of this revision's Streamable HTTP transport.
* servers MUST validate the ``Origin`` header (DNS-rebinding defence): an
  present-but-unrecognised Origin is answered with HTTP 403.
* protocol-defined error codes live in ``-32020..-32099``; the sub-range
  ``-32000..-32019`` is legacy and new implementations must not allocate in
  it. This gateway's application-specific denial codes are therefore
  allocated *outside* the JSON-RPC reserved range (``-32768..-32000``), as
  the specification directs.

The upstream side of the gateway speaks the same revision: ``mock_server.py``
is a 2026-07-28 server, and every gateway-to-upstream call made through
:func:`mcp_request` carries the required headers and per-request ``_meta``.
"""

from __future__ import annotations

import base64
import json
import uuid
from typing import Any

import httpx

from . import jsonrpc

# ── Protocol identity ────────────────────────────────────────────────────────

MCP_PROTOCOL_VERSION = "2026-07-28"
SUPPORTED_VERSIONS: tuple[str, ...] = (MCP_PROTOCOL_VERSION,)

SERVER_INFO = {
    "name": "mcp-gateway-pbac",
    "version": "1.2.0",
    "title": "MCP Gateway with Policy-Based Access Control",
}

# ── Reserved ``_meta`` keys (specification: Basic _meta) ─────────────────────

META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"

# This gateway's own extension namespace for carrying gateway telemetry in
# ``_meta`` without colliding with MCP-reserved keys. The prefix follows the
# reserved-key naming rules (dot-separated labels, second label is not
# "modelcontextprotocol" or "mcp", trailing slash before the key name).
GATEWAY_META_PREFIX = "uk.ac.roehampton.mcpgateway/"
GATEWAY_META_REQUEST_ID = GATEWAY_META_PREFIX + "requestId"
GATEWAY_META_POLICY_MS = GATEWAY_META_PREFIX + "policyLatencyMs"
GATEWAY_META_TOTAL_MS = GATEWAY_META_PREFIX + "totalLatencyMs"
GATEWAY_META_SESSION_ID = GATEWAY_META_PREFIX + "sessionId"

# ── HTTP header names (Streamable HTTP: Request Metadata) ───────────────────

HEADER_PROTOCOL_VERSION = "MCP-Protocol-Version"
HEADER_METHOD = "Mcp-Method"
HEADER_NAME = "Mcp-Name"

_BASE64_SENTINEL_PREFIX = "=?base64?"
_BASE64_SENTINEL_SUFFIX = "?="

#: Methods for which the specification requires the ``Mcp-Name`` header.
_METHODS_REQUIRING_NAME = {"tools/call", "resources/read", "prompts/get"}


class McpValidationError(Exception):
    """A transport-level MCP validation failure.

    Carries the JSON-RPC error code, a message, the HTTP status the
    specification requires for that failure, and optional ``data``.
    """

    def __init__(self, code: int, message: str, http_status: int = 400, data: Any = None):
        self.code = code
        self.message = message
        self.http_status = http_status
        self.data = data
        super().__init__(message)


def decode_header_value(value: str) -> str:
    """Decode the Base64 sentinel encoding used for unsafe header values.

    ``=?base64?{payload}?=`` wraps a Base64-encoded UTF-8 value; plain ASCII
    values are returned unchanged. Used for ``Mcp-Name`` comparisons.
    """
    if value.startswith(_BASE64_SENTINEL_PREFIX) and value.endswith(_BASE64_SENTINEL_SUFFIX):
        payload = value[len(_BASE64_SENTINEL_PREFIX) : -len(_BASE64_SENTINEL_SUFFIX)]
        try:
            return base64.b64decode(payload, validate=True).decode("utf-8")
        except Exception as exc:  # noqa: BLE001 - malformed sentinel
            raise McpValidationError(
                jsonrpc.HEADER_MISMATCH,
                f"Mcp-Name carries a malformed base64 sentinel value: {exc}",
            ) from exc
    return value


def validate_origin(origin: str | None, allowed_origins: list[str]) -> None:
    """Streamable HTTP security requirement: validate the Origin header.

    A missing Origin (non-browser client) is accepted. A present Origin that
    is not in the configured allow-list raises a 403 — the specification's
    mandated answer to an invalid Origin, which exists to stop DNS-rebinding
    attacks against local servers.
    """
    if origin is None:
        return
    if origin not in allowed_origins:
        raise McpValidationError(
            jsonrpc.INVALID_REQUEST,
            f"Origin '{origin}' is not permitted to call this MCP endpoint",
            http_status=403,
        )


def validate_accept_header(accept: str | None) -> None:
    """Clients should advertise both JSON and SSE acceptance on every POST.

    A missing header, or the wildcard ``*/*`` (the default for common HTTP
    clients such as httpx and curl), is accepted: the requirement exists so
    clients can consume a streaming response, not so the server can reject a
    client that does not advertise one. A *present* header that names
    concrete types must name both.
    """
    if accept is None:
        return
    types = {t.split(";")[0].strip().lower() for t in accept.split(",")}
    if "*/*" in types:
        return
    if not {"application/json", "text/event-stream"} <= types:
        raise McpValidationError(
            jsonrpc.HEADER_MISMATCH,
            "Accept header must include application/json and text/event-stream "
            "(or */*)",
        )


def validate_request_meta(params: dict) -> dict:
    """Validate the required per-request protocol fields in ``params._meta``.

    Returns the ``_meta`` object. Raises ``-32602`` (HTTP 400) when a required
    field is missing or malformed, as the specification requires.
    """
    meta = params.get("_meta")
    if meta is None:
        meta = {}
    if not isinstance(meta, dict):
        raise McpValidationError(
            jsonrpc.INVALID_PARAMS,
            "'params._meta' must be an object when present",
        )

    missing: list[str] = []
    version = meta.get(META_PROTOCOL_VERSION)
    if not isinstance(version, str) or not version:
        missing.append(META_PROTOCOL_VERSION)
    if META_CLIENT_CAPABILITIES not in meta:
        missing.append(META_CLIENT_CAPABILITIES)

    if missing:
        raise McpValidationError(
            jsonrpc.INVALID_PARAMS,
            "request is missing required per-request protocol metadata",
            data={"missing": missing, "revision": MCP_PROTOCOL_VERSION},
        )
    return meta


def validate_protocol_headers(
    headers: Any,
    body_method: str,
    meta_version: str,
    body_name: str | None = None,
) -> str:
    """Validate the Streamable HTTP request-metadata headers against the body.

    ``headers`` is any case-insensitive mapping. Returns the validated
    protocol version. Raises :class:`McpValidationError` with ``-32020``
    (``HeaderMismatch``) for a missing/mismatched header and ``-32022``
    (``UnsupportedProtocolVersion``) for a version this server does not
    implement; both are answered with HTTP 400.
    """
    version_header = headers.get(HEADER_PROTOCOL_VERSION)
    if version_header is None:
        raise McpValidationError(
            jsonrpc.HEADER_MISMATCH,
            f"{HEADER_PROTOCOL_VERSION} header is required on every request",
        )
    if version_header != meta_version:
        raise McpValidationError(
            jsonrpc.HEADER_MISMATCH,
            f"{HEADER_PROTOCOL_VERSION} header '{version_header}' does not match "
            f"the request body's {_meta_version_label(meta_version)}",
        )
    if version_header not in SUPPORTED_VERSIONS:
        raise McpValidationError(
            jsonrpc.UNSUPPORTED_PROTOCOL_VERSION,
            "Unsupported protocol version",
            data={"supported": list(SUPPORTED_VERSIONS), "requested": version_header},
        )

    method_header = headers.get(HEADER_METHOD)
    if method_header is None:
        raise McpValidationError(
            jsonrpc.HEADER_MISMATCH,
            f"{HEADER_METHOD} header is required on every request",
        )
    if method_header != body_method:
        raise McpValidationError(
            jsonrpc.HEADER_MISMATCH,
            f"{HEADER_METHOD} header '{method_header}' does not match body method "
            f"'{body_method}'",
        )

    if body_method in _METHODS_REQUIRING_NAME:
        name_header = headers.get(HEADER_NAME)
        if body_name is None:
            # params.name is missing entirely; method dispatch rejects that
            # with -32602, which is a more precise error than a header
            # mismatch, so the header check is skipped here.
            pass
        elif name_header is None:
            raise McpValidationError(
                jsonrpc.HEADER_MISMATCH,
                f"{HEADER_NAME} header is required for '{body_method}' requests",
            )
        else:
            decoded = decode_header_value(name_header)
            if decoded != body_name:
                raise McpValidationError(
                    jsonrpc.HEADER_MISMATCH,
                    f"{HEADER_NAME} header '{decoded}' does not match body name "
                    f"'{body_name}'",
                )

    return version_header


def _meta_version_label(version: str) -> str:
    return f"params._meta['{META_PROTOCOL_VERSION}'] ('{version}')"


def request_meta(
    client_name: str = "mcp-gateway-pbac",
    client_version: str = SERVER_INFO["version"],
    extra: dict | None = None,
) -> dict:
    """Build a conforming per-request ``_meta`` object for outbound calls."""
    meta = {
        META_PROTOCOL_VERSION: MCP_PROTOCOL_VERSION,
        META_CLIENT_INFO: {"name": client_name, "version": client_version},
        META_CLIENT_CAPABILITIES: {},
    }
    if extra:
        meta.update(extra)
    return meta


def result_meta(extra: dict | None = None) -> dict:
    """Build the server-side ``_meta`` echoed on every result."""
    meta = {META_SERVER_INFO: SERVER_INFO}
    if extra:
        meta.update(extra)
    return meta


class McpUpstreamError(Exception):
    """The upstream MCP server returned a protocol error or was unreachable."""

    def __init__(self, message: str, code: int | None = None, data: Any = None):
        self.code = code
        self.data = data
        super().__init__(message)


async def mcp_request(
    client: httpx.AsyncClient,
    base_url: str,
    method: str,
    params: dict | None = None,
    token: str | None = None,
    request_id: str | None = None,
) -> dict:
    """Perform one MCP 2026-07-28 JSON-RPC request against an upstream server.

    Builds the required per-request ``_meta`` and the mandatory Streamable
    HTTP metadata headers, POSTs to ``{base_url}/mcp``, and returns the
    JSON-RPC ``result`` object. Raises :class:`McpUpstreamError` on transport
    failure or when the upstream answers with a JSON-RPC error.
    """
    params = dict(params or {})
    params.setdefault("_meta", request_meta())

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        HEADER_PROTOCOL_VERSION: MCP_PROTOCOL_VERSION,
        HEADER_METHOD: method,
    }
    name = params.get("name")
    if method in _METHODS_REQUIRING_NAME and isinstance(name, str):
        headers[HEADER_NAME] = name
    if token:
        headers["Authorization"] = f"Bearer {token}"

    payload = {
        "jsonrpc": jsonrpc.JSONRPC_VERSION,
        "id": request_id or str(uuid.uuid4()),
        "method": method,
        "params": params,
    }

    try:
        request = client.build_request(
            "POST", f"{base_url.rstrip('/')}/mcp", json=payload, headers=headers
        )
        resp = await client.send(request, stream=True)
    except httpx.RequestError as exc:
        raise McpUpstreamError(f"upstream unreachable: {exc}") from exc

    try:
        content_type = resp.headers.get("content-type", "").lower()
        if "application/json" in content_type:
            raw = await resp.aread()
            try:
                body = json.loads(raw)
            except Exception as exc:  # noqa: BLE001
                raise McpUpstreamError(
                    f"upstream returned invalid JSON (HTTP {resp.status_code})"
                ) from exc
        elif "text/event-stream" in content_type:
            body = await _read_sse_response(resp, payload["id"])
        else:
            raise McpUpstreamError(
                f"upstream returned unsupported content type '{content_type or 'missing'}' "
                f"(HTTP {resp.status_code})"
            )
    finally:
        await resp.aclose()

    if not isinstance(body, dict):
        raise McpUpstreamError("upstream returned a non-object JSON-RPC response")

    if "error" in body:
        err = body.get("error") or {}
        raise McpUpstreamError(
            err.get("message", "upstream JSON-RPC error"),
            code=err.get("code"),
            data=err.get("data"),
        )
    if "result" not in body:
        raise McpUpstreamError("upstream response had neither 'result' nor 'error'")
    return body["result"]


async def _read_sse_response(response: httpx.Response, request_id: Any) -> dict:
    """Read the terminal JSON-RPC response from an SSE transport response."""
    event_data: list[str] = []
    async for line in response.aiter_lines():
        if not line:
            if event_data:
                candidate = "\n".join(event_data)
                event_data.clear()
                if candidate == "[DONE]":
                    continue
                try:
                    message = json.loads(candidate)
                except Exception as exc:  # noqa: BLE001
                    raise McpUpstreamError("upstream SSE contained invalid JSON data") from exc
                if isinstance(message, dict) and message.get("id") == request_id:
                    return message
            continue
        if line.startswith(":"):
            continue
        field, sep, value = line.partition(":")
        if field == "data":
            event_data.append(value[1:] if sep and value.startswith(" ") else value)
    if event_data:
        try:
            message = json.loads("\n".join(event_data))
        except Exception as exc:  # noqa: BLE001
            raise McpUpstreamError("upstream SSE contained invalid JSON data") from exc
        if isinstance(message, dict) and message.get("id") == request_id:
            return message
    raise McpUpstreamError("upstream SSE ended without a matching JSON-RPC response")


async def mcp_tools_list_all(
    client: httpx.AsyncClient,
    base_url: str,
    token: str | None = None,
) -> list[dict]:
    """Fetch all pages of an upstream's paginated ``tools/list`` result."""
    tools: list[dict] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()
    while True:
        params = {"cursor": cursor} if cursor is not None else {}
        result = await mcp_request(client, base_url, "tools/list", params=params, token=token)
        page = result.get("tools", [])
        if not isinstance(page, list):
            raise McpUpstreamError("upstream tools/list returned a non-list 'tools' value")
        tools.extend(page)
        cursor = result.get("nextCursor")
        if cursor is None:
            return tools
        if not isinstance(cursor, str) or not cursor:
            raise McpUpstreamError("upstream tools/list returned an invalid nextCursor")
        if cursor in seen_cursors:
            raise McpUpstreamError("upstream tools/list repeated a pagination cursor")
        seen_cursors.add(cursor)
