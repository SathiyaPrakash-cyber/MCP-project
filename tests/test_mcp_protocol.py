"""
Protocol-conformance tests for the MCP endpoint at revision 2026-07-28.

These tests exercise ``POST /mcp`` directly through the ASGI application, with
the policy engine, upstream MCP server and audit logger replaced by local
doubles. They therefore run in a clean checkout with no Docker, no OPA and no
network, which is what makes them usable as submitted evidence.

What is covered (all rules are from the published 2026-07-28 specification)
---------------------------------------------------------------------------
* per-request protocol metadata: required ``params._meta`` fields, HTTP
  ``MCP-Protocol-Version``/``Mcp-Method``/``Mcp-Name`` headers and their
  consistency with the body (-32602 / -32020 / -32022)
* Origin validation (HTTP 403), notifications (HTTP 202), batch rejection
  (HTTP 400), null request-id rejection (-32600)
* ``server/discover``, ``tools/list``, ``tools/call``; legacy
  ``initialize`` answered as an unknown method naming the supported versions
  (HTTP 404 / -32601); unknown methods answered 404 / -32601
* ``CallToolResult`` shape, ``resultType``, and ``_meta`` serverInfo echo
* enforcement parity: policy and schema denials surface as JSON-RPC errors
  with the application codes allocated outside the reserved range, and the
  REST adapter reaches the same verdict for the same call
* the gateway's own outbound upstream calls carry the required headers and
  per-request ``_meta``

Run with:  pytest -q tests/test_mcp_protocol.py
"""

from __future__ import annotations

import json as jsonlib
import sys
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import jsonrpc, main as gw, mcp_protocol  # noqa: E402
from gateway.auth import TokenClaims, verify_token  # noqa: E402
from gateway.audit_logger import AuditLogger  # noqa: E402
from gateway.models import GatewayConfig  # noqa: E402
from gateway.policy_engine import PolicyDecision  # noqa: E402
from gateway.schema_pinning import ToolSchemaPinning  # noqa: E402

V = mcp_protocol.MCP_PROTOCOL_VERSION
UPSTREAM = "http://upstream.test"

UPSTREAM_TOOLS = [
    {
        "name": "filesystem.read",
        "description": "Read a file",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
    },
    {
        "name": "filesystem.write",
        "description": "Write a file",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
    },
]


class StubPolicyEngine:
    """Allows everything except filesystem.write, with no OPA required."""

    def __init__(self):
        self.calls: list[str] = []

    async def evaluate(self, policy_input) -> PolicyDecision:
        tool = policy_input["input"]["tool"]["name"]
        self.calls.append(tool)
        if tool == "filesystem.write":
            return PolicyDecision(
                allow=False,
                reason="read_only role may not call a write tool",
                rule_matched="rbac.deny_write",
                evaluation_ms=0.4,
            )
        return PolicyDecision(
            allow=True, reason="permitted", rule_matched="rbac.allow", evaluation_ms=0.4
        )


# Records every outbound upstream request so tests can assert the gateway
# speaks MCP to its own upstream, not the custom REST adapter.
UPSTREAM_SEEN: list[tuple[dict, dict]] = []


def _upstream_handler(request: httpx.Request) -> httpx.Response:
    payload = jsonlib.loads(request.content)
    UPSTREAM_SEEN.append(
        (dict(request.headers), {"payload": payload})
    )
    method = payload.get("method")
    rid = payload.get("id")
    if method == "tools/list":
        result: dict = {"tools": UPSTREAM_TOOLS}
    elif method == "tools/call":
        result = {
            "content": [{"type": "text", "text": "file contents"}],
            "isError": False,
        }
    else:
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": rid,
                "error": {"code": -32601, "message": "unknown"},
            },
        )
    result.setdefault("resultType", "complete")
    return httpx.Response(
        200, json={"jsonrpc": "2.0", "id": rid, "result": result}
    )


@pytest_asyncio.fixture
async def client(tmp_path, monkeypatch):
    """Wire the app's globals to local doubles and yield an ASGI client."""
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    UPSTREAM_SEEN.clear()

    gw.config = GatewayConfig()
    gw.config.upstream_default = UPSTREAM
    gw.config.upstream_routes = {}  # every tool routes to the one test upstream
    gw.policy_engine = StubPolicyEngine()
    gw.http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(_upstream_handler)
    )
    gw.audit_logger = AuditLogger(log_dir=str(tmp_path))
    await gw.audit_logger.initialize()

    pinner = ToolSchemaPinning()
    pinner.register_many(UPSTREAM, UPSTREAM_TOOLS)
    pinner.seal(UPSTREAM)
    gw.schema_pinner = pinner

    gw.app.dependency_overrides[verify_token] = lambda: TokenClaims(
        sub="user_test",
        role="developer",
        groups=["eng"],
        email="dev@test.com",
        exp=4_102_444_800,
        raw_token="stub",
    )

    transport = httpx.ASGITransport(app=gw.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://gateway.test"
    ) as c:
        yield c

    gw.app.dependency_overrides.clear()
    await gw.http_client.aclose()


def meta() -> dict:
    return {
        mcp_protocol.META_PROTOCOL_VERSION: V,
        mcp_protocol.META_CLIENT_CAPABILITIES: {},
    }


def headers(method: str, name: str | None = None, version: str = V) -> dict:
    h = {
        mcp_protocol.HEADER_PROTOCOL_VERSION: version,
        mcp_protocol.HEADER_METHOD: method,
    }
    if name is not None:
        h[mcp_protocol.HEADER_NAME] = name
    return h


async def rpc(client, payload, method: str | None = None, name: str | None = None, hdrs: dict | None = None):
    """POST one JSON-RPC message with conforming _meta and headers."""
    if isinstance(payload, dict) and "method" in payload:
        method = payload.setdefault("method", method)
        params = payload.setdefault("params", {})
        params.setdefault("_meta", meta())
        if name is None and isinstance(params.get("name"), str):
            name = params["name"]
        if hdrs is None:
            hdrs = headers(method, name)
    return await client.post("/mcp", json=payload, headers=hdrs or {})


# ── Envelope + metadata conformance ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_server_discover_returns_supported_versions(client):
    r = await rpc(client, {"jsonrpc": "2.0", "id": 1, "method": "server/discover"})
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == 1
    result = body["result"]
    assert V in result["supportedVersions"]
    assert "tools" in result["capabilities"]
    assert result["resultType"] == "complete"
    assert result["_meta"][mcp_protocol.META_SERVER_INFO]["name"]


@pytest.mark.asyncio
async def test_legacy_initialize_is_404_naming_supported_versions(client):
    r = await rpc(client, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert r.status_code == 404
    body = r.json()
    assert body["error"]["code"] == jsonrpc.METHOD_NOT_FOUND
    assert V in body["error"]["data"]["supportedVersions"]


@pytest.mark.asyncio
async def test_legacy_initialize_without_meta_is_still_404(client):
    """A real legacy client sends no ``_meta`` and no modern headers.

    The helpful "unknown method, supported versions" answer must not be
    pre-empted by the ``params._meta`` requirement, so this exercise posts the
    bare request a pre-2026-07-28 client would actually send.
    """
    r = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2024-11-05"}},
    )
    assert r.status_code == 404
    body = r.json()
    assert body["error"]["code"] == jsonrpc.METHOD_NOT_FOUND
    assert V in body["error"]["data"]["supportedVersions"]


@pytest.mark.asyncio
async def test_id_is_echoed_including_string_ids(client):
    r = await rpc(client, {"jsonrpc": "2.0", "id": "abc-123", "method": "server/discover"})
    body = r.json()
    assert body["id"] == "abc-123"
    assert "error" not in body
    assert body["result"]["resultType"] == "complete"


@pytest.mark.asyncio
async def test_null_id_is_rejected(client):
    """2026-07-28: request IDs must not be null."""
    r = await rpc(client, {"jsonrpc": "2.0", "id": None, "method": "server/discover"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == jsonrpc.INVALID_REQUEST


@pytest.mark.asyncio
async def test_parse_error(client):
    r = await client.post(
        "/mcp", content=b"{not json", headers={"Content-Type": "application/json"}
    )
    assert r.status_code == 400
    body = r.json()
    assert body["error"]["code"] == jsonrpc.PARSE_ERROR
    assert body["id"] is None


@pytest.mark.asyncio
async def test_invalid_request_missing_version(client):
    r = await client.post(
        "/mcp",
        json={"id": 1, "method": "server/discover", "params": {"_meta": meta()}},
        headers=headers("server/discover"),
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == jsonrpc.INVALID_REQUEST


@pytest.mark.asyncio
async def test_missing_meta_is_invalid_params(client):
    """Required per-request protocol metadata is missing -> -32602, HTTP 400."""
    r = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}},
        headers=headers("server/discover"),
    )
    assert r.status_code == 400
    body = r.json()
    assert body["error"]["code"] == jsonrpc.INVALID_PARAMS
    assert mcp_protocol.META_PROTOCOL_VERSION in body["error"]["data"]["missing"]


@pytest.mark.asyncio
async def test_missing_protocol_version_header_is_header_mismatch(client):
    r = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": meta()}},
        headers={mcp_protocol.HEADER_METHOD: "server/discover"},
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == jsonrpc.HEADER_MISMATCH


@pytest.mark.asyncio
async def test_header_body_version_mismatch(client):
    r = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": meta()}},
        headers=headers("server/discover", version="2025-06-18"),
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == jsonrpc.HEADER_MISMATCH


@pytest.mark.asyncio
async def test_unsupported_version_lists_supported(client):
    """An unsupported revision is -32022 with data.supported/data.requested."""
    bad = "2024-11-05"
    bad_meta = {
        mcp_protocol.META_PROTOCOL_VERSION: bad,
        mcp_protocol.META_CLIENT_CAPABILITIES: {},
    }
    r = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": bad_meta}},
        headers=headers("server/discover", version=bad),
    )
    assert r.status_code == 400
    body = r.json()
    assert body["error"]["code"] == jsonrpc.UNSUPPORTED_PROTOCOL_VERSION
    assert body["error"]["data"]["supported"] == [V]
    assert body["error"]["data"]["requested"] == bad


@pytest.mark.asyncio
async def test_method_header_mismatch(client):
    r = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": meta()}},
        headers=headers("tools/list"),
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == jsonrpc.HEADER_MISMATCH


@pytest.mark.asyncio
async def test_missing_mcp_name_header_for_tools_call(client):
    r = await client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "filesystem.read",
                "arguments": {"path": "/tmp/x"},
                "_meta": meta(),
            },
        },
        headers=headers("tools/call"),
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == jsonrpc.HEADER_MISMATCH


@pytest.mark.asyncio
async def test_mcp_name_header_mismatch(client):
    r = await client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "filesystem.read",
                "arguments": {},
                "_meta": meta(),
            },
        },
        headers=headers("tools/call", name="filesystem.write"),
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == jsonrpc.HEADER_MISMATCH


@pytest.mark.asyncio
async def test_invalid_origin_is_403(client):
    r = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": meta()}},
        headers={**headers("server/discover"), "Origin": "https://evil.example"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_notification_returns_202_empty(client):
    r = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "server/discover", "params": {"_meta": meta()}},
        headers=headers("server/discover"),
    )
    assert r.status_code == 202
    assert not r.content


@pytest.mark.asyncio
async def test_batch_is_rejected(client):
    """The Streamable HTTP transport carries one message per POST."""
    r = await client.post(
        "/mcp",
        json=[
            {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": meta()}},
            {"jsonrpc": "2.0", "id": 2, "method": "server/discover", "params": {"_meta": meta()}},
        ],
        headers=headers("server/discover"),
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == jsonrpc.INVALID_REQUEST


@pytest.mark.asyncio
async def test_unknown_method_is_404(client):
    r = await rpc(client, {"jsonrpc": "2.0", "id": 2, "method": "resources/list"})
    assert r.status_code == 404
    body = r.json()
    assert body["error"]["code"] == jsonrpc.METHOD_NOT_FOUND
    assert body["id"] == 2


@pytest.mark.asyncio
async def test_ping_is_not_implemented(client):
    r = await rpc(client, {"jsonrpc": "2.0", "id": 3, "method": "ping"})
    assert r.status_code == 404
    assert r.json()["error"]["code"] == jsonrpc.METHOD_NOT_FOUND


@pytest.mark.asyncio
async def test_invalid_params_missing_tool_name(client):
    r = await rpc(
        client,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"arguments": {}},
        },
    )
    assert r.json()["error"]["code"] == jsonrpc.INVALID_PARAMS


@pytest.mark.asyncio
async def test_positional_params_rejected(client):
    r = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": [1, 2]},
        headers=headers("tools/call"),
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == jsonrpc.INVALID_PARAMS


# ── MCP semantics ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tools_list_is_policy_filtered(client):
    r = await rpc(client, {"jsonrpc": "2.0", "id": 5, "method": "tools/list"})
    result = r.json()["result"]
    names = [t["name"] for t in result["tools"]]
    assert "filesystem.read" in names
    assert "filesystem.write" not in names, "denied tool must not be advertised"
    assert result["resultType"] == "complete"


@pytest.mark.asyncio
async def test_tools_call_returns_call_tool_result(client):
    r = await rpc(
        client,
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "filesystem.read", "arguments": {"path": "/tmp/x"}},
        },
    )
    result = r.json()["result"]
    assert result["isError"] is False
    assert isinstance(result["content"], list)
    assert result["content"][0]["type"] == "text"
    assert result["resultType"] == "complete"
    assert result["_meta"][mcp_protocol.META_SERVER_INFO]
    assert result["_meta"][mcp_protocol.GATEWAY_META_REQUEST_ID]


@pytest.mark.asyncio
async def test_policy_denial_is_a_jsonrpc_error(client):
    r = await rpc(
        client,
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "filesystem.write", "arguments": {}},
        },
    )
    body = r.json()
    assert "result" not in body
    assert body["error"]["code"] == jsonrpc.POLICY_DENIED


@pytest.mark.asyncio
async def test_unpinned_tool_is_denied_not_forwarded(client):
    """Fail-closed: a tool absent from the sealed snapshot must be refused."""
    r = await rpc(
        client,
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {"name": "database.drop_table", "arguments": {}},
        },
    )
    body = r.json()
    assert body["error"]["code"] == jsonrpc.SCHEMA_DENIED
    assert body["error"]["data"]["error"] == "tool_not_pinned"


@pytest.mark.asyncio
async def test_rest_and_mcp_reach_the_same_verdict(client):
    """Enforcement parity: one policy path behind two interfaces."""
    rest = await client.post(
        "/mcp/v1/tools/call",
        json={"tool": {"name": "filesystem.write"}, "arguments": {}},
    )
    rpc_resp = await rpc(
        client,
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "filesystem.write", "arguments": {}},
        },
    )
    assert rest.status_code == 403
    assert rpc_resp.json()["error"]["code"] == jsonrpc.POLICY_DENIED
    assert (
        rest.json()["detail"]["reason"]
        == rpc_resp.json()["error"]["data"]["reason"]
    )


@pytest.mark.asyncio
async def test_gateway_calls_upstream_with_mcp_headers_and_meta(client):
    """The gateway-to-upstream hop is real MCP, not the REST adapter."""
    UPSTREAM_SEEN.clear()
    await rpc(
        client,
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": "filesystem.read", "arguments": {"path": "/tmp/x"}},
        },
    )
    calls = [p for h, p in UPSTREAM_SEEN if p["payload"].get("method") == "tools/call"]
    assert calls, "no tools/call reached the upstream"
    headers_seen = [h for h, p in UPSTREAM_SEEN if p["payload"].get("method") == "tools/call"]
    outbound = headers_seen[0]
    assert outbound[mcp_protocol.HEADER_PROTOCOL_VERSION.lower()] == V
    assert outbound[mcp_protocol.HEADER_METHOD.lower()] == "tools/call"
    assert outbound[mcp_protocol.HEADER_NAME.lower()] == "filesystem.read"
    sent_meta = calls[0]["payload"]["params"]["_meta"]
    assert sent_meta[mcp_protocol.META_PROTOCOL_VERSION] == V
    assert mcp_protocol.META_CLIENT_CAPABILITIES in sent_meta
