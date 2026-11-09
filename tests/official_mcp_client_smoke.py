"""Exercise the HTTP endpoint with the official MCP Python SDK client.

This smoke test starts the real FastAPI app on loopback, while replacing only
the gateway's external OPA/upstream services with local test doubles. It checks
SDK discovery, tool listing, an allowed call, and a policy-denied call.
Install the optional SDK with ``pip install -r requirements-official-client.txt``
and run ``python tests/official_mcp_client_smoke.py``.
"""

from __future__ import annotations

import asyncio
import json
import socket
import tempfile
from pathlib import Path
import sys

# Make `python tests/official_mcp_client_smoke.py` work from the project root.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import httpx
import httpx2
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from gateway import main as gw
from gateway.audit_logger import AuditLogger
from gateway.auth import TokenClaims, verify_token
from gateway.mcp_protocol import MCP_PROTOCOL_VERSION
from gateway.models import GatewayConfig
from gateway.policy_engine import PolicyDecision
from gateway.schema_pinning import ToolSchemaPinning

UPSTREAM = "http://upstream.test"
TOOLS = [
    {"name": "filesystem.read", "description": "Read a file", "inputSchema": {
        "type": "object", "properties": {"path": {"type": "string"}},
        "required": ["path"],
    }},
    {"name": "filesystem.write", "description": "Write a file", "inputSchema": {
        "type": "object", "properties": {"path": {"type": "string"},
        "content": {"type": "string"}}, "required": ["path", "content"],
    }},
]


class PolicyStub:
    async def evaluate(self, policy_input):
        name = policy_input["input"]["tool"]["name"]
        allowed = name == "filesystem.read"
        return PolicyDecision(
            allow=allowed,
            reason="permitted" if allowed else "write denied by test policy",
            rule_matched="test.allow_read" if allowed else "test.deny_write",
            evaluation_ms=0.1,
        )


def upstream_handler(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    method, request_id = body.get("method"), body.get("id")
    if method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "official-client-ok"}], "isError": False}
    else:
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": request_id,
            "error": {"code": -32601, "message": "unknown method"}})
    result["resultType"] = "complete"
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": request_id, "result": result})


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="mcp-sdk-smoke-") as temp_dir:
        gw.config = GatewayConfig()
        gw.config.upstream_default = UPSTREAM
        gw.config.upstream_routes = {}
        gw.policy_engine = PolicyStub()
        gw.audit_logger = AuditLogger(log_dir=temp_dir)
        await gw.audit_logger.initialize()
        gw.http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
        pinner = ToolSchemaPinning()
        pinner.register_many(UPSTREAM, TOOLS)
        pinner.seal(UPSTREAM)
        gw.schema_pinner = pinner

        gw.app.dependency_overrides[verify_token] = lambda: TokenClaims(
            sub="official-sdk-smoke", role="developer", groups=["test"],
            email="sdk@example.invalid", exp=4_102_444_800, raw_token="test-token",
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(128)
        sock.setblocking(False)
        port = sock.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(gw.app, log_level="critical", lifespan="off"))
        server_task = asyncio.create_task(server.serve(sockets=[sock]))
        try:
            for _ in range(200):
                if server.started:
                    break
                await asyncio.sleep(0.025)
            if not server.started:
                raise RuntimeError("gateway did not start on loopback")

            base_url = f"http://127.0.0.1:{port}/mcp"
            async with httpx2.AsyncClient(
                headers={"Authorization": "Bearer sdk-smoke"}, trust_env=False
            ) as sdk_http:
              async with streamable_http_client(base_url, http_client=sdk_http) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    discovery = await session.discover()
                    assert MCP_PROTOCOL_VERSION in discovery.supported_versions
                    print("PASS official SDK server/discover")

                    listed = await session.list_tools()
                    tool_names = {item.name for item in listed.tools}
                    assert "filesystem.read" in tool_names
                    assert "filesystem.write" not in tool_names
                    print("PASS official SDK tools/list reflects policy")

                    called = await session.call_tool("filesystem.read", {"path": "/tmp/demo"})
                    assert not called.is_error
                    assert any(getattr(item, "text", "") == "official-client-ok" for item in called.content)
                    print("PASS official SDK allowed tools/call")

                    try:
                        await session.call_tool("filesystem.write", {"path": "/tmp/demo", "content": "x"})
                    except Exception as exc:
                        assert "denied" in str(exc).lower() or "-1000" in str(exc)
                        print("PASS official SDK policy-denied tools/call")
                    else:
                        raise AssertionError("policy-denied call unexpectedly succeeded")
            from importlib.metadata import version
            print(f"Official MCP Python SDK interoperability: PASS (mcp {version('mcp')})")
        finally:
            server.should_exit = True
            await server_task
            gw.app.dependency_overrides.clear()
            await gw.http_client.aclose()


if __name__ == "__main__":
    asyncio.run(main())
