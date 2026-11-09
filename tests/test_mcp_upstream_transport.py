"""Focused tests for upstream JSON/SSE responses and tools/list pagination."""

import json

import httpx
import pytest

from gateway import mcp_protocol


@pytest.mark.asyncio
async def test_mcp_request_accepts_sse_jsonrpc_response():
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        message = {
            "jsonrpc": "2.0",
            "id": payload["id"],
            "result": {"tools": [{"name": "from-sse"}], "resultType": "complete"},
        }
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            text=f": keepalive\nevent: message\ndata: {json.dumps(message)}\n\n",
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await mcp_protocol.mcp_request(client, "http://upstream.test", "tools/list")
    assert result["tools"] == [{"name": "from-sse"}]


@pytest.mark.asyncio
async def test_mcp_tools_list_fetches_every_cursor_page():
    seen_cursors = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        cursor = payload["params"].get("cursor")
        seen_cursors.append(cursor)
        if cursor is None:
            result = {"tools": [{"name": "first"}], "nextCursor": "page-2"}
        else:
            result = {"tools": [{"name": "second"}]}
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": payload["id"], "result": result},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        tools = await mcp_protocol.mcp_tools_list_all(client, "http://upstream.test")
    assert [tool["name"] for tool in tools] == ["first", "second"]
    assert seen_cursors == [None, "page-2"]


@pytest.mark.asyncio
async def test_mcp_tools_list_rejects_repeated_cursor():
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": payload["id"],
                "result": {"tools": [], "nextCursor": "loop"},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(mcp_protocol.McpUpstreamError, match="repeated"):
            await mcp_protocol.mcp_tools_list_all(client, "http://upstream.test")
