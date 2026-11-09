"""
JSON-RPC 2.0 envelope handling for the MCP gateway interface (revision 2026-07-28).

The custom REST adapter (``POST /mcp/v1/tools/call`` with a nested
``tool.name`` field and a ``data``/``gateway_meta`` wrapper) remains in
``main.py`` for the evaluation harness only; it is *not* the Model Context
Protocol and is documented as such. ``POST /mcp`` speaks the real protocol
at revision 2026-07-28; the MCP-specific validation (per-request ``_meta``,
HTTP metadata headers, Origin, ``server/discover``) lives in
``mcp_protocol.py``. This module implements the JSON-RPC 2.0 envelope layer
underneath it:

* single requests and notifications (no ``id``, no response). JSON-RPC
  batching is not carried on this revision's Streamable HTTP transport, so
  top-level arrays are rejected by the endpoint rather than dispatched here.
* the reserved error codes -32700, -32600, -32601, -32602 and -32603
* the MCP-defined protocol errors -32020 (HeaderMismatch), -32021
  (MissingRequiredClientCapability) and -32022 (UnsupportedProtocolVersion),
  allocated by the specification from the -32020..-32099 reserved sub-range
* this gateway's application-specific denials (policy, schema, upstream) are
  allocated *outside* the JSON-RPC reserved range (-32768..-32022), because
  revision 2026-07-28 forbids new allocations in the legacy -32000..-32019
  sub-range and directs application codes outside the reserved range. The
  previous codes -32001/-32002/-32003 are not reused: -32002 in particular is
  a specification-reserved code that this revision forbids emitting.

References: JSON-RPC 2.0 Specification sections 4, 4.1, 5 and 5.1; MCP
specification 2026-07-28, "Base Protocol — Error Codes" and "Streamable HTTP".
"""

from __future__ import annotations

from typing import Any

JSONRPC_VERSION = "2.0"

# Reserved codes (JSON-RPC 2.0 §5.1)
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# MCP protocol-defined errors (2026-07-28, allocated from -32020..-32099)
HEADER_MISMATCH = -32020
MISSING_CLIENT_CAPABILITY = -32021
UNSUPPORTED_PROTOCOL_VERSION = -32022

# Application-specific errors. The MCP specification reserves -32768..-32099
# for protocol-defined codes and directs application errors outside that
# range; these therefore sit above the reserved block.
POLICY_DENIED = -1000
SCHEMA_DENIED = -1001
UPSTREAM_ERROR = -1002
AUDIT_UNAVAILABLE = -1003

_ERROR_MESSAGES = {
    PARSE_ERROR: "Parse error",
    INVALID_REQUEST: "Invalid Request",
    METHOD_NOT_FOUND: "Method not found",
    INVALID_PARAMS: "Invalid params",
    INTERNAL_ERROR: "Internal error",
    HEADER_MISMATCH: "Header mismatch",
    MISSING_CLIENT_CAPABILITY: "Missing required client capability",
    UNSUPPORTED_PROTOCOL_VERSION: "Unsupported protocol version",
    POLICY_DENIED: "Access denied by policy",
    SCHEMA_DENIED: "Tool schema verification failed",
    UPSTREAM_ERROR: "Upstream MCP server error",
    AUDIT_UNAVAILABLE: "Audit log unavailable; request not executed",
}


class JsonRpcError(Exception):
    """An error that should be returned as a JSON-RPC error object."""

    def __init__(self, code: int, message: str | None = None, data: Any = None):
        self.code = code
        self.message = message or _ERROR_MESSAGES.get(code, "Server error")
        self.data = data
        super().__init__(self.message)

    def to_object(self) -> dict:
        obj: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            obj["data"] = self.data
        return obj


def success(request_id: Any, result: Any) -> dict:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}


def error(request_id: Any, code: int, message: str | None = None, data: Any = None) -> dict:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "error": JsonRpcError(code, message, data).to_object(),
    }


def is_notification(message: dict) -> bool:
    """A request without an ``id`` member is a notification (§4.1)."""
    return "id" not in message


def validate(message: Any) -> tuple[Any, str, dict]:
    """
    Validate one JSON-RPC request object (revision 2026-07-28 rules).

    Returns ``(id, method, params)``. Raises :class:`JsonRpcError` with
    -32600 for a structurally invalid request or -32602 for params of the
    wrong type. Unlike base JSON-RPC, MCP 2026-07-28 requires request IDs to
    be a string or integer and forbids ``null``. The caller is responsible
    for suppressing the response when the message is a notification.
    """
    if not isinstance(message, dict):
        raise JsonRpcError(INVALID_REQUEST, data="request must be a JSON object")

    if message.get("jsonrpc") != JSONRPC_VERSION:
        raise JsonRpcError(
            INVALID_REQUEST, data="missing or unsupported 'jsonrpc' version"
        )

    method = message.get("method")
    if not isinstance(method, str) or not method:
        raise JsonRpcError(INVALID_REQUEST, data="'method' must be a non-empty string")

    if "id" in message and message["id"] is None:
        raise JsonRpcError(
            INVALID_REQUEST,
            data="'id' must not be null (MCP 2026-07-28, base protocol)",
        )
    request_id = message.get("id")
    if request_id is not None and not isinstance(request_id, (str, int, float)):
        raise JsonRpcError(
            INVALID_REQUEST, data="'id' must be a string or number"
        )

    params = message.get("params", {})
    if params is None:
        params = {}
    if not isinstance(params, (dict, list)):
        raise JsonRpcError(INVALID_PARAMS, data="'params' must be an object or array")
    if isinstance(params, list):
        raise JsonRpcError(
            INVALID_PARAMS, data="positional parameters are not supported"
        )

    return request_id, method, params
