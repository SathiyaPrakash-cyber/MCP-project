"""
Data models for MCP Gateway
"""

import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class MCPRequest:
    tool_name: str
    tool_args: dict
    session_id: str
    raw: dict


@dataclass
class MCPResponse:
    data: Any
    request_id: str
    policy_latency_ms: float
    total_latency_ms: float


@dataclass
class AuditRecord:
    """
    One line of the append-only NDJSON audit log.

    ``event_type`` distinguishes the three kinds of record the gateway now
    writes, which is required for the "audit-before-execution" ordering:

    * ``decision``     — legacy/default: a single record written after the
                         whole request (pre-fix behaviour; kept so older
                         logs and log readers still load).
    * ``authorization``— written and fsynced *before* the upstream call is
                         dispatched. An ALLOW record here is the durable
                         authorisation grant; if it cannot be written the
                         request is refused with a 503 and the tool is NOT
                         executed.
    * ``completion``   — written after the upstream call returns (or fails),
                         carrying the upstream/total latency and any upstream
                         error.
    * ``denial``       — written when the policy denies. (Denials are also
                         safe to keep as ``decision`` records for compat.)

    Log analysis scripts filter out ``completion`` events when counting
    decisions so an ALLOW request is not counted twice.
    """
    request_id: str
    timestamp: float
    user_id: str
    role: str
    tool_name: str
    policy_decision: bool          # True = ALLOW, False = DENY
    policy_reason: str
    policy_rule_matched: str
    latency_policy_ms: float
    source_ip: str
    session_id: str
    denied: bool = False
    upstream_error: Optional[str] = None
    latency_upstream_ms: Optional[float] = None
    latency_total_ms: Optional[float] = None
    event_type: str = "decision"   # decision | authorization | completion | denial

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "timestamp_iso": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.timestamp)
            ),
            "timestamp_epoch": self.timestamp,
            "user_id": self.user_id,
            "role": self.role,
            "tool_name": self.tool_name,
            "policy_decision": "ALLOW" if self.policy_decision else "DENY",
            "policy_reason": self.policy_reason,
            "policy_rule_matched": self.policy_rule_matched,
            "latency_policy_ms": self.latency_policy_ms,
            "latency_upstream_ms": self.latency_upstream_ms,
            "latency_total_ms": self.latency_total_ms,
            "source_ip": self.source_ip,
            "session_id": self.session_id,
            "denied": self.denied,
            "upstream_error": self.upstream_error,
            "event_type": self.event_type,
        }


@dataclass
class GatewayConfig:
    opa_url: str = field(
        default_factory=lambda: os.getenv("OPA_URL", "http://opa:8181")
    )
    upstream_default: str = field(
        default_factory=lambda: os.getenv(
            "UPSTREAM_DEFAULT", "http://mock-mcp-server:9000"
        )
    )
    log_dir: str = field(
        default_factory=lambda: os.getenv("LOG_DIR", "/app/logs")
    )
    jwt_secret: str = field(
        default_factory=lambda: os.getenv(
            "JWT_SECRET",
            ""
        )
    )
    jwt_algorithm: str = "HS256"

    # Tool name prefix -> upstream MCP server URL mapping
    upstream_routes: dict = field(default_factory=lambda: {
        "filesystem": os.getenv("UPSTREAM_FS", "http://mock-mcp-server:9000"),
        "database":   os.getenv("UPSTREAM_DB", "http://mock-mcp-server:9000"),
        "code":       os.getenv("UPSTREAM_CODE", "http://mock-mcp-server:9000"),
        "saas":       os.getenv("UPSTREAM_SAAS", "http://mock-mcp-server:9000"),
    })

    # Max policy decision latency before we alert
    max_policy_latency_ms: float = 50.0
