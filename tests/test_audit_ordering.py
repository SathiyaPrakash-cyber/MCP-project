"""
Tests for the audit-before-execution ordering (fix 4 of the action list).

The original gateway wrote one audit record *after* the upstream call
returned. That meant an ALLOW decision was only durable once the tool had
already run: if the process died between the policy decision and the log
write, or if the write itself failed (the old ``write`` swallowed every
exception), the system could execute a tool call whose authorisation was
never recorded. The corrected ordering is:

    policy ALLOW  ->  write durable ``authorization`` record (fsynced)
                   ->  schema-pin check
                   ->  upstream tools/call
                   ->  write ``completion`` record

If the authorization write fails, the request is refused with 503 and the
upstream is never contacted. Denials write a ``denial`` record (a failed
denial write is logged loudly but the request is still refused, because the
tool is not executed either way).

Run with:  pytest -q tests/test_audit_ordering.py
"""

from __future__ import annotations

import json as jsonlib
import sys
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import main as gw  # noqa: E402
from gateway.audit_logger import AuditLogger, AuditWriteError  # noqa: E402
from gateway.auth import TokenClaims, verify_token  # noqa: E402
from gateway.models import AuditRecord, GatewayConfig  # noqa: E402
from gateway.policy_engine import PolicyDecision  # noqa: E402
from gateway.schema_pinning import ToolSchemaPinning  # noqa: E402

UPSTREAM = "http://upstream.test"

PINNED_TOOLS = [
    {
        "name": "filesystem.read",
        "description": "Read a file from disk",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
    }
]

UPSTREAM_CALLS: list[str] = []


class AllowAllPolicy:
    async def evaluate(self, policy_input) -> PolicyDecision:
        return PolicyDecision(
            allow=True, reason="permitted", rule_matched="test.allow", evaluation_ms=0.1
        )


def _upstream_handler(request: httpx.Request) -> httpx.Response:
    payload = jsonlib.loads(request.content)
    method = payload.get("method")
    rid = payload.get("id")
    UPSTREAM_CALLS.append(method)
    result: dict
    if method == "tools/list":
        result = {"tools": PINNED_TOOLS}
    else:
        result = {
            "content": [{"type": "text", "text": "ok"}],
            "isError": False,
        }
    result.setdefault("resultType", "complete")
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": result})


class FailingWriteLogger(AuditLogger):
    """Simulates a full disk / unwritable log directory."""

    async def write(self, record):  # type: ignore[override]
        raise AuditWriteError("simulated: audit log unwritable")


def _read_log(log_dir: Path) -> list[dict]:
    records: list[dict] = []
    for path in sorted(log_dir.glob("mcp_audit_*.ndjson")):
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(jsonlib.loads(line))
    return records


@pytest_asyncio.fixture
async def env(tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    UPSTREAM_CALLS.clear()

    gw.config = GatewayConfig()
    gw.config.upstream_default = UPSTREAM
    gw.config.upstream_routes = {}
    gw.policy_engine = AllowAllPolicy()
    gw.http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(_upstream_handler)
    )

    pinner = ToolSchemaPinning()
    pinner.register_many(UPSTREAM, PINNED_TOOLS)
    pinner.seal(UPSTREAM)
    gw.schema_pinner = pinner

    gw.app.dependency_overrides[verify_token] = lambda: TokenClaims(
        sub="u1",
        role="admin",
        groups=[],
        email="a@test.com",
        exp=4_102_444_800,
        raw_token="stub",
    )

    created: list[httpx.AsyncClient] = []

    async def build(logger: AuditLogger | None = None):
        if logger is None:
            logger = AuditLogger(log_dir=str(tmp_path))
            await logger.initialize()
        gw.audit_logger = logger
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gw.app),
            base_url="http://gateway.test",
        )
        created.append(client)
        return client

    yield build

    gw.app.dependency_overrides.clear()
    await gw.http_client.aclose()
    for c in created:
        await c.aclose()


async def call(client):
    return await client.post(
        "/mcp/v1/tools/call",
        json={"tool": {"name": "filesystem.read"}, "arguments": {"path": "/tmp/a"}},
    )


# ── ordering ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_authorization_record_is_written_before_completion(env, tmp_path):
    client = await env()
    r = await call(client)
    assert r.status_code == 200

    records = _read_log(tmp_path)
    assert len(records) == 2, (
        f"expected authorization then completion, got {[x.get('event_type') for x in records]}"
    )
    assert records[0]["event_type"] == "authorization"
    assert records[1]["event_type"] == "completion"
    assert records[0]["request_id"] == records[1]["request_id"]
    # The authorization record is the pre-execution grant: it must carry the
    # policy decision but no upstream latency (the call had not run yet).
    assert records[0]["policy_decision"] == "ALLOW"
    assert records[0]["latency_upstream_ms"] is None
    assert records[1]["latency_upstream_ms"] is not None


@pytest.mark.asyncio
async def test_completion_audit_failure_is_not_reported_as_success(env, tmp_path):
    client = await env()
    original_write = gw.audit_logger.write
    writes = 0

    async def fail_completion(record):
        nonlocal writes
        writes += 1
        if writes == 1:
            return await original_write(record)
        raise AuditWriteError("simulated completion fsync failure")

    gw.audit_logger.write = fail_completion
    UPSTREAM_CALLS.clear()
    r = await call(client)
    assert r.status_code == 503
    assert "completion_audit_unavailable" in r.text
    assert "tools/call" in UPSTREAM_CALLS
    assert [record["event_type"] for record in _read_log(tmp_path)] == ["authorization"]


@pytest.mark.asyncio
async def test_fsync_failure_is_reported_and_logger_fails_closed(tmp_path, monkeypatch):
    logger = AuditLogger(str(tmp_path))
    monkeypatch.setattr("os.fsync", lambda _fd: (_ for _ in ()).throw(OSError("fsync failed")))
    record = AuditRecord(
        request_id="fsync-failure",
        timestamp=1_750_000_000.0,
        user_id="tester",
        role="developer",
        tool_name="filesystem.read",
        policy_decision=True,
        policy_reason="test",
        policy_rule_matched="test.allow",
        latency_policy_ms=1.0,
        source_ip="127.0.0.1",
        session_id="test",
    )
    with pytest.raises(AuditWriteError, match="fsync failed"):
        await logger.write(record)
    assert logger._prev_hash == "0" * 64
    with pytest.raises(AuditWriteError, match="unavailable after an earlier"):
        await logger.write(record)


@pytest.mark.asyncio
async def test_denial_writes_one_denial_record_and_never_calls_upstream(env, tmp_path):
    client = await env()

    class DenyPolicy:
        async def evaluate(self, policy_input) -> PolicyDecision:
            return PolicyDecision(
                allow=False, reason="denied for test", rule_matched="test.deny",
                evaluation_ms=0.1,
            )

    gw.policy_engine = DenyPolicy()
    r = await call(client)
    assert r.status_code == 403
    assert "tools/call" not in UPSTREAM_CALLS, "denied call must not reach upstream"

    records = _read_log(tmp_path)
    assert len(records) == 1
    assert records[0]["event_type"] == "denial"
    assert records[0]["policy_decision"] == "DENY"


@pytest.mark.asyncio
async def test_schema_guard_denial_follows_authorization_record(env, tmp_path):
    """Policy allowed (authorization written) but the schema pin denied."""
    client = await env()
    # Withdraw the tool upstream so the live listing no longer has it.
    def withdrawn(request: httpx.Request) -> httpx.Response:
        payload = jsonlib.loads(request.content)
        rid = payload.get("id")
        UPSTREAM_CALLS.append(payload.get("method"))
        result = {"tools": [], "resultType": "complete"}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": result})

    await gw.http_client.aclose()
    gw.http_client = httpx.AsyncClient(transport=httpx.MockTransport(withdrawn))

    r = await call(client)
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "tool_withdrawn_upstream"
    assert "tools/call" not in UPSTREAM_CALLS

    records = _read_log(tmp_path)
    assert [x["event_type"] for x in records] == ["authorization", "denial"]


# ── fail-closed on audit failure ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_failed_authorization_write_refuses_request_and_skips_upstream(env):
    logger = FailingWriteLogger(log_dir="unused")
    client = await env(logger)
    r = await call(client)
    assert r.status_code == 503
    assert r.json()["detail"]["error"] == "audit_unavailable"
    assert "tools/call" not in UPSTREAM_CALLS, (
        "an ALLOW whose authorisation was never recorded must not execute"
    )


@pytest.mark.asyncio
async def test_audit_write_failure_on_denial_still_denies(env):
    """A denial must not become an allow because the log write failed."""
    logger = FailingWriteLogger(log_dir="unused")
    client = await env(logger)

    class DenyPolicy:
        async def evaluate(self, policy_input) -> PolicyDecision:
            return PolicyDecision(
                allow=False, reason="denied for test", rule_matched="test.deny",
                evaluation_ms=0.1,
            )

    gw.policy_engine = DenyPolicy()
    r = await call(client)
    assert r.status_code == 403
    assert "tools/call" not in UPSTREAM_CALLS
