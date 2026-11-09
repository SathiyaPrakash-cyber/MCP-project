"""
MCP Gateway - Integration Test Suite
Tests:
  1. RBAC allow/deny matrix
  2. ABAC context-based restrictions
  3. Attack simulations (tool poisoning, privilege escalation, rug pull)
  4. Latency benchmarks (validates <50ms OPA SLA from RQ1)
  5. Audit log integrity

Run: python tests/test_gateway.py
     (standalone runner; pytest cannot collect these because the tests take a
      client fixture that this file supplies itself, so it is not used here)
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path

# Allow running from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from gateway.auth import generate_test_token

# ── Test configuration ─────────────────────────────────────────────────────────
GATEWAY_URL = "http://localhost:8080"
# Must match the value the gateway container was started with.
# scripts/bootstrap_env.sh writes it to .env;  set -a; . ./.env; set +a
JWT_SECRET = os.environ.get("JWT_SECRET", "")

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


# ── Token fixtures ─────────────────────────────────────────────────────────────

def make_token(role: str, user_id: str = None) -> str:
    uid = user_id or f"test_{role}_001"
    return generate_test_token(user_id=uid, role=role, email=f"{role}@test.com")


# ── Test cases (each returns True=pass, False=fail) ───────────────────────────

async def test_admin_can_call_any_tool(client: "httpx.AsyncClient") -> bool:
    """Admin role should be allowed on any tool."""
    token = make_token("admin")
    resp = await client.post(
        f"{GATEWAY_URL}/mcp/v1/tools/call",
        json={"tool": {"name": "filesystem.read"}, "arguments": {"path": "/tmp"}},
        headers={"Authorization": f"Bearer {token}"},
    )
    passed = resp.status_code == 200
    print(f"  [{'PASS' if passed else 'FAIL'}] Admin can call filesystem.read → {resp.status_code}")
    return passed


async def test_readonly_denied_write_tool(client: "httpx.AsyncClient") -> bool:
    """read_only role must be denied filesystem.write."""
    token = make_token("read_only")
    resp = await client.post(
        f"{GATEWAY_URL}/mcp/v1/tools/call",
        json={"tool": {"name": "filesystem.write"}, "arguments": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    passed = resp.status_code == 403
    body = resp.json()
    print(f"  [{'PASS' if passed else 'FAIL'}] read_only denied filesystem.write → {resp.status_code} ({body.get('detail', {}).get('reason', '')})")
    return passed


async def test_developer_can_execute_code(client: "httpx.AsyncClient") -> bool:
    """developer role should be allowed code.execute."""
    token = make_token("developer")
    resp = await client.post(
        f"{GATEWAY_URL}/mcp/v1/tools/call",
        json={"tool": {"name": "code.execute"}, "arguments": {"code": "print('hello')"}},
        headers={"Authorization": f"Bearer {token}"},
    )
    passed = resp.status_code == 200
    print(f"  [{'PASS' if passed else 'FAIL'}] Developer can call code.execute → {resp.status_code}")
    return passed


async def test_developer_denied_admin_tool(client: "httpx.AsyncClient") -> bool:
    """developer must be denied admin.create_user."""
    token = make_token("developer")
    resp = await client.post(
        f"{GATEWAY_URL}/mcp/v1/tools/call",
        json={"tool": {"name": "admin.create_user"}, "arguments": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    passed = resp.status_code == 403
    print(f"  [{'PASS' if passed else 'FAIL'}] Developer denied admin.create_user → {resp.status_code}")
    return passed


async def test_globally_blocked_tool_always_denied(client: "httpx.AsyncClient") -> bool:
    """Even admin must be denied a globally blocked tool."""
    token = make_token("admin")
    resp = await client.post(
        f"{GATEWAY_URL}/mcp/v1/tools/call",
        json={"tool": {"name": "system.format_disk"}, "arguments": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    passed = resp.status_code == 403
    print(f"  [{'PASS' if passed else 'FAIL'}] Globally blocked tool denied even for admin → {resp.status_code}")
    return passed


async def test_no_token_rejected(client: "httpx.AsyncClient") -> bool:
    """Request without token must return 401."""
    resp = await client.post(
        f"{GATEWAY_URL}/mcp/v1/tools/call",
        json={"tool": {"name": "filesystem.read"}, "arguments": {}},
    )
    passed = resp.status_code == 401
    print(f"  [{'PASS' if passed else 'FAIL'}] No token → 401 → {resp.status_code}")
    return passed


async def test_expired_token_rejected(client: "httpx.AsyncClient") -> bool:
    """Expired JWT must return 401."""
    token = generate_test_token(
        user_id="expired_user",
        role="admin",
        ttl_seconds=-1,  # already expired
    )
    resp = await client.post(
        f"{GATEWAY_URL}/mcp/v1/tools/call",
        json={"tool": {"name": "filesystem.read"}, "arguments": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    passed = resp.status_code == 401
    print(f"  [{'PASS' if passed else 'FAIL'}] Expired token → 401 → {resp.status_code}")
    return passed


async def test_privilege_escalation_attack(client: "httpx.AsyncClient") -> bool:
    """
    Attack simulation: read_only user attempts database.drop.
    Must be blocked (privilege escalation).
    """
    token = make_token("read_only", user_id="attacker_001")
    resp = await client.post(
        f"{GATEWAY_URL}/mcp/v1/tools/call",
        json={"tool": {"name": "database.drop"}, "arguments": {"table": "users"}},
        headers={"Authorization": f"Bearer {token}"},
    )
    passed = resp.status_code == 403
    print(f"  [{'PASS' if passed else 'FAIL'}] [ATTACK] Privilege escalation (database.drop as read_only) blocked → {resp.status_code}")
    return passed


async def test_tool_poisoning_blocked_tool(client: "httpx.AsyncClient") -> bool:
    """
    Tool poisoning: attacker injects admin.drop_all_tables.
    Globally blocked → must be denied regardless of role.
    """
    token = make_token("admin", user_id="poisoned_agent")
    resp = await client.post(
        f"{GATEWAY_URL}/mcp/v1/tools/call",
        json={"tool": {"name": "admin.drop_all_tables"}, "arguments": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    passed = resp.status_code == 403
    print(f"  [{'PASS' if passed else 'FAIL'}] [ATTACK] Tool poisoning (globally blocked tool) blocked → {resp.status_code}")
    return passed


async def test_sensitive_tool_requires_elevated_role(client: "httpx.AsyncClient") -> bool:
    """
    ABAC: sensitive tool (admin.modify_policy) requires elevated role.
    developer must be denied even though not in explicit RBAC deny.
    """
    token = make_token("developer")
    resp = await client.post(
        f"{GATEWAY_URL}/mcp/v1/tools/call",
        json={"tool": {"name": "admin.modify_policy"}, "arguments": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    passed = resp.status_code == 403
    print(f"  [{'PASS' if passed else 'FAIL'}] [ABAC] Sensitive tool denied to developer → {resp.status_code}")
    return passed


async def test_policy_decision_latency(client: "httpx.AsyncClient") -> bool:
    """
    RQ1 benchmark: policy decision overhead must be under 50ms.
    Average over 20 requests.
    """
    token = make_token("developer")
    latencies = []
    N = 20

    for _ in range(N):
        start = time.time()
        resp = await client.post(
            f"{GATEWAY_URL}/mcp/v1/tools/call",
            json={"tool": {"name": "filesystem.read"}, "arguments": {}},
            headers={"Authorization": f"Bearer {token}"},
        )
        elapsed_ms = (time.time() - start) * 1000

        if resp.status_code == 200:
            meta = resp.json().get("gateway_meta", {})
            policy_ms = meta.get("policy_latency_ms", elapsed_ms)
            latencies.append(policy_ms)

    if not latencies:
        print(f"  [FAIL] Latency test: no successful responses")
        return False

    avg_ms = sum(latencies) / len(latencies)
    max_ms = max(latencies)
    passed = avg_ms < 50

    print(f"  [{'PASS' if passed else 'FAIL'}] Policy latency: avg={avg_ms:.1f}ms max={max_ms:.1f}ms (SLA=50ms) over {len(latencies)} requests")
    return passed


async def test_tool_list_filtered_by_role(client: "httpx.AsyncClient") -> bool:
    """
    read_only user's tool list must not include write/delete tools.
    """
    token = make_token("read_only")
    resp = await client.post(
        f"{GATEWAY_URL}/mcp/v1/tools/list",
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp.status_code != 200:
        print(f"  [FAIL] Tool list returned {resp.status_code}")
        return False

    tools = resp.json().get("tools", [])
    tool_names = [t["name"] for t in tools]
    has_write = any("write" in n or "delete" in n or "drop" in n for n in tool_names)
    passed = not has_write

    print(f"  [{'PASS' if passed else 'FAIL'}] Tool list filtered for read_only: {len(tool_names)} tools visible, no write tools={'yes' if not has_write else 'NO - LEAK'}")
    return passed


async def test_audit_log_written(client: "httpx.AsyncClient") -> bool:
    """Audit endpoint must return records after test calls."""
    token = make_token("admin")
    # Make a call first
    await client.post(
        f"{GATEWAY_URL}/mcp/v1/tools/call",
        json={"tool": {"name": "filesystem.read"}, "arguments": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    # Check audit
    resp = await client.get(
        f"{GATEWAY_URL}/audit/recent?limit=5",
        headers={"Authorization": f"Bearer {token}"},
    )
    passed = resp.status_code == 200 and len(resp.json().get("records", [])) > 0
    count = len(resp.json().get("records", [])) if resp.status_code == 200 else 0
    print(f"  [{'PASS' if passed else 'FAIL'}] Audit log: {count} records found")
    return passed


# ─── Test runner ──────────────────────────────────────────────────────────────

TESTS = [
    test_no_token_rejected,
    test_expired_token_rejected,
    test_admin_can_call_any_tool,
    test_readonly_denied_write_tool,
    test_developer_can_execute_code,
    test_developer_denied_admin_tool,
    test_globally_blocked_tool_always_denied,
    test_privilege_escalation_attack,
    test_tool_poisoning_blocked_tool,
    test_sensitive_tool_requires_elevated_role,
    test_tool_list_filtered_by_role,
    test_audit_log_written,
    test_policy_decision_latency,   # Run last (warm cache)
]


async def run_all_tests() -> int:
    """Run the suite and return a process exit code (0 = success)."""
    if not HAS_HTTPX:
        print("ERROR: httpx not installed. Run: pip install httpx")
        return 1

    print("\n" + "="*60)
    print("  MCP Gateway Test Suite")
    print("="*60)

    # Check gateway is up
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            health = await client.get(f"{GATEWAY_URL}/health")
            if health.status_code != 200:
                print(f"ERROR: Gateway health check failed: {health.status_code}")
                return 1
            print(f"Gateway healthy: {health.json()}\n")
    except Exception as e:
        print(f"ERROR: Gateway not reachable at {GATEWAY_URL}: {e}")
        print("Make sure you ran: docker-compose up -d")
        return 1

    passed = 0
    failed = 0

    async with httpx.AsyncClient(timeout=10.0) as client:
        for test_fn in TESTS:
            try:
                result = await test_fn(client)
                if result:
                    passed += 1
                else:
                    failed += 1
            except Exception as e:
                print(f"  [ERROR] {test_fn.__name__}: {e}")
                failed += 1

    print("\n" + "="*60)
    print(f"  Results: {passed}/{passed+failed} passed")
    if failed > 0:
        print(f"  {failed} FAILURES - investigate before submission")
    else:
        print("  ALL TESTS PASSED")
    print("="*60 + "\n")

    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run_all_tests()))
