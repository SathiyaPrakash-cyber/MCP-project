"""
RQ3 — Measured ASR reduction (both sides) on a probing corpus.
C1: every attack runs (a) directly at the mock and (b) through the gateway
    with a properly signed token for the attacker role. Both outcomes recorded;
    the reduction is computed, not asserted.
C2: corpus probes for failure — every role incl. admin wildcards, argument
    injection on permitted tools, name-canonicalisation variants, and tool drift.

The unmediated side speaks MCP 2026-07-28 directly to the mock server
(JSON-RPC over POST /mcp with the required per-request ``_meta`` and HTTP
metadata headers), because the mock no longer exposes the gateway's custom
REST adapter — it is a real MCP server.
"""
import asyncio
import csv
import json
import sys
import time
import uuid
from pathlib import Path

import httpx

sys.path.insert(0, ".")
from gateway.auth import generate_test_token

MOCK = "http://localhost:9000"
GATEWAY = "http://localhost:8080"
MCP_VERSION = "2026-07-28"

# (attack_class, tool, role, args)
CORPUS = [
    # privilege escalation
    ("privilege_escalation", "filesystem.write",        "read_only", {}),
    ("privilege_escalation", "database.drop",            "read_only", {}),
    ("privilege_escalation", "admin.create_user",        "developer", {}),
    ("privilege_escalation", "admin.modify_policy",      "developer", {}),
    # globally-blocked / privileged as admin (admin wildcard probe)
    ("admin_wildcard",       "system.format_disk",       "admin",     {}),
    ("admin_wildcard",       "admin.drop_all_tables",     "admin",     {}),
    ("admin_wildcard",       "code.execute_privileged",   "developer", {}),
    # name-canonicalisation bypass probes
    ("name_variant",         "system.FORMAT_DISK",        "admin",     {}),
    ("name_variant",         "SYSTEM.Format_Disk",        "admin",     {}),
    # argument injection on PERMITTED tools
    ("arg_injection",        "database.query",            "developer", {"sql": "SELECT * FROM users WHERE '1'='1' OR 1=1"}),
    ("arg_injection",        "database.query",            "developer", {"sql": "1; DELETE FROM accounts"}),
    ("arg_injection",        "filesystem.read",           "developer", {"path": "../../../../etc/passwd"}),
    # sensitivity (developer via code.* reaching a sensitive tool)
    ("sensitivity",          "code.deploy_production",    "developer", {}),
    # rug pull (tested separately in attack_simulation; placeholder here)
    # True-negative control: permitted call that correctly passes gateway
    ("true_negative_control", "filesystem.read",           "developer", {}),
]


async def hit_mock(client, tool, args):
    """Unmediated call: speak MCP 2026-07-28 straight to the mock server."""
    payload = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": args,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MCP_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": MCP_VERSION,
        "Mcp-Method": "tools/call",
        "Mcp-Name": tool,
    }
    try:
        r = await client.post(f"{MOCK}/mcp", json=payload, headers=headers)
        if r.status_code != 200:
            return False
        body = r.json()
        # A JSON-RPC error (e.g. unknown tool) is a blocked call; a result
        # object — even one with isError: true — means the tool executed.
        return "result" in body and "error" not in body
    except Exception:
        return False


async def hit_gateway(client, tool, role, args):
    token = generate_test_token(f"atk_{role}", role, ttl_seconds=600)
    try:
        r = await client.post(
            f"{GATEWAY}/mcp/v1/tools/call",
            json={"tool": {"name": tool}, "arguments": args},
            headers={"Authorization": f"Bearer {token}"},
        )
        return r.status_code == 200
    except Exception:
        return False


async def run():
    print("\n" + "=" * 64)
    print("  RQ3 — MEASURED ASR (unmediated vs gateway) on probing corpus")
    print("=" * 64)
    rows = []
    limits = httpx.Limits(max_connections=1, max_keepalive_connections=0)
    async with httpx.AsyncClient(timeout=5.0, limits=limits) as client:
        for cls, tool, role, args in CORPUS:
            um = await hit_mock(client, tool, args)
            gw = await hit_gateway(client, tool, role, args)
            rows.append({
                "attack_class": cls, "tool": tool, "role": role,
                "succeeded_unmediated": um, "succeeded_gateway": gw,
            })
            um_s = "SUCCEED" if um else "blocked"
            gw_s = "SUCCEED" if gw else "blocked"
            flag = "  <-- GATEWAY BYPASS" if gw else ""
            print(f"  [{cls:20}] {role:10} {tool:28} unmediated={um_s:7} gateway={gw_s:7}{flag}")

    n = len(rows)
    um_succ = sum(1 for r in rows if r["succeeded_unmediated"])
    gw_succ = sum(1 for r in rows if r["succeeded_gateway"])
    um_asr = round(um_succ / n * 100, 1)
    gw_asr = round(gw_succ / n * 100, 1)
    reduction = round(um_asr - gw_asr, 1)

    print("\n  ── Measured result ──")
    print(f"  Corpus size:           {n}")
    print(f"  Unmediated ASR:        {um_succ}/{n} = {um_asr}%")
    print(f"  Gateway ASR:           {gw_succ}/{n} = {gw_asr}%")
    print(f"  ASR reduction:         {reduction} percentage points")
    if gw_succ > 0:
        print(f"  NOTE: {gw_succ} attack(s) still succeed through the gateway — these are")
        print(f"        the bypasses the corpus is designed to surface (correct, stronger result).")
    print()

    Path("logs").mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out = f"logs/baseline_both_sides_{ts}.csv"
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print(f"  CSV: {out}\n")


if __name__ == "__main__":
    asyncio.run(run())
