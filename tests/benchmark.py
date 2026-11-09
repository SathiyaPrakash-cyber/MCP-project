"""
RQ1 — Deterministic latency benchmark.
G1: fixed seed, cache-defeated (unique session per request), health-gated,
    fail-fast if any cell has errors, >=1000 samples/cell, mean +/- 95% CI over 3 repeats.
    Keeps the OPA-vs-end-to-end split.
"""
import asyncio
import csv
import math
import random
import statistics
import sys
import time
import uuid
from pathlib import Path

import httpx

sys.path.insert(0, ".")
from gateway.auth import generate_test_token

GATEWAY = "http://localhost:8080"
CONCURRENCY_LEVELS = [1, 5, 10, 25, 50, 100]
SAMPLES_PER_CELL = 1000
REPEATS = 3
SLA_MS = 50.0
SEED = 1337

random.seed(SEED)


def token(role):
    return generate_test_token(f"bench_{role}", role, ttl_seconds=3600)


async def health_gate():
    async with httpx.AsyncClient(timeout=5) as c:
        try:
            r = await c.get(f"{GATEWAY}/health")
            return r.status_code == 200
        except Exception:
            return False


async def one_request(client, tok):
    # unique session_id defeats the policy cache (A3 keys on full input)
    body = {"tool": {"name": "filesystem.read"},
            "arguments": {"path": "/tmp/x"},
            "session_id": str(uuid.uuid4())}
    t0 = time.perf_counter()
    try:
        r = await client.post(f"{GATEWAY}/mcp/v1/tools/call", json=body,
                              headers={"Authorization": f"Bearer {tok}"})
        e2e = (time.perf_counter() - t0) * 1000
        ok = r.status_code == 200
        pol = None
        try:
            pol = r.json().get("gateway_meta", {}).get("policy_latency_ms")
        except Exception:
            pass
        return ok, e2e, pol
    except Exception:
        return False, (time.perf_counter() - t0) * 1000, None


async def run_cell(concurrency, tok):
    e2e_lat, pol_lat, errors = [], [], 0
    limits = httpx.Limits(max_connections=concurrency + 10, max_keepalive_connections=concurrency)
    async with httpx.AsyncClient(timeout=30, limits=limits) as client:
        done = 0
        while done < SAMPLES_PER_CELL:
            batch = min(concurrency, SAMPLES_PER_CELL - done)
            res = await asyncio.gather(*[one_request(client, tok) for _ in range(batch)])
            for ok, e2e, pol in res:
                if not ok:
                    errors += 1
                else:
                    e2e_lat.append(e2e)
                    if pol is not None:
                        pol_lat.append(pol)
            done += batch
    return e2e_lat, pol_lat, errors


def ci95(values):
    if len(values) < 2:
        return 0.0
    sd = statistics.pstdev(values)
    return round(1.96 * sd / math.sqrt(len(values)), 2)


async def run():
    print("\n" + "=" * 72)
    print("  RQ1 — DETERMINISTIC LATENCY BENCHMARK")
    print(f"  seed={SEED} samples/cell={SAMPLES_PER_CELL} repeats={REPEATS} SLA={SLA_MS}ms")
    print("=" * 72)

    if not await health_gate():
        print("  ABORT: gateway /health not OK"); sys.exit(1)

    tok = token("developer")
    rows = []
    print(f"  {'Conc':<6} {'E2E mean':<12} {'E2E 95%CI':<11} {'Policy mean':<12} {'SLA pass%':<10} {'errors':<7}")
    print("  " + "-" * 68)

    for c in CONCURRENCY_LEVELS:
        repeat_means, repeat_pol, repeat_sla = [], [], []
        total_err = 0
        all_e2e = []
        for _ in range(REPEATS):
            e2e, pol, err = await run_cell(c, tok)
            total_err += err
            if e2e:
                repeat_means.append(statistics.mean(e2e))
                repeat_sla.append(sum(1 for x in e2e if x < SLA_MS) / len(e2e) * 100)
                all_e2e.extend(e2e)
            if pol:
                repeat_pol.append(statistics.mean(pol))

        # G1: fail-fast — abort the whole run if any cell errored
        if total_err > 0:
            print(f"  c={c}: ABORT — {total_err} errored requests (results not trustworthy)")
            sys.exit(2)

        e2e_mean = round(statistics.mean(repeat_means), 2) if repeat_means else 0
        e2e_ci = ci95(all_e2e)
        pol_mean = round(statistics.mean(repeat_pol), 2) if repeat_pol else 0
        sla = round(statistics.mean(repeat_sla), 1) if repeat_sla else 0
        print(f"  {c:<6} {e2e_mean:<12} +/-{e2e_ci:<8} {pol_mean:<12} {sla:<10} {total_err:<7}")
        rows.append({"concurrency": c, "e2e_mean_ms": e2e_mean, "e2e_ci95_ms": e2e_ci,
                     "policy_mean_ms": pol_mean, "sla_pass_pct": sla, "errors": total_err})

    Path("logs").mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out = f"logs/benchmark_deterministic_{ts}.csv"
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print(f"\n  CSV: {out}")
    print("  (Cache defeated via unique session_id per request; the policy-evaluation")
    print("   step is measured separately from the end-to-end path.)\n")


if __name__ == "__main__":
    asyncio.run(run())
