#!/usr/bin/env python3
"""
Audit hash-chain integrity experiment (pre-fix vs post-fix).

Measures how often concurrent writers break the audit hash chain when the
record hash is computed outside the writer lock (the implementation submitted
for the first attempt) compared with the corrected implementation, which links,
hashes and appends inside a single critical section.

For each concurrency level the experiment writes a fixed total number of audit
records through both implementations, then runs the chain verifier over the
resulting NDJSON and records the proportion of links that do not resolve.

Usage
-----
    python3 tests/audit_chain_experiment.py
    python3 tests/audit_chain_experiment.py --total 4000 --out results/

Outputs
-------
    results/audit_chain_integrity.csv

Reproduces: Table 4.9 and Figure 4.11 of the dissertation.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway.audit_logger import AuditLogger, verify_chain  # noqa: E402
from gateway.models import AuditRecord  # noqa: E402

CONCURRENCY_LEVELS = [1, 2, 5, 10, 25, 50, 100]


class PreFixAuditLogger(AuditLogger):
    """First-attempt implementation: hash computed before the lock is taken."""

    async def write(self, record: AuditRecord):  # type: ignore[override]
        import aiofiles

        record_dict = record.to_dict()
        record_dict["prev_hash"] = self._prev_hash
        record_dict["record_hash"] = hashlib.sha256(
            json.dumps(record_dict, sort_keys=True).encode()
        ).hexdigest()
        async with self._lock:
            async with aiofiles.open(self._log_path(), mode="a", encoding="utf-8") as f:
                await f.write(json.dumps(record_dict) + "\n")
            self._prev_hash = record_dict["record_hash"]
            self._buffer.append(record_dict)


def make_record(i: int) -> AuditRecord:
    return AuditRecord(
        request_id=f"req-{i:06d}",
        timestamp=1_750_000_000.0 + i,
        user_id=f"user{i % 7}",
        role="developer",
        tool_name="filesystem.read",
        policy_decision=(i % 3 != 0),
        policy_reason="chain integrity experiment",
        policy_rule_matched="rbac.developer",
        latency_policy_ms=1.0,
        source_ip="127.0.0.1",
        session_id=f"sess-{i % 5}",
    )


def read_log(log_dir: Path) -> list[dict]:
    records: list[dict] = []
    for path in sorted(log_dir.glob("mcp_audit_*.ndjson")):
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    return records


async def run_one(cls, concurrency: int, total: int) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="chain-exp-"))
    try:
        logger = cls(str(tmp))
        await logger.initialize()
        per_writer = total // concurrency

        async def writer(base: int) -> None:
            for j in range(per_writer):
                await logger.write(make_record(base + j))

        await asyncio.gather(
            *(writer(w * per_writer) for w in range(concurrency))
        )
        summary = verify_chain(read_log(tmp))
        broken = len(summary["bad_link"]) + len(summary["bad_content"])
        checked = max(summary["links_checked"], 1)
        return {
            "records": summary["records"],
            "links_checked": summary["links_checked"],
            "broken_links": broken,
            "broken_pct": round(broken / checked * 100, 2),
            "intact": summary["intact"],
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


async def main_async(total: int, out_dir: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    print(
        f"{'concurrency':>12}{'records':>9}"
        f"{'pre-fix broken':>16}{'post-fix broken':>17}"
    )
    print("-" * 54)
    for c in CONCURRENCY_LEVELS:
        pre = await run_one(PreFixAuditLogger, c, total)
        post = await run_one(AuditLogger, c, total)
        rows.append(
            {
                "concurrency": c,
                "records": post["records"],
                "links_checked": post["links_checked"],
                "prefix_broken_links": pre["broken_links"],
                "prefix_broken_pct": pre["broken_pct"],
                "postfix_broken_links": post["broken_links"],
                "postfix_broken_pct": post["broken_pct"],
                "postfix_intact": post["intact"],
            }
        )
        print(
            f"{c:>12}{post['records']:>9}"
            f"{pre['broken_links']:>9} ({pre['broken_pct']:>4.1f}%)"
            f"{post['broken_links']:>10} ({post['broken_pct']:>4.1f}%)"
        )

    csv_path = out_dir / "audit_chain_integrity.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nwrote {csv_path}")

    all_intact = all(r["postfix_intact"] for r in rows)
    print(
        "post-fix chain intact at every concurrency level"
        if all_intact
        else "WARNING: post-fix chain was broken at one or more levels"
    )
    return 0 if all_intact else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--total", type=int, default=2000, help="records per run")
    ap.add_argument("--out", default="results", help="output directory")
    args = ap.parse_args()
    return asyncio.run(main_async(args.total, Path(args.out)))


if __name__ == "__main__":
    raise SystemExit(main())
