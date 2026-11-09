#!/usr/bin/env python3
"""
Audit hash-chain integrity verifier.

Reads one or more NDJSON audit logs written by ``gateway.audit_logger`` and
checks, for every record that carries a hash, that

  1. the stored ``record_hash`` matches a recomputation over the record's
     content (detecting tampering with a field after the fact), and
  2. the record's ``prev_hash`` equals the preceding record's ``record_hash``
     (detecting insertion, deletion or reordering).

Usage
-----
    python3 scripts/verify_chain.py logs/                     # every log file
    python3 scripts/verify_chain.py logs/mcp_audit_2026-06-06.ndjson
    python3 scripts/verify_chain.py logs/ --json              # machine readable

Exit status is 0 when every checked file is intact and 1 otherwise, so the
script can be used as a gate in a reproduction run.

Reproduces: Table 4.9 and Section 4.7 of the dissertation.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway.audit_logger import verify_chain  # noqa: E402


def load(path: Path) -> list[dict]:
    records = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return records


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target", help="an NDJSON log file or a directory of them")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    args = ap.parse_args()

    target = Path(args.target)
    if target.is_dir():
        files = sorted(target.glob("mcp_audit_*.ndjson"))
    else:
        files = [target]

    if not files:
        print(f"no audit logs found under {target}", file=sys.stderr)
        return 1

    results = {}
    for path in files:
        records = load(path)
        summary = verify_chain(records)
        summary["unhashed"] = summary["records"] - summary["with_hash"]
        results[path.name] = summary

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        head = f"{'log file':<34}{'records':>9}{'hashed':>9}{'links':>8}{'broken':>8}  status"
        print(head)
        print("-" * len(head))
        for name, s in results.items():
            broken = len(s["bad_link"]) + len(s["bad_content"])
            status = "intact" if s["intact"] and s["unhashed"] == 0 else "BROKEN"
            if s["intact"] and s["unhashed"]:
                status = f"no hashes ({s['unhashed']})"
            print(
                f"{name:<34}{s['records']:>9}{s['with_hash']:>9}"
                f"{s['links_checked']:>8}{broken:>8}  {status}"
            )

    ok = all(s["intact"] and s["unhashed"] == 0 for s in results.values())
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
