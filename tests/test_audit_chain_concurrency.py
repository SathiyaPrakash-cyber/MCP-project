"""
Concurrency test for the audit hash chain.

This test exists because an earlier revision of ``AuditLogger.write`` computed
``prev_hash`` and ``record_hash`` *before* acquiring the writer lock. Under
concurrent load several coroutines could read the same chain head, so the
records they appended all pointed at the same predecessor and the chain no
longer resolved. The defect is quantified in Section 4.7 of the dissertation.

Two tests are provided:

* ``test_concurrent_writes_preserve_chain`` drives the current, fixed logger
  with a large number of concurrent writers and asserts the resulting log is
  an unbroken chain.
* ``test_prehash_outside_lock_breaks_chain`` reconstructs the old behaviour in
  a local subclass and asserts that it *does* break, so the regression test
  would fail if the hash computation were ever moved back out of the lock.

Run with:  pytest -q tests/test_audit_chain_concurrency.py
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway.audit_logger import AuditLogger, verify_chain  # noqa: E402
from gateway.models import AuditRecord  # noqa: E402

CONCURRENT_WRITERS = 50
WRITES_PER_WRITER = 20
TOTAL = CONCURRENT_WRITERS * WRITES_PER_WRITER


def _record(i: int) -> AuditRecord:
    return AuditRecord(
        request_id=f"req-{i:05d}",
        timestamp=1_750_000_000.0 + i,
        user_id=f"user{i % 7}",
        role="developer",
        tool_name="filesystem.read",
        policy_decision=(i % 3 != 0),
        policy_reason="concurrency test",
        policy_rule_matched="rbac.developer",
        latency_policy_ms=1.0,
        source_ip="127.0.0.1",
        session_id=f"sess-{i % 5}",
    )


def _read_log(log_dir: Path) -> list[dict]:
    records: list[dict] = []
    for path in sorted(log_dir.glob("mcp_audit_*.ndjson")):
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    return records


async def _drive(logger: AuditLogger) -> None:
    async def writer(base: int) -> None:
        for j in range(WRITES_PER_WRITER):
            await logger.write(_record(base + j))

    await asyncio.gather(
        *(writer(w * WRITES_PER_WRITER) for w in range(CONCURRENT_WRITERS))
    )


@pytest.mark.asyncio
async def test_concurrent_writes_preserve_chain(tmp_path):
    """The fixed logger produces an unbroken chain under concurrent load."""
    logger = AuditLogger(str(tmp_path))
    await logger.initialize()
    await _drive(logger)

    records = _read_log(tmp_path)
    assert len(records) == TOTAL, f"expected {TOTAL} records, got {len(records)}"

    summary = verify_chain(records)
    assert summary["with_hash"] == TOTAL, "every record must carry a hash"
    assert summary["links_checked"] == TOTAL - 1
    assert summary["genesis_ok"] is True, "first record must link to the genesis hash"
    assert not summary["bad_content"], (
        f"{len(summary['bad_content'])} records failed content rehash"
    )
    assert not summary["bad_link"], (
        f"{len(summary['bad_link'])} broken links out of {summary['links_checked']}"
    )
    assert summary["intact"] is True


class _PreFixAuditLogger(AuditLogger):
    """The pre-fix implementation: hash computed before the lock is taken."""

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


@pytest.mark.asyncio
async def test_prehash_outside_lock_breaks_chain(tmp_path):
    """Guard test: hashing outside the lock must be detectable as broken."""
    logger = _PreFixAuditLogger(str(tmp_path))
    await logger.initialize()
    await _drive(logger)

    summary = verify_chain(_read_log(tmp_path))
    assert summary["bad_link"], (
        "the pre-fix implementation was expected to break the chain; if this "
        "assertion fails the concurrency test is no longer exercising the race"
    )
