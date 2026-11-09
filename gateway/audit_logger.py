"""
Immutable Audit Logger
Records every policy decision and tool call in SIEM-compatible JSON (NDJSON).
Supports append-only writes - records are never mutated.
Compatible with Elasticsearch / Kibana ingestion format.
"""

import asyncio
import json
import os
import time
from collections import deque
from pathlib import Path
from typing import Optional

import hashlib
import aiofiles
import structlog

from .models import AuditRecord

log = structlog.get_logger()

# In-memory circular buffer for /audit/recent endpoint (last 1000 records)
_BUFFER_MAX = 1000

GENESIS_HASH = "0" * 64


class AuditWriteError(Exception):
    """
    Raised when an audit record could not be made durable.

    The gateway's audit-before-execution contract treats this as fatal for
    the request: an ALLOW decision that cannot be written to the log is not
    a decision the system is allowed to act on, so the tool is never called
    and the client receives a 503 (``AUDIT_UNAVAILABLE``).
    """


def compute_record_hash(record_dict: dict) -> str:
    """
    Canonical hash of one audit record.

    The digest covers every field of the record including ``prev_hash`` but
    excluding ``record_hash`` itself. Keys are sorted so the encoding is
    independent of insertion order. This single definition is used both when
    writing records and when verifying a chain, so the two cannot drift.
    """
    payload = {k: v for k, v in record_dict.items() if k != "record_hash"}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def verify_chain(records: list[dict], expect_genesis: bool = True) -> dict:
    """
    Verify hash-chain continuity over an ordered list of audit records.

    Returns a summary dict with the total number of records, how many carry a
    hash, how many links were checkable, and the indices of any record whose
    stored ``record_hash`` does not match its content or whose ``prev_hash``
    does not equal the preceding record's ``record_hash``.
    """
    summary = {
        "records": len(records),
        "with_hash": 0,
        "links_checked": 0,
        "bad_content": [],
        "bad_link": [],
        "genesis_ok": None,
    }
    prev = None
    for i, rec in enumerate(records):
        stored = rec.get("record_hash")
        if not stored:
            prev = None
            continue
        summary["with_hash"] += 1
        if compute_record_hash(rec) != stored:
            summary["bad_content"].append(i)
        if prev is None:
            if expect_genesis and i == 0:
                summary["genesis_ok"] = rec.get("prev_hash") == GENESIS_HASH
        else:
            summary["links_checked"] += 1
            if rec.get("prev_hash") != prev:
                summary["bad_link"].append(i)
        prev = stored
    summary["intact"] = not summary["bad_content"] and not summary["bad_link"]
    return summary


class AuditLogger:
    """
    Async NDJSON audit logger.
    Each record is one JSON object per line - immutable, append-only.
    """

    def __init__(self, log_dir: str):
        self.log_dir = Path(log_dir)
        self._buffer: deque[dict] = deque(maxlen=_BUFFER_MAX)
        self._lock = asyncio.Lock()
        self._prev_hash = GENESIS_HASH
        self._failed = False
        import os as _os
        self._es_url = _os.getenv("ES_URL", "")  # F1: set to http://elasticsearch:9200 to enable
        self._es_index = _os.getenv("ES_INDEX", "mcp-gateway-audit")
        self._stats = {
            "total_requests": 0,
            "total_allowed": 0,
            "total_denied": 0,
            "total_errors": 0,
        }

    async def initialize(self):
        """Create log directory if it doesn't exist."""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._continue_chain()
        log.info("audit_logger.initialized", log_dir=str(self.log_dir))

    def _log_path(self) -> Path:
        """Daily rotating log file: mcp_audit_YYYY-MM-DD.ndjson"""
        day = time.strftime("%Y-%m-%d", time.gmtime())
        return self.log_dir / f"mcp_audit_{day}.ndjson"

    def _continue_chain(self):
        """F2: resume the hash chain from the last record on disk."""
        try:
            import json as _json
            files = sorted(self.log_dir.glob("mcp_audit_*.ndjson"))
            if not files:
                return
            lines = [l for l in files[-1].read_text().splitlines() if l.strip()]
            if not lines:
                return
            last = _json.loads(lines[-1])
            if last.get("record_hash"):
                self._prev_hash = last["record_hash"]
                log.info("audit_logger.chain_resumed", prev=self._prev_hash[:12])
        except Exception as e:
            log.warning("audit_logger.chain_resume_failed", error=str(e))

    async def _ship_to_es(self, record_dict: dict):
        """F1: best-effort async POST to Elasticsearch bulk API."""
        if not self._es_url:
            return
        try:
            import httpx as _httpx, json as _json
            body = (
                _json.dumps({"index": {"_index": self._es_index}}) + "\n"
                + _json.dumps(record_dict) + "\n"
            )
            async with _httpx.AsyncClient(timeout=2.0) as c:
                await c.post(
                    f"{self._es_url}/_bulk",
                    content=body.encode(),
                    headers={"Content-Type": "application/x-ndjson"},
                )
        except Exception as e:
            log.debug("audit_logger.es_ship_failed", error=str(e))

    async def write(self, record: AuditRecord):
        """
        Append one audit record to the NDJSON log file and make it durable.

        Chain integrity: ``prev_hash`` is read, ``record_hash`` is computed and
        the line is appended inside a single lock-protected critical section.
        Computing the hash outside the lock (as an earlier revision did) lets
        concurrent coroutines observe the same ``_prev_hash`` and emit records
        whose links do not resolve; see ``scripts/verify_chain.py`` for the
        verifier and Section 4.7 of the report for the measured effect.

        Durability and failure: after the append, the file is flushed and
        ``fsync``-ed before the chain head advances, so a record that has been
        acknowledged is on stable storage even if the process dies
        immediately afterwards. If the write or the sync fails, the chain head
        is NOT advanced and :class:`AuditWriteError` is raised. Swallowing
        that failure (as an earlier revision did) silently dropped the very
        evidence the mechanism exists to produce, and would have let the
        gateway execute a tool call whose authorisation was never recorded.
        """
        record_dict = record.to_dict()

        try:
            async with self._lock:
                if self._failed:
                    raise AuditWriteError(
                        "audit logger is unavailable after an earlier ambiguous write failure"
                    )
                # --- critical section: link, hash, append and fsync ---
                record_dict["prev_hash"] = self._prev_hash
                record_dict["record_hash"] = compute_record_hash(record_dict)

                line = json.dumps(record_dict) + "\n"
                path = self._log_path()
                async with aiofiles.open(path, mode="a", encoding="utf-8") as f:
                    await f.write(line)
                    await f.flush()
                    # fsync while the handle is still open, so the bytes are
                    # on stable storage before the chain head advances.
                    import os as _os
                    _os.fsync(f.fileno())

                # Advance the chain head only after the line is durable.
                self._prev_hash = record_dict["record_hash"]
                self._buffer.append(record_dict)
                self._stats["total_requests"] += 1
                if record.policy_decision:
                    self._stats["total_allowed"] += 1
                else:
                    self._stats["total_denied"] += 1
                if record.upstream_error:
                    self._stats["total_errors"] += 1

        except AuditWriteError:
            self._failed = True
            raise
        except Exception as e:
            self._failed = True
            log.error("audit_logger.write_failed", error=str(e), exc_info=True)
            raise AuditWriteError(f"audit write failed: {e}") from e

        await self._ship_to_es(record_dict)

    async def get_recent(self, limit: int = 50) -> list[dict]:
        """Return last N records from in-memory buffer."""
        records = list(self._buffer)
        return records[-limit:] if len(records) > limit else records

    async def get_stats(self) -> dict:
        """Return aggregate statistics."""
        return {
            **self._stats,
            "deny_rate": (
                round(
                    self._stats["total_denied"]
                    / max(self._stats["total_requests"], 1)
                    * 100,
                    2,
                )
            ),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    async def export_for_siem(
        self,
        start_epoch: Optional[float] = None,
        end_epoch: Optional[float] = None,
    ) -> list[dict]:
        """
        Export records for a time window.
        Used to feed Elasticsearch or other SIEM systems.
        """
        all_records: list[dict] = []

        for log_file in sorted(self.log_dir.glob("mcp_audit_*.ndjson")):
            try:
                async with aiofiles.open(log_file, mode="r", encoding="utf-8") as f:
                    async for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                            ts = rec.get("timestamp_epoch", 0)
                            if start_epoch and ts < start_epoch:
                                continue
                            if end_epoch and ts > end_epoch:
                                continue
                            all_records.append(rec)
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                log.error("audit_logger.export_error", file=str(log_file), error=str(e))

        return all_records
