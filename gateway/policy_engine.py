"""
Policy Engine - Policy Decision Point (PDP) client for OPA.
Single decision call (A4) + full-input cache key (A3).
Fails closed (DENY) when OPA is unreachable.
"""

import hashlib
import json
import os
import time
from dataclasses import dataclass

import httpx
import structlog

log = structlog.get_logger()


@dataclass
class PolicyDecision:
    allow: bool
    reason: str
    rule_matched: str
    evaluation_ms: float


class PolicyEngine:
    # A4: one rule object returning {allow, reason, rule_matched}
    DECISION_PATH = "/v1/data/mcp_gateway/authz/decision"

    def __init__(self, opa_url: str):
        self.opa_url = opa_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=5.0)
        self._cache: dict[str, tuple[PolicyDecision, float]] = {}
        # A3: cache can be disabled for deterministic benchmarking
        self._cache_disabled = os.getenv("DISABLE_POLICY_CACHE", "0") == "1"
        self._cache_ttl = 1.0

    @staticmethod
    def _full_input_key(policy_input: dict) -> str:
        # A3: key on the ENTIRE input (incl. context hour/ip/session + args),
        # so context-dependent ABAC decisions are never served stale.
        blob = json.dumps(policy_input, sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()

    async def evaluate(self, policy_input: dict) -> PolicyDecision:
        start = time.time()
        inp = policy_input.get("input", {})

        cache_key = self._full_input_key(policy_input)
        if not self._cache_disabled and cache_key in self._cache:
            decision, cached_at = self._cache[cache_key]
            if time.time() - cached_at < self._cache_ttl:
                return decision

        try:
            # A4: single round-trip
            resp = await self._client.post(
                f"{self.opa_url}{self.DECISION_PATH}",
                json=policy_input,
            )
            resp.raise_for_status()
            result = resp.json().get("result", {})
            allow = bool(result.get("allow", False))
            reason = result.get("reason", "policy_evaluated")
            rule_matched = result.get("rule_matched", "unknown")

        except httpx.RequestError as e:
            log.error("policy_engine.opa_unreachable", error=str(e))
            return PolicyDecision(
                allow=False,
                reason="opa_unreachable_fail_closed",
                rule_matched="none",
                evaluation_ms=round((time.time() - start) * 1000, 2),
            )
        except httpx.HTTPStatusError as e:
            log.error("policy_engine.opa_error", status=e.response.status_code)
            return PolicyDecision(
                allow=False,
                reason=f"opa_http_error_{e.response.status_code}",
                rule_matched="none",
                evaluation_ms=round((time.time() - start) * 1000, 2),
            )

        eval_ms = round((time.time() - start) * 1000, 2)
        decision = PolicyDecision(
            allow=allow,
            reason=reason,
            rule_matched=rule_matched,
            evaluation_ms=eval_ms,
        )

        if eval_ms > 50:
            log.warning("policy_engine.latency_sla_breach", eval_ms=eval_ms, sla_ms=50,
                        tool=inp.get("tool", {}).get("name"))

        if not self._cache_disabled:
            self._cache[cache_key] = (decision, time.time())
        return decision

    async def health_check(self) -> bool:
        try:
            resp = await self._client.get(f"{self.opa_url}/health")
            return resp.status_code == 200
        except Exception:
            return False
