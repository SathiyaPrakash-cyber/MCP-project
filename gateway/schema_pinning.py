"""
Runtime tool-schema pinning — rug-pull detection (B2 novel mechanism, wired in E1).

A rug pull is a tool whose advertised description or input schema changes after
a client has approved it, so that a tool the user once consented to quietly
starts doing something else. The gateway defends against this by hashing every
tool schema advertised by each upstream MCP server at startup, sealing that
upstream's snapshot, and re-checking the live schema on every call.

Per-upstream registries
-----------------------
The laboratory topology routes four tool-name prefixes (``filesystem``,
``database``, ``code``, ``saas``) at the *same* mock MCP server. A single
global registry keyed only by tool name cannot express "this upstream's
baseline is sealed" independently of the others, so the registry is keyed by
``(upstream_base_url, tool_name)``. Each upstream is sealed independently
during the startup discovery pass; an upstream whose baseline could not be
built is treated as unsealed forever, and every call routed to it is denied
(fail-closed). Applying trust-on-first-use on the request path would let an
attacker introduce a brand-new tool and have it trusted on its first
invocation, which is exactly the attack the mechanism exists to stop.

The verification hash covers the entire tool definition as returned by the
upstream's ``tools/list`` (``name``, ``description`` and ``inputSchema``),
because a change to any of those fields can change what the tool does.
"""

import hashlib
import json

import structlog

log = structlog.get_logger()


class ToolSchemaPinning:
    def __init__(self):
        # (upstream_base_url, tool_name) -> sha256 of the canonical tool def
        self._registry: dict[tuple[str, str], str] = {}
        # upstreams whose baseline has been successfully sealed
        self._sealed_upstreams: set[str] = set()
        self.drift_count = 0
        self.check_count = 0
        self.unpinned_denials = 0

    # ── baseline construction (startup only) ────────────────────────────────

    def register(self, upstream: str, tool_name: str, schema: dict) -> str:
        """
        Pin one tool schema for one upstream.

        Rejected once *that upstream's* registry is sealed: after sealing, an
        unknown tool is a denial rather than a new registration.
        """
        if upstream in self._sealed_upstreams:
            raise RuntimeError(
                f"schema registry for upstream '{upstream}' is sealed; "
                "tools cannot be pinned at request time"
            )
        h = self._hash(schema)
        self._registry[(upstream, tool_name)] = h
        log.info(
            "schema_pin.registered",
            upstream=upstream,
            tool=tool_name,
            hash=h[:12],
        )
        return h

    def register_many(self, upstream: str, tools: list[dict]):
        for t in tools:
            name = t.get("name")
            if name:
                self.register(upstream, name, t)

    def seal(self, upstream: str):
        """
        Close the baseline for one upstream. Must be called once that
        upstream's startup pinning pass has succeeded; until it is called,
        ``is_ready(upstream)`` is False and the gateway denies tool calls
        routed to that upstream rather than forwarding them unverified.
        """
        keys = [k for k in self._registry if k[0] == upstream]
        if not keys:
            raise RuntimeError(
                f"refusing to seal an empty schema snapshot for '{upstream}'"
            )
        self._sealed_upstreams.add(upstream)
        log.info(
            "schema_pin.sealed", upstream=upstream, tools=len(keys)
        )

    def is_sealed(self, upstream: str) -> bool:
        return upstream in self._sealed_upstreams

    # ── request-path checks ─────────────────────────────────────────────────

    def is_ready(self, upstream: str) -> bool:
        """True only when this upstream's snapshot has been pinned and sealed."""
        return self.is_sealed(upstream) and any(
            k[0] == upstream for k in self._registry
        )

    def is_pinned(self, upstream: str, tool_name: str) -> bool:
        return (upstream, tool_name) in self._registry

    def verify(self, upstream: str, tool_name: str, schema: dict) -> tuple[bool, str]:
        """
        Compare a live tool definition against the pinned hash for this
        upstream.

        Returns ``(False, reason)`` for an unpinned tool once the upstream is
        sealed — it does not silently register it. Before sealing, an unknown
        tool is pinned, which is how the startup baseline is built.
        """
        self.check_count += 1
        key = (upstream, tool_name)
        if key not in self._registry:
            if self.is_sealed(upstream):
                self.unpinned_denials += 1
                msg = (
                    f"UNPINNED_TOOL: '{tool_name}' is not in the sealed schema "
                    f"snapshot for upstream '{upstream}' taken at startup"
                )
                log.warning(
                    "schema_pin.unpinned", upstream=upstream, tool=tool_name
                )
                return False, msg
            self.register(upstream, tool_name, schema)
            return True, "new_tool_registered"

        expected = self._registry[key]
        current = self._hash(schema)
        if expected != current:
            self.drift_count += 1
            msg = (
                f"RUG_PULL_DETECTED: schema of '{tool_name}' on '{upstream}' "
                f"changed {expected[:8]}->{current[:8]}"
            )
            log.warning(
                "schema_pin.drift", upstream=upstream, tool=tool_name, msg=msg
            )
            return False, msg
        return True, "schema_ok"

    def stats(self) -> dict:
        return {
            "tools_pinned": len(self._registry),
            "sealed_upstreams": len(self._sealed_upstreams),
            "checks": self.check_count,
            "drift_detected": self.drift_count,
            "unpinned_denials": self.unpinned_denials,
        }

    @staticmethod
    def _hash(schema: dict) -> str:
        return hashlib.sha256(
            json.dumps(schema, sort_keys=True).encode()
        ).hexdigest()
