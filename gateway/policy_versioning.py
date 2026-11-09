"""
Policy Version Manager
Phase 3: Policy versioning with hot-reload via OPA bundle API

Features:
- Store named policy versions with metadata
- Activate a version (pushes to OPA via bundle API)
- Rollback to previous version
- Full version history with timestamps and author
- Diff between versions

This directly addresses the research question:
"How can PBAC policies be updated safely in a live MCP deployment?"
"""

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

import httpx
import structlog

log = structlog.get_logger()


@dataclass
class PolicyVersion:
    version_id: str           # v1, v2, v3 ...
    policy_text: str          # raw Rego content
    sha256: str               # integrity hash
    created_at: float
    created_by: str
    description: str
    is_active: bool = False
    activated_at: Optional[float] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["created_at_iso"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.created_at))
        d["activated_at_iso"] = (
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.activated_at))
            if self.activated_at else None
        )
        return d

    def summary(self) -> dict:
        """Lightweight summary without full policy text."""
        return {
            "version_id": self.version_id,
            "sha256": self.sha256[:16] + "...",
            "created_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.created_at)),
            "created_by": self.created_by,
            "description": self.description,
            "is_active": self.is_active,
            "lines": len(self.policy_text.splitlines()),
        }


class PolicyVersionManager:
    """
    Manages Rego policy versions and pushes active policy to OPA.
    Uses OPA's PUT /v1/policies/{id} endpoint for hot-reload.
    No OPA restart required when changing policy.
    """

    def __init__(self, opa_url: str, policy_dir: str = "/app/policies"):
        self.opa_url = opa_url.rstrip("/")
        self.policy_dir = Path(policy_dir)
        self.store_path = self.policy_dir / "version_store.json"
        self._versions: dict[str, PolicyVersion] = {}
        self._client = httpx.AsyncClient(timeout=10.0)
        self._load_store()

    def _load_store(self):
        """Load version history from disk."""
        if self.store_path.exists():
            try:
                data = json.loads(self.store_path.read_text())
                for vid, v in data.items():
                    pv = PolicyVersion(**{k: v[k] for k in PolicyVersion.__dataclass_fields__})
                    self._versions[vid] = pv
                log.info("policy_versions.loaded", count=len(self._versions))
            except Exception as e:
                log.error("policy_versions.load_failed", error=str(e))

    def _save_store(self):
        """Persist version history to disk."""
        self.policy_dir.mkdir(parents=True, exist_ok=True)
        data = {vid: asdict(v) for vid, v in self._versions.items()}
        self.store_path.write_text(json.dumps(data, indent=2))

    def _next_version_id(self) -> str:
        if not self._versions:
            return "v1"
        nums = []
        for vid in self._versions:
            try:
                nums.append(int(vid.lstrip("v")))
            except ValueError:
                pass
        return f"v{max(nums) + 1}" if nums else "v1"

    def _sha256(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    async def create_version(
        self,
        policy_text: str,
        description: str,
        created_by: str = "admin",
    ) -> PolicyVersion:
        """Store a new policy version without activating it."""
        version_id = self._next_version_id()
        sha = self._sha256(policy_text)

        # Validate Rego syntax via OPA parse endpoint before storing
        valid, parse_error = await self._validate_rego(policy_text)
        if not valid:
            raise ValueError(f"Rego syntax error: {parse_error}")

        version = PolicyVersion(
            version_id=version_id,
            policy_text=policy_text,
            sha256=sha,
            created_at=time.time(),
            created_by=created_by,
            description=description,
            is_active=False,
        )
        self._versions[version_id] = version
        self._save_store()

        log.info("policy_version.created", version_id=version_id, sha=sha[:16])
        return version

    async def activate_version(self, version_id: str) -> dict:
        """
        Activate a stored version:
        1. Validate syntax
        2. Push to OPA via PUT /v1/policies/mcp_gateway
        3. Mark as active in version store
        4. Deactivate previous version
        Returns activation result with timing.
        """
        if version_id not in self._versions:
            raise KeyError(f"Version {version_id} not found")

        version = self._versions[version_id]
        start = time.time()

        # Push to OPA (hot-reload, no restart)
        try:
            resp = await self._client.put(
                f"{self.opa_url}/v1/policies/mcp_gateway",
                content=version.policy_text,
                headers={"Content-Type": "text/plain"},
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            error_body = e.response.text
            raise RuntimeError(f"OPA rejected policy: {error_body}")
        except httpx.RequestError as e:
            raise RuntimeError(f"OPA unreachable: {e}")

        activation_ms = round((time.time() - start) * 1000, 2)

        # Update version store
        prev_active = self.get_active_version()
        for v in self._versions.values():
            v.is_active = False
        version.is_active = True
        version.activated_at = time.time()
        self._save_store()

        # Write active policy to disk (for OPA file mount fallback)
        active_path = self.policy_dir / "mcp_gateway.rego"
        active_path.write_text(version.policy_text)

        log.info(
            "policy_version.activated",
            version_id=version_id,
            prev=prev_active.version_id if prev_active else None,
            activation_ms=activation_ms,
        )

        return {
            "activated": version_id,
            "previous": prev_active.version_id if prev_active else None,
            "activation_ms": activation_ms,
            "sha256": version.sha256[:16] + "...",
        }

    async def rollback(self) -> dict:
        """Rollback to the previously active version."""
        history = self.list_versions()
        # Find last activated (not current)
        active = self.get_active_version()
        activated_versions = [
            v for v in self._versions.values()
            if v.activated_at and (not active or v.version_id != active.version_id)
        ]
        if not activated_versions:
            raise RuntimeError("No previous version to roll back to")

        # Most recently activated non-current version
        prev = sorted(activated_versions, key=lambda v: v.activated_at or 0, reverse=True)[0]
        return await self.activate_version(prev.version_id)

    def get_active_version(self) -> Optional[PolicyVersion]:
        for v in self._versions.values():
            if v.is_active:
                return v
        return None

    def get_version(self, version_id: str) -> Optional[PolicyVersion]:
        return self._versions.get(version_id)

    def list_versions(self) -> list[dict]:
        return [
            v.summary()
            for v in sorted(self._versions.values(), key=lambda x: x.created_at, reverse=True)
        ]

    def diff(self, version_id_a: str, version_id_b: str) -> dict:
        """Simple line-level diff between two versions."""
        a = self._versions.get(version_id_a)
        b = self._versions.get(version_id_b)
        if not a or not b:
            raise KeyError("One or both versions not found")

        lines_a = set(a.policy_text.splitlines())
        lines_b = set(b.policy_text.splitlines())

        return {
            "version_a": version_id_a,
            "version_b": version_id_b,
            "lines_added": sorted(lines_b - lines_a),
            "lines_removed": sorted(lines_a - lines_b),
            "lines_a": len(lines_a),
            "lines_b": len(lines_b),
        }

    async def _validate_rego(self, policy_text: str) -> tuple[bool, str]:
        """A5: Compile via OPA. Reject invalid Rego with the OPA error."""
        try:
            put_resp = await self._client.put(
                f"{self.opa_url}/v1/policies/__validate_temp__",
                content=policy_text.encode(),
                headers={"Content-Type": "text/plain"},
            )
            # OPA returns 200 on a syntactically/semantically valid module,
            # 400 with an error body otherwise.
            if put_resp.status_code == 200:
                await self._client.delete(f"{self.opa_url}/v1/policies/__validate_temp__")
                return True, ""
            # Invalid — surface the OPA error and clean up if needed
            try:
                err = put_resp.json()
                msg = err.get("message") or str(err)
            except Exception:
                msg = put_resp.text
            await self._client.delete(f"{self.opa_url}/v1/policies/__validate_temp__")
            return False, msg
        except Exception as e:
            # OPA unreachable → cannot validate → fail closed (reject)
            log.warning("policy_validation.opa_unreachable", error=str(e))
            return False, f"opa_unreachable: {e}"
