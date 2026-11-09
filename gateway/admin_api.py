"""
Admin API - Policy Management Endpoints
Phase 3: Policy versioning, activation, rollback

Endpoints (all require admin role):
  POST   /admin/policies              - upload new policy version
  GET    /admin/policies              - list all versions
  GET    /admin/policies/{version_id} - get specific version
  POST   /admin/policies/{version_id}/activate - activate a version
  POST   /admin/policies/rollback     - rollback to previous
  GET    /admin/policies/diff         - diff two versions
  GET    /admin/status                - gateway + OPA status
"""

import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .auth import TokenClaims, verify_token
from .policy_versioning import PolicyVersionManager

router = APIRouter(prefix="/admin", tags=["admin"])

# Injected by main.py on startup
_policy_manager: Optional[PolicyVersionManager] = None


def set_policy_manager(pm: PolicyVersionManager):
    global _policy_manager
    _policy_manager = pm


def get_pm() -> PolicyVersionManager:
    if _policy_manager is None:
        raise HTTPException(status_code=503, detail="Policy manager not initialized")
    return _policy_manager


def require_admin(claims: TokenClaims = Depends(verify_token)) -> TokenClaims:
    if claims.role != "admin":
        raise HTTPException(
            status_code=403,
            detail={"error": "admin_required", "message": "This endpoint requires admin role"},
        )
    return claims


# ─── Pydantic models ──────────────────────────────────────────────────────────

class CreatePolicyRequest(BaseModel):
    policy_text: str
    description: str
    activate_immediately: bool = False


class ActivateRequest(BaseModel):
    version_id: str


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/policies")
async def create_policy_version(
    body: CreatePolicyRequest,
    claims: TokenClaims = Depends(require_admin),
):
    """
    Upload a new Rego policy version.
    Validates syntax via OPA before storing.
    Optionally activates immediately.
    """
    pm = get_pm()
    try:
        version = await pm.create_version(
            policy_text=body.policy_text,
            description=body.description,
            created_by=claims.sub,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail={"error": "invalid_rego", "message": str(e)})

    result = {
        "created": version.summary(),
        "activated": None,
    }

    if body.activate_immediately:
        try:
            activation = await pm.activate_version(version.version_id)
            result["activated"] = activation
        except RuntimeError as e:
            raise HTTPException(status_code=502, detail={"error": "activation_failed", "message": str(e)})

    return JSONResponse(content=result, status_code=201)


@router.get("/policies")
async def list_policy_versions(
    claims: TokenClaims = Depends(require_admin),
):
    """List all stored policy versions with metadata."""
    pm = get_pm()
    versions = pm.list_versions()
    active = pm.get_active_version()
    return {
        "versions": versions,
        "total": len(versions),
        "active_version": active.version_id if active else None,
    }


@router.get("/policies/active")
async def get_active_policy(
    claims: TokenClaims = Depends(require_admin),
):
    """Get the currently active policy version with full text."""
    pm = get_pm()
    active = pm.get_active_version()
    if not active:
        raise HTTPException(status_code=404, detail="No active policy version found")
    return active.to_dict()


@router.get("/policies/diff")
async def diff_versions(
    version_a: str,
    version_b: str,
    claims: TokenClaims = Depends(require_admin),
):
    """Compare two policy versions line by line."""
    pm = get_pm()
    try:
        return pm.diff(version_a, version_b)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/policies/{version_id}")
async def get_policy_version(
    version_id: str,
    claims: TokenClaims = Depends(require_admin),
):
    """Get a specific policy version including full Rego text."""
    pm = get_pm()
    version = pm.get_version(version_id)
    if not version:
        raise HTTPException(status_code=404, detail=f"Version {version_id} not found")
    return version.to_dict()


@router.post("/policies/{version_id}/activate")
async def activate_policy_version(
    version_id: str,
    claims: TokenClaims = Depends(require_admin),
):
    """
    Activate a stored policy version.
    Hot-reloads OPA without restart.
    All subsequent requests evaluated against new policy immediately.
    """
    pm = get_pm()
    try:
        result = await pm.activate_version(version_id)
        return {
            "success": True,
            "result": result,
            "message": f"Policy {version_id} is now active. OPA hot-reloaded.",
        }
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Version {version_id} not found")
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail={"error": "activation_failed", "message": str(e)})


@router.post("/policies/rollback")
async def rollback_policy(
    claims: TokenClaims = Depends(require_admin),
):
    """
    Rollback to the previously active policy version.
    Used for emergency revert if a new policy causes issues.
    """
    pm = get_pm()
    try:
        result = await pm.rollback()
        return {
            "success": True,
            "result": result,
            "message": f"Rolled back to {result['activated']}",
        }
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail={"error": "rollback_failed", "message": str(e)})


@router.get("/status")
async def admin_status(
    claims: TokenClaims = Depends(require_admin),
):
    """Full gateway status for admin dashboard."""
    pm = get_pm()
    active = pm.get_active_version()
    versions = pm.list_versions()

    return {
        "gateway": "operational",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "policy": {
            "active_version": active.version_id if active else None,
            "total_versions": len(versions),
            "active_sha256": (active.sha256[:16] + "...") if active else None,
            "active_since": (
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(active.activated_at))
                if active and active.activated_at else None
            ),
        },
        "versions": versions,
    }
