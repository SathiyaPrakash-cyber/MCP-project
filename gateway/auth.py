"""
Authentication middleware for MCP Gateway.
Verifies JWT tokens and extracts identity claims used for RBAC + ABAC.
"""

import os
import time
from dataclasses import dataclass, field
from typing import Optional

import jwt
import structlog
log = structlog.get_logger()
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

security_scheme = HTTPBearer(auto_error=False)

# Read from env at module load
JWT_SECRET = os.getenv("JWT_SECRET", "")

# Fail-fast: refuse insecure/default/empty secrets (A2).
#
# Every value that has ever appeared in this repository's compose file,
# documentation or test scripts is listed here. A secret published alongside
# the code is not a secret, so the gateway refuses to sign or verify with one
# unless MCP_GATEWAY_LAB_MODE is explicitly set, which is how the local
# experimental stack acknowledges that it is not a real deployment.
_KNOWN_DEFAULTS = {
    "",
    "change-this-in-production-use-strong-secret-min-32chars",
    "mcp-gateway-dev-secret-change-in-prod-min32",
    "replace-me-with-a-random-48-character-value",
    "secret",
    "changeme",
}

_LAB_MODE = os.getenv("MCP_GATEWAY_LAB_MODE", "0") == "1"


def _assert_secret_ok():
    if len(JWT_SECRET) < 32:
        raise RuntimeError(
            "JWT_SECRET is unset or shorter than 32 characters. "
            "Run ./scripts/bootstrap_env.sh to generate one."
        )
    if JWT_SECRET in _KNOWN_DEFAULTS:
        if not _LAB_MODE:
            raise RuntimeError(
                "JWT_SECRET is a value published in this repository and cannot "
                "be used. Run ./scripts/bootstrap_env.sh to generate a random "
                "secret, or set MCP_GATEWAY_LAB_MODE=1 if this is the isolated "
                "experimental stack."
            )
        log.warning(
            "auth.insecure_secret_permitted_in_lab_mode",
            detail=(
                "JWT_SECRET is a publicly known development value. This is "
                "permitted only because MCP_GATEWAY_LAB_MODE=1. Any token "
                "issued by this gateway can be forged by anyone with the "
                "repository."
            ),
        )
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")


@dataclass
class TokenClaims:
    """
    Decoded JWT claims.
    sub    = user ID
    role   = primary RBAC role (admin | analyst | developer | read_only)
    groups = optional list of secondary groups (ABAC)
    email  = user email
    raw_token = original token string (forwarded to upstream)
    """
    sub: str
    role: str
    groups: list[str]
    email: str
    exp: int
    raw_token: str = ""


# Supported roles and their base permissions (used in policy engine too)
VALID_ROLES = {
    "admin",
    "security_analyst",
    "developer",
    "read_only",
    "agent",          # for LLM agents calling tools
}


async def verify_token(
    credentials: HTTPAuthorizationCredentials = Security(security_scheme),
) -> TokenClaims:
    """
    FastAPI dependency.
    Extracts and validates Bearer JWT token.
    Returns TokenClaims for use in policy evaluation.
    """
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail={"error": "missing_token", "message": "Authorization header required"},
        )
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"verify_exp": True},
        )
    except jwt.ExpiredSignatureError:
        log.warning("auth.token_expired", sub="unknown")
        raise HTTPException(
            status_code=401,
            detail={"error": "token_expired", "message": "JWT token has expired"},
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_token", "message": str(e)},
        )

    sub = payload.get("sub")
    role = payload.get("role", "read_only")
    groups = payload.get("groups", [])
    email = payload.get("email", "")
    exp = payload.get("exp", 0)

    if not sub:
        raise HTTPException(
            status_code=401,
            detail={"error": "missing_sub", "message": "Token missing 'sub' claim"},
        )

    if role not in VALID_ROLES:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "invalid_role",
                "message": f"Role '{role}' is not recognized",
            },
        )

    return TokenClaims(
        sub=sub,
        role=role,
        groups=groups if isinstance(groups, list) else [groups],
        email=email,
        exp=exp,
        raw_token=token,
    )


def generate_test_token(
    user_id: str,
    role: str,
    groups: list[str] | None = None,
    email: str = "",
    ttl_seconds: int = 3600,
) -> str:
    """
    Utility: generate a JWT for testing.
    NOT for production use.
    """
    if groups is None:
        groups = []

    payload = {
        "sub": user_id,
        "role": role,
        "groups": groups,
        "email": email,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl_seconds,
        "iss": "mcp-gateway-test",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
