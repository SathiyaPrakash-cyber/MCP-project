#!/usr/bin/env python3
"""
Utility: generate JWT tokens for testing the MCP Gateway.
Usage: python scripts/gen_token.py --role developer --user dev001
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gateway.auth import generate_test_token, VALID_ROLES


def main():
    parser = argparse.ArgumentParser(description="Generate MCP Gateway test tokens")
    parser.add_argument("--role", default="developer", choices=list(VALID_ROLES))
    parser.add_argument("--user", default=None)
    parser.add_argument("--email", default=None)
    parser.add_argument("--ttl", type=int, default=3600, help="TTL in seconds")
    args = parser.parse_args()

    user_id = args.user or f"test_{args.role}_001"
    email = args.email or f"{user_id}@test.local"

    token = generate_test_token(
        user_id=user_id,
        role=args.role,
        email=email,
        ttl_seconds=args.ttl,
    )

    print(f"\nRole:    {args.role}")
    print(f"User:    {user_id}")
    print(f"TTL:     {args.ttl}s")
    print(f"\nToken:\n{token}\n")
    print(f"Use with:")
    print(f'  curl -H "Authorization: Bearer {token[:40]}..." http://localhost:8080/mcp/v1/tools/call')


if __name__ == "__main__":
    main()
