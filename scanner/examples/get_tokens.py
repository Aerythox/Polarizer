"""Logs in the invoice lab's test users and prints the tokens as shell variables.

Usage:
    python examples/get_tokens.py            # bash / zsh export lines
    python examples/get_tokens.py --powershell

The lab must be running on http://127.0.0.1:3000. These are fake accounts.
"""

from __future__ import annotations

import argparse
import sys

import httpx

BASE_URL = "http://127.0.0.1:3000"
USERS = {
    "POLARIZER_TOKEN_A": ("alice@example.test", "alice-lab-password"),
    "POLARIZER_TOKEN_B": ("bob@example.test", "bob-lab-password"),
    "POLARIZER_TOKEN_ADMIN": ("admin@example.test", "admin-lab-password"),
}


def login(client: httpx.Client, email: str, password: str) -> str:
    response = client.post("/auth/login", json={"email": email, "password": password})
    response.raise_for_status()
    return response.json()["token"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=BASE_URL)
    parser.add_argument("--powershell", action="store_true", help="Print PowerShell lines instead of bash.")
    args = parser.parse_args()

    try:
        with httpx.Client(base_url=args.base_url, timeout=10.0) as client:
            tokens = {name: login(client, email, password) for name, (email, password) in USERS.items()}
    except httpx.HTTPError as exc:
        print(f"Could not reach the lab at {args.base_url}: {exc}", file=sys.stderr)
        print("Start it with: docker compose up --build", file=sys.stderr)
        return 1

    for name, token in tokens.items():
        if args.powershell:
            print(f'$env:{name} = "{token}"')
        else:
            print(f"export {name}='{token}'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
