"""Offline check: is any supplied token signed with a common, guessable secret?

No requests are sent. For each token, the HMAC signature is recomputed with
every secret in a small built-in list. This is the standard way to show that a
JWT signing secret is too weak, and it only ever runs against the tokens the
operator supplied for their own test accounts.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from importlib.resources import files
from typing import TYPE_CHECKING

from ..models import Finding

if TYPE_CHECKING:
    from . import CheckContext

HMAC_ALGORITHMS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def load_wordlist() -> list[str]:
    text = files("polarizer").joinpath("wordlist.txt").read_text(encoding="utf-8")
    secrets = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            secrets.append(line)
    return secrets


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _parse(token: str) -> tuple[str, bytes, bytes] | None:
    """Returns (algorithm, signing input, signature bytes) or None if not a JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_segment, payload_segment, signature_segment = parts
    try:
        header = json.loads(_b64url_decode(header_segment))
        signature = _b64url_decode(signature_segment)
    except (ValueError, binascii.Error):
        return None
    if not isinstance(header, dict):
        return None
    algorithm = header.get("alg", "")
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    return algorithm, signing_input, signature


def crack(token: str, secrets: list[str]) -> str | None:
    """Returns the secret that signs this token, if one is in the list."""
    parsed = _parse(token)
    if parsed is None:
        return None
    algorithm, signing_input, signature = parsed
    digest = HMAC_ALGORITHMS.get(algorithm)
    if digest is None:  # not an HMAC-signed token, so a wordlist cannot apply
        return None
    for secret in secrets:
        expected = hmac.new(secret.encode("utf-8"), signing_input, digest).digest()
        if hmac.compare_digest(expected, signature):
            return secret
    return None


def run(ctx: "CheckContext") -> None:
    secrets = load_wordlist()
    weak = {}
    for identity, token in ctx.config.tokens.items():
        found = crack(token, secrets)
        if found is not None:
            weak[identity] = found

    if not weak:
        return

    # One finding for the target, listing which identities were affected. The
    # secret itself is included because that is the actionable evidence.
    secret_value = next(iter(weak.values()))
    identities = ", ".join(sorted(weak))
    ctx.results.add(
        Finding(
            check="jwt-weak-secret",
            title="JWT tokens are signed with a guessable secret",
            severity="critical",
            owasp="API2:2023 Broken Authentication",
            endpoint="(token signing)",
            description=(
                f"Tokens for {identities} are signed with the secret {secret_value!r}, which is in "
                "a short list of common values. Anyone who guesses the secret can forge a token for "
                "any user and any role, so every other authorization check can be bypassed. This "
                "check ran offline against the supplied tokens and sent no requests."
            ),
            remediation=(
                "Sign tokens with a long, random secret kept out of source control (at least 32 "
                "random bytes), rotate the current secret, and reject tokens that do not verify."
            ),
            notes=["Offline check. No requests were sent to the target."],
        )
    )
