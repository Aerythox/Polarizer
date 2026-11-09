"""Checks whether an endpoint that should need a token can be reached without one.

Only safe methods (GET, HEAD) are tried, so this never creates or changes data.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..client import ANONYMOUS
from ..models import Finding

if TYPE_CHECKING:
    from . import CheckContext

SAFE_METHODS = {"GET", "HEAD"}


def run(ctx: "CheckContext") -> None:
    for op in ctx.operations:
        if op.method not in SAFE_METHODS or not op.requires_auth:
            continue

        # Build the path from user_a's resources where parameters are needed.
        path = ctx.resolve_path(op, "user_a")
        if path is None:
            continue

        reply = ctx.client.request(ANONYMOUS, op.method, path)
        if not reply.ok:
            continue

        ctx.results.add(
            Finding(
                check="missing-authentication",
                title="Endpoint is reachable without a token",
                severity="high",
                owasp="API2:2023 Broken Authentication",
                endpoint=op.key,
                description=(
                    f"The spec marks {op.key} as requiring authentication, but a request with no "
                    f"token returned {reply.status}. Anyone on the network can call it."
                ),
                remediation="Require and verify a valid token on this route before returning data.",
                evidence=[reply.exchange],
            )
        )
