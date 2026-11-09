"""Broken object level authorization (BOLA).

For an endpoint that takes an object ID in the path, one user asks for an object
that a different user owns. If the response succeeds and matches what the owner
sees, the object was handed to someone who should not have it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..compare import looks_like_same_object
from ..models import Finding

if TYPE_CHECKING:
    from . import CheckContext


def run(ctx: "CheckContext") -> None:
    for op in ctx.operations:
        if op.method != "GET" or not op.path_params:
            continue

        # Identities that have a configured object for every path parameter.
        owners = [name for name in ctx.config.tokens if ctx.resolve_path(op, name) is not None]
        if len(owners) < 2:
            ctx.results.skip(f"{op.key}: needs objects for at least two identities to test BOLA.")
            continue

        for victim in owners:
            victim_path = ctx.resolve_path(op, victim)
            owner_reply = ctx.client.request(victim, op.method, victim_path)
            if not owner_reply.ok:
                ctx.results.mark_inconclusive(
                    f"{op.key}: {victim} could not read their own object ({owner_reply.status})."
                )
                continue

            for attacker in owners:
                if attacker == victim:
                    continue
                attacker_reply = ctx.client.request(attacker, op.method, victim_path)
                if not attacker_reply.ok:
                    continue
                if not looks_like_same_object(owner_reply.data, attacker_reply.data):
                    continue

                ctx.results.add(
                    Finding(
                        check="bola",
                        title="A user can read another user's object",
                        severity="high",
                        owasp="API1:2023 Broken Object Level Authorization",
                        endpoint=op.key,
                        detail=f"{attacker}->{victim}",
                        description=(
                            f"{attacker} requested {victim_path}, an object owned by {victim}, and "
                            f"received {attacker_reply.status} with the same data the owner sees. "
                            "The endpoint checks that the caller is logged in but not that the "
                            "object belongs to them."
                        ),
                        remediation=(
                            "Scope the lookup to the caller (for example match both the object ID "
                            "and the owner ID from the verified token), and return 404 when the "
                            "object is not theirs."
                        ),
                        evidence=[owner_reply.exchange, attacker_reply.exchange],
                    )
                )
