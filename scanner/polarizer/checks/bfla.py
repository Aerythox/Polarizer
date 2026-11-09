"""Broken function level authorization (BFLA).

A non-admin identity calls each route the config marks as admin-only. If the
call succeeds, the route is missing its role check. When an admin token is
available, the check first confirms the admin can use the route, so a route that
is simply broken for everyone is not reported as a privilege problem.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding

if TYPE_CHECKING:
    from . import CheckContext

NON_ADMIN = "user_a"


def run(ctx: "CheckContext") -> None:
    for key in ctx.config.admin_only:
        op = ctx.ops_by_key.get(key)
        if op is None:
            ctx.results.warn(f"admin_only lists {key!r}, which is not in the spec.")
            continue

        path = ctx.resolve_path(op, NON_ADMIN)
        if path is None and "admin" in ctx.config.tokens:
            path = ctx.resolve_path(op, "admin")
        if path is None:
            path = op.path if not op.path_params else None
        if path is None:
            ctx.results.skip(f"{key}: no object configured to build the path.")
            continue

        reply = ctx.client.request(NON_ADMIN, op.method, path)
        if not reply.ok:
            continue

        if "admin" in ctx.config.tokens:
            admin_reply = ctx.client.request("admin", op.method, path)
            if not admin_reply.ok:
                ctx.results.mark_inconclusive(
                    f"{key}: {NON_ADMIN} got {reply.status} but admin got {admin_reply.status}, "
                    "so this may be open to everyone rather than an admin-only route."
                )
                continue

        ctx.results.add(
            Finding(
                check="bfla",
                title="An admin-only route has no role check",
                severity="high",
                owasp="API5:2023 Broken Function Level Authorization",
                endpoint=op.key,
                description=(
                    f"{NON_ADMIN}, a non-admin user, called {op.key} and received {reply.status}. "
                    "The route is meant for admins only but does not check the caller's role."
                ),
                remediation="Require the admin role on this route and return 403 otherwise.",
                evidence=[reply.exchange],
            )
        )
