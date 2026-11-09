"""Mass assignment / broken object property level authorization.

A user sends a privileged field (such as role) on an update that should not
accept it, then reads the value back. If it changed, the server let the user set
a field they should not control. This check writes, so it runs only with
--allow-writes, and it restores the original value afterwards.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding

if TYPE_CHECKING:
    from . import CheckContext

ACTOR = "user_a"


def run(ctx: "CheckContext") -> None:
    if not ctx.config.mass_assignment:
        return
    if not ctx.allow_writes:
        ctx.results.skip("mass assignment: skipped because --allow-writes was not set.")
        return

    for target in ctx.config.mass_assignment:
        update_op = ctx.ops_by_key.get(target.update)
        read_op = ctx.ops_by_key.get(target.read)
        if update_op is None or read_op is None:
            ctx.results.warn(
                f"mass_assignment refers to {target.update!r} or {target.read!r}, "
                "which is not in the spec."
            )
            continue

        read_path = ctx.resolve_path(read_op, ACTOR) or read_op.path
        update_path = ctx.resolve_path(update_op, ACTOR) or update_op.path

        before = ctx.client.request(ACTOR, read_op.method, read_path)
        if not before.ok or not isinstance(before.data, dict):
            ctx.results.mark_inconclusive(
                f"{target.update}: could not read {target.field} before testing ({before.status})."
            )
            continue
        original = before.data.get(target.field)
        if original == target.value:
            ctx.results.mark_inconclusive(
                f"{target.update}: {ACTOR} already has {target.field}={target.value!r}, "
                "so the test would be meaningless."
            )
            continue

        attempt = ctx.client.request(ACTOR, update_op.method, update_path, json={target.field: target.value})
        after = ctx.client.request(ACTOR, read_op.method, read_path)
        changed = isinstance(after.data, dict) and after.data.get(target.field) == target.value

        if changed:
            ctx.results.add(
                Finding(
                    check="mass-assignment",
                    title="A user can set a field they should not control",
                    severity="high",
                    owasp="API3:2023 Broken Object Property Level Authorization",
                    endpoint=update_op.key,
                    detail=target.field,
                    description=(
                        f"{ACTOR} sent {target.field}={target.value!r} to {update_op.key}. Reading "
                        f"the profile back showed {target.field} had changed to {target.value!r}. "
                        "The update accepts fields the user is not allowed to set."
                    ),
                    remediation=(
                        "Accept only an allowlist of editable fields on this route and ignore the "
                        f"rest, so {target.field} and similar fields cannot be set by the client."
                    ),
                    evidence=[attempt.exchange, after.exchange],
                )
            )
            # Put the value back so the account is left as it started.
            restore = ctx.client.request(ACTOR, update_op.method, update_path, json={target.field: original})
            check = ctx.client.request(ACTOR, read_op.method, read_path)
            if not restore.ok or (isinstance(check.data, dict) and check.data.get(target.field) == target.value):
                ctx.results.warn(
                    f"{target.update}: could not restore {target.field} to {original!r}. "
                    "Reset the test account manually."
                )
