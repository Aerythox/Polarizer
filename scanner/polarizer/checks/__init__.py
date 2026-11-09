"""The individual checks, and the shared context they run with."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..client import ApiClient, fill_path
from ..config import ScanConfig
from ..models import ScanResults
from ..spec import Operation


@dataclass
class CheckContext:
    client: ApiClient
    config: ScanConfig
    operations: list[Operation]
    results: ScanResults
    allow_writes: bool
    ops_by_key: dict[str, Operation] = field(init=False)

    def __post_init__(self) -> None:
        self.ops_by_key = {op.key: op for op in self.operations}

    def resolve_path(self, op: Operation, identity: str) -> str | None:
        """Fills the path with IDs that identity owns, or returns None."""
        values = {}
        for name in op.path_params:
            owned = self.config.resources.get(name, {})
            if identity not in owned:
                return None
            values[name] = owned[identity]
        return fill_path(op.path, values)

    def path_for(self, op: Operation, identity: str) -> str | None:
        """Like resolve_path, but records a skip when a value is missing."""
        path = self.resolve_path(op, identity)
        if path is None:
            missing = [n for n in op.path_params if identity not in self.config.resources.get(n, {})]
            self.results.skip(f"{op.key}: no {missing} value configured for {identity}.")
        return path


# Imported last because each check module refers back to CheckContext.
from . import bfla, bola, jwt_secret, mass_assignment, unauthenticated  # noqa: E402

# Read-only checks first. Mass assignment changes data, so it runs last.
ALL_CHECKS = (jwt_secret, unauthenticated, bola, bfla, mass_assignment)
