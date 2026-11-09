"""Loads and checks a Polarizer config file. Tokens come from environment
variables, never from the file itself."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import yaml

KNOWN_IDENTITIES = ("user_a", "user_b", "admin")
REQUIRED_IDENTITIES = ("user_a", "user_b")


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class MassAssignmentTarget:
    update: str  # operation key, e.g. "PATCH /profile/me"
    read: str  # operation key used to read the value back
    field: str  # the field a user should not be able to set, e.g. "role"
    value: str  # the privileged value to attempt, e.g. "admin"


@dataclass
class ScanConfig:
    base_url: str
    spec_path: Path
    tokens: dict[str, str]
    # Path parameter name -> identity -> the ID of an object that identity owns.
    resources: dict[str, dict[str, str]] = field(default_factory=dict)
    admin_only: list[str] = field(default_factory=list)
    mass_assignment: list[MassAssignmentTarget] = field(default_factory=list)


def load_config(
    path: str | Path,
    env: Mapping[str, str] = os.environ,
    base_url: str | None = None,
    spec: str | None = None,
) -> ScanConfig:
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"Could not read the config at {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} must contain a YAML mapping.")

    target = raw.get("target") or {}
    base_url = base_url or target.get("base_url")
    if not base_url:
        raise ConfigError("Set target.base_url in the config, or pass --base-url.")

    if spec:
        spec_path = Path(spec)
    elif target.get("spec"):
        # Relative spec paths in the file are relative to the config file.
        spec_path = (path.parent / target["spec"]).resolve()
    else:
        raise ConfigError("Set target.spec in the config, or pass --spec.")

    return ScanConfig(
        base_url=str(base_url).rstrip("/"),
        spec_path=spec_path,
        tokens=_load_tokens(raw.get("identities") or {}, env),
        resources=_load_resources(raw.get("resources") or {}),
        admin_only=_load_admin_only(raw.get("admin_only") or []),
        mass_assignment=_load_mass_assignment(raw.get("mass_assignment") or []),
    )


def _load_tokens(identities: dict, env: Mapping[str, str]) -> dict[str, str]:
    unknown = set(identities) - set(KNOWN_IDENTITIES)
    if unknown:
        raise ConfigError(f"Unknown identities {sorted(unknown)}. Use {list(KNOWN_IDENTITIES)}.")
    missing = [name for name in REQUIRED_IDENTITIES if name not in identities]
    if missing:
        raise ConfigError(f"The config must define identities {missing}.")

    tokens = {}
    for name, entry in identities.items():
        env_name = (entry or {}).get("token_env")
        if not env_name:
            raise ConfigError(f"Identity {name} needs a token_env setting.")
        token = env.get(env_name, "").strip()
        if not token:
            raise ConfigError(f"Set the environment variable {env_name} to the token for {name}.")
        tokens[name] = token

    # Identical tokens would make every cross-user check look like a leak.
    if len(set(tokens.values())) != len(tokens):
        raise ConfigError("Each identity needs its own token, but two of them are the same.")
    return tokens


def _load_resources(resources: dict) -> dict[str, dict[str, str]]:
    loaded = {}
    for param, owners in resources.items():
        if not isinstance(owners, dict):
            raise ConfigError(f"resources.{param} must map identities to IDs.")
        loaded[str(param)] = {str(identity): str(value) for identity, value in owners.items()}
    return loaded


def _load_admin_only(entries: list) -> list[str]:
    loaded = []
    for entry in entries:
        loaded.append(_operation_key(entry, "admin_only"))
    return loaded


def _load_mass_assignment(entries: list) -> list[MassAssignmentTarget]:
    loaded = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ConfigError("Each mass_assignment entry must be a mapping.")
        try:
            loaded.append(
                MassAssignmentTarget(
                    update=_operation_key(entry["update"], "mass_assignment.update"),
                    read=_operation_key(entry["read"], "mass_assignment.read"),
                    field=str(entry["field"]),
                    value=str(entry["value"]),
                )
            )
        except KeyError as exc:
            raise ConfigError(f"A mass_assignment entry is missing {exc}.") from exc
    return loaded


def _operation_key(entry: object, where: str) -> str:
    method, _, route = str(entry).strip().partition(" ")
    if not route.startswith("/"):
        raise ConfigError(f"{where} entry {entry!r} must look like 'GET /admin/users'.")
    return f"{method.upper()} {route.strip()}"
