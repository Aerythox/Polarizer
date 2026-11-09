"""End-to-end scanner tests against the in-memory fake lab."""

from pathlib import Path

from polarizer.config import MassAssignmentTarget, ScanConfig
from polarizer.scan import exit_code, run_scan
from tests.fakelab import build_transport, make_token

SPEC = Path(__file__).resolve().parents[2] / "target-api" / "openapi.yaml"
STRONG_SECRET = "f3a9c0b2e8d7461f9a2c5b8e0d147a6c9b8e0d147a6c9b8e0d1"


def _config(secret: str) -> ScanConfig:
    return ScanConfig(
        base_url="http://127.0.0.1:3000",
        spec_path=SPEC,
        tokens={
            "user_a": make_token("a", "user", secret),
            "user_b": make_token("b", "user", secret),
            "admin": make_token("adm", "admin", secret),
        },
        resources={"number": {"user_a": "1001", "user_b": "1003"}},
        admin_only=["GET /admin/users", "GET /admin/stats"],
        mass_assignment=[MassAssignmentTarget("PATCH /profile/me", "GET /profile/me", "role", "admin")],
    )


def test_vulnerable_mode_is_fully_flagged():
    results = run_scan(
        _config("secret123"),
        allow_writes=True,
        transport=build_transport("vulnerable"),
    )
    checks = {f.check for f in results.findings}
    assert checks == {"jwt-weak-secret", "bola", "bfla", "mass-assignment"}
    assert exit_code(results) == 1


def test_bfla_flags_only_the_unprotected_admin_route():
    results = run_scan(
        _config("secret123"),
        allow_writes=True,
        transport=build_transport("vulnerable"),
    )
    bfla = [f for f in results.findings if f.check == "bfla"]
    assert [f.endpoint for f in bfla] == ["GET /admin/users"]  # /admin/stats is not flagged


def test_fixed_mode_is_clean():
    results = run_scan(
        _config(STRONG_SECRET),
        allow_writes=True,
        transport=build_transport("fixed"),
    )
    assert results.findings == []
    assert results.inconclusive == []
    assert exit_code(results) == 0


def test_mass_assignment_restores_the_value():
    transport = build_transport("vulnerable")
    run_scan(_config("secret123"), allow_writes=True, transport=transport)
    # A second run still finds the flaw, which proves the first run put role back.
    results = run_scan(_config("secret123"), allow_writes=True, transport=transport)
    assert any(f.check == "mass-assignment" for f in results.findings)


def test_writes_are_skipped_without_allow_writes():
    results = run_scan(
        _config("secret123"),
        allow_writes=False,
        transport=build_transport("vulnerable"),
    )
    assert not any(f.check == "mass-assignment" for f in results.findings)
    assert any("mass assignment" in note for note in results.skipped)
