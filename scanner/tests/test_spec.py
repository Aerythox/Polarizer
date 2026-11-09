from pathlib import Path

import pytest

from polarizer.spec import SpecError, load_operations

SPEC = Path(__file__).resolve().parents[2] / "target-api" / "openapi.yaml"


def _by_key(operations):
    return {op.key: op for op in operations}


def test_loads_the_lab_spec():
    ops = _by_key(load_operations(SPEC))
    assert "GET /invoices/{number}" in ops
    assert "PATCH /profile/me" in ops


def test_public_routes_do_not_require_auth():
    ops = _by_key(load_operations(SPEC))
    assert ops["POST /auth/login"].requires_auth is False
    assert ops["GET /invoices/{number}"].requires_auth is True


def test_path_params_and_response_fields_are_read():
    ops = _by_key(load_operations(SPEC))
    assert ops["GET /invoices/{number}"].path_params == ["number"]
    # The Invoice schema is behind a $ref that must be resolved.
    assert "customer" in ops["GET /invoices/{number}"].response_fields


def test_request_fields_are_read():
    ops = _by_key(load_operations(SPEC))
    assert set(ops["PATCH /profile/me"].request_fields) == {"name", "email"}


def test_a_non_openapi_file_is_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("hello: world", encoding="utf-8")
    with pytest.raises(SpecError):
        load_operations(bad)
