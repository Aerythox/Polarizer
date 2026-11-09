import pytest

from polarizer.config import ConfigError, load_config

CONFIG = """
target:
  base_url: http://127.0.0.1:3000
  spec: ./openapi.yaml
identities:
  user_a:
    token_env: TOK_A
  user_b:
    token_env: TOK_B
resources:
  number:
    user_a: 1001
    user_b: 1003
admin_only:
  - GET /admin/users
mass_assignment:
  - update: PATCH /profile/me
    read: GET /profile/me
    field: role
    value: admin
"""


def _write(tmp_path, text=CONFIG):
    path = tmp_path / "lab.yaml"
    path.write_text(text, encoding="utf-8")
    (tmp_path / "openapi.yaml").write_text("openapi: 3.0.3\npaths: {}\n", encoding="utf-8")
    return path


def test_loads_tokens_from_env(tmp_path):
    config = load_config(_write(tmp_path), env={"TOK_A": "aaa", "TOK_B": "bbb"})
    assert config.tokens == {"user_a": "aaa", "user_b": "bbb"}
    assert config.resources["number"]["user_a"] == "1001"
    assert config.admin_only == ["GET /admin/users"]
    assert config.mass_assignment[0].field == "role"


def test_spec_path_is_relative_to_the_config(tmp_path):
    config = load_config(_write(tmp_path), env={"TOK_A": "aaa", "TOK_B": "bbb"})
    assert config.spec_path == (tmp_path / "openapi.yaml").resolve()


def test_missing_token_is_an_error(tmp_path):
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path), env={"TOK_A": "aaa"})


def test_duplicate_tokens_are_rejected(tmp_path):
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path), env={"TOK_A": "same", "TOK_B": "same"})


def test_base_url_override(tmp_path):
    config = load_config(
        _write(tmp_path),
        env={"TOK_A": "aaa", "TOK_B": "bbb"},
        base_url="http://127.0.0.1:9999",
    )
    assert config.base_url == "http://127.0.0.1:9999"
