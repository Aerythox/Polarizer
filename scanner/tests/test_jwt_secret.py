from polarizer.checks.jwt_secret import crack, load_wordlist
from tests.fakelab import make_token


def test_wordlist_loads_and_includes_the_lab_secret():
    secrets = load_wordlist()
    assert "secret123" in secrets
    assert all(not s.startswith("#") for s in secrets)


def test_crack_finds_a_weak_secret():
    token = make_token("a", "user", secret="secret123")
    assert crack(token, load_wordlist()) == "secret123"


def test_crack_misses_a_strong_secret():
    token = make_token("a", "user", secret="f3a9c0b2e8d7461f9a2c5b8e0d147a6c")
    assert crack(token, load_wordlist()) is None


def test_crack_ignores_a_non_jwt_string():
    assert crack("not-a-jwt", load_wordlist()) is None
