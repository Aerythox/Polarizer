import pytest

from polarizer.guard import HostNotAllowed, ensure_allowed, is_loopback


def test_loopback_hosts_are_allowed():
    for url in ["http://127.0.0.1:3000", "http://localhost:8080/x", "http://[::1]:3000"]:
        ensure_allowed(url, [])


def test_non_local_host_is_refused():
    with pytest.raises(HostNotAllowed):
        ensure_allowed("http://example.com/api", [])


def test_allowlist_permits_a_named_host():
    ensure_allowed("https://staging.internal/api", ["staging.internal"])


def test_userinfo_cannot_disguise_the_real_host():
    # The real host here is example.com, not 127.0.0.1.
    with pytest.raises(HostNotAllowed):
        ensure_allowed("http://127.0.0.1@example.com/api", [])


def test_non_http_scheme_is_refused():
    with pytest.raises(HostNotAllowed):
        ensure_allowed("ftp://127.0.0.1/x", [])


def test_is_loopback():
    assert is_loopback("127.0.0.1")
    assert is_loopback("localhost")
    assert not is_loopback("10.0.0.1")
    assert not is_loopback("example.com")
