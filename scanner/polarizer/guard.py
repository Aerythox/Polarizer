"""Decides which hosts Polarizer may send requests to.

Only loopback addresses are allowed by default. Any other host must be named
explicitly with --allow-host, which is the user stating that they own the
system or are authorized to test it.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from urllib.parse import urlsplit


class HostNotAllowed(Exception):
    pass


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def ensure_allowed(url: str, allowed_hosts: Iterable[str]) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise HostNotAllowed(f"Refusing {url!r}: only http and https URLs are supported.")

    # hostname already drops any user:password@ part, so a URL like
    # http://127.0.0.1@example.com is correctly treated as example.com.
    host = (parts.hostname or "").lower()
    if not host:
        raise HostNotAllowed(f"Refusing {url!r}: the URL has no host.")

    if is_loopback(host) or host in {h.lower() for h in allowed_hosts}:
        return

    raise HostNotAllowed(
        f"Refusing to send requests to {host}. Only localhost is allowed by default. "
        f"If you own {host} or are authorized to test it, pass --allow-host {host}."
    )
