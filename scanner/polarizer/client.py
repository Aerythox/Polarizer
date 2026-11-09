"""HTTP client with a rate limit, a host check on every request, no redirects,
and evidence records that never include tokens."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from . import __version__
from .guard import ensure_allowed
from .models import Exchange

ANONYMOUS = "anonymous"
EXCERPT_LIMIT = 400
MAX_RATE = 20.0


class RateLimiter:
    """Keeps at least 1 / per_second seconds between requests."""

    def __init__(
        self,
        per_second: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not 0 < per_second <= MAX_RATE:
            raise ValueError(f"Rate must be above 0 and at most {MAX_RATE:g} requests per second.")
        self._interval = 1.0 / per_second
        self._clock = clock
        self._sleep = sleep
        self._next: float | None = None

    def wait(self) -> None:
        now = self._clock()
        if self._next is not None and now < self._next:
            self._sleep(self._next - now)
            now = self._next
        self._next = now + self._interval


@dataclass
class Reply:
    status: int | None
    data: Any
    exchange: Exchange

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300


class ApiClient:
    def __init__(
        self,
        base_url: str,
        tokens: dict[str, str],
        allowed_hosts: Iterable[str] = (),
        rate: float = 5.0,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._allowed = tuple(allowed_hosts)
        ensure_allowed(base_url, self._allowed)
        self._tokens = dict(tokens)
        self._limiter = RateLimiter(rate)
        self._http = httpx.Client(
            base_url=base_url,
            follow_redirects=False,
            timeout=timeout,
            transport=transport,
            headers={"User-Agent": f"polarizer/{__version__}"},
        )
        self.requests_sent = 0

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "ApiClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def request(self, identity: str, method: str, path: str, json: dict | None = None) -> Reply:
        headers = {}
        if identity != ANONYMOUS:
            headers["Authorization"] = f"Bearer {self._tokens[identity]}"

        request = self._http.build_request(method, path, json=json, headers=headers)
        # Checked again on the final URL, not just the base URL at start-up.
        ensure_allowed(str(request.url), self._allowed)

        self._limiter.wait()
        self.requests_sent += 1
        try:
            response = self._http.send(request)
        except httpx.HTTPError as exc:
            failure = f"request failed: {type(exc).__name__}"
            return Reply(None, None, Exchange(identity, method, path, None, failure, json))

        try:
            data = response.json()
        except ValueError:
            data = None
        excerpt = response.text[:EXCERPT_LIMIT]
        exchange = Exchange(identity, method, path, response.status_code, excerpt, json)
        return Reply(response.status_code, data, exchange)


def fill_path(template: str, values: dict[str, str]) -> str:
    path = template
    for name, value in values.items():
        path = path.replace("{" + name + "}", quote(str(value), safe=""))
    return path
