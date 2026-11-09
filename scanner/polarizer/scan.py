"""Runs every check against one target and collects the results."""

from __future__ import annotations

from collections.abc import Iterable

import httpx

from .checks import ALL_CHECKS, CheckContext
from .client import ApiClient
from .config import ScanConfig
from .models import ScanResults
from .spec import load_operations


def run_scan(
    config: ScanConfig,
    *,
    allowed_hosts: Iterable[str] = (),
    rate: float = 5.0,
    allow_writes: bool = False,
    transport: httpx.BaseTransport | None = None,
) -> ScanResults:
    operations = load_operations(config.spec_path)
    results = ScanResults()

    client = ApiClient(
        config.base_url,
        config.tokens,
        allowed_hosts=allowed_hosts,
        rate=rate,
        transport=transport,
    )
    try:
        context = CheckContext(client, config, operations, results, allow_writes)
        for check in ALL_CHECKS:
            check.run(context)
    finally:
        client.close()

    results.requests_sent = client.requests_sent
    return results


def exit_code(results: ScanResults) -> int:
    """0 clean, 1 findings, 2 inconclusive. Findings take priority."""
    if results.findings:
        return 1
    if results.inconclusive:
        return 2
    return 0
