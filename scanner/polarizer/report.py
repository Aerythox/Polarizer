"""Turns scan results into Markdown and JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from . import __version__
from .config import ScanConfig
from .models import Exchange, ScanResults

SEVERITY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _exchange_line(exchange: Exchange) -> str:
    status = exchange.status if exchange.status is not None else "no response"
    line = f"`{exchange.identity}` {exchange.method} {exchange.path} -> {status}"
    if exchange.request_body:
        line += f" (body: {json.dumps(exchange.request_body)})"
    return line


def render_markdown(results: ScanResults, config: ScanConfig, *, generated_at: str | None = None) -> str:
    findings = results.sorted_findings()
    lines = [
        "# Polarizer authorization scan",
        "",
        f"- Target: {config.base_url}",
        f"- Generated: {generated_at or _now()}",
        f"- Requests sent: {results.requests_sent}",
        f"- Findings: {len(findings)}",
        "",
    ]

    if findings:
        lines += ["## Summary", "", "| Severity | Finding | Endpoint | OWASP |", "| --- | --- | --- | --- |"]
        for f in findings:
            lines.append(
                f"| {SEVERITY_LABEL.get(f.severity, f.severity)} | {f.title} | {f.endpoint} | {f.owasp} |"
            )
        lines.append("")

        lines += ["## Findings", ""]
        for index, f in enumerate(findings, start=1):
            lines += [
                f"### {index}. {f.title}",
                "",
                f"- Severity: {SEVERITY_LABEL.get(f.severity, f.severity)}",
                f"- Endpoint: {f.endpoint}",
                f"- OWASP: {f.owasp}",
                f"- Finding ID: `{f.id}`",
                "",
                f.description,
                "",
            ]
            if f.evidence:
                lines.append("Evidence:")
                lines.append("")
                for exchange in f.evidence:
                    lines.append(f"- {_exchange_line(exchange)}")
                lines.append("")
            lines += ["Remediation:", "", f.remediation, ""]
            for note in f.notes:
                lines.append(f"> {note}")
            if f.notes:
                lines.append("")
    else:
        lines += ["No authorization findings.", ""]

    lines += _section("Inconclusive", results.inconclusive)
    lines += _section("Skipped", results.skipped)
    lines += _section("Warnings", results.warnings)
    return "\n".join(lines).rstrip() + "\n"


def _section(title: str, items: list[str]) -> list[str]:
    if not items:
        return []
    lines = [f"## {title}", ""]
    lines += [f"- {item}" for item in items]
    lines.append("")
    return lines


def render_json(results: ScanResults, config: ScanConfig, *, generated_at: str | None = None) -> str:
    findings = results.sorted_findings()
    payload = {
        "tool": "polarizer",
        "version": __version__,
        "target": config.base_url,
        "generated_at": generated_at or _now(),
        "requests_sent": results.requests_sent,
        "summary": {
            "findings": len(findings),
            "inconclusive": len(results.inconclusive),
            "skipped": len(results.skipped),
            "warnings": len(results.warnings),
        },
        "findings": [f.to_dict() for f in findings],
        "inconclusive": results.inconclusive,
        "skipped": results.skipped,
        "warnings": results.warnings,
    }
    return json.dumps(payload, indent=2) + "\n"
