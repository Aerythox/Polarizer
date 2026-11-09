"""Data shared by the checks and the reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = ("critical", "high", "medium", "low")


@dataclass
class Exchange:
    """One request and its response, kept as evidence. Never holds a token."""

    identity: str
    method: str
    path: str
    status: int | None
    body_excerpt: str
    request_body: dict | None = None


@dataclass
class Finding:
    check: str
    title: str
    severity: str
    owasp: str
    endpoint: str
    description: str
    remediation: str
    evidence: list[Exchange] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    detail: str = ""

    @property
    def id(self) -> str:
        parts = [self.check, self.endpoint]
        if self.detail:
            parts.append(self.detail)
        return ":".join(parts)

    def to_dict(self) -> dict:
        return {"id": self.id, **asdict(self)}


@dataclass
class ScanResults:
    findings: list[Finding] = field(default_factory=list)
    inconclusive: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    requests_sent: int = 0

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def mark_inconclusive(self, message: str) -> None:
        if message not in self.inconclusive:
            self.inconclusive.append(message)

    def skip(self, message: str) -> None:
        if message not in self.skipped:
            self.skipped.append(message)

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (SEVERITY_ORDER.index(f.severity), f.id))
