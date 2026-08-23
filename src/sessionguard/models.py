"""Shared data structures used by every check and command."""
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    check: str
    severity: Severity
    message: str
    passed: bool = False


@dataclass
class ScanResult:
    target: str
    findings: list = field(default_factory=list)

    def add(self, check: str, severity: Severity, message: str, passed: bool) -> None:
        self.findings.append(Finding(check, severity, message, passed))

    @property
    def failed(self) -> list:
        return [f for f in self.findings if not f.passed]
