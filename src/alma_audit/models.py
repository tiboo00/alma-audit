"""Dataclasses + enums shared across analyzers and the reporting layer.

Severity uses three tiers (INFO / WARN / CRITICAL). A Finding carries a
module name (analyzer), structured details (a dict that can be JSON-
serialized) and an optional remediation hint. AuditReport is the top-level
artifact the CLI writes to disk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    INFO = "INFO"
    WARN = "WARN"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    module: str
    severity: Severity
    title: str
    description: str
    details: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "details": self.details,
            "recommendation": self.recommendation,
        }


@dataclass
class AuditReport:
    timestamp: str
    hostname: str
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
        }
