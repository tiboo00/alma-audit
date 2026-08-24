"""Dataclasses + enums shared across analyzers and the reporting layer.

Severity uses three tiers (INFO / WARN / CRITICAL). A Finding carries a
module name (analyzer), structured details (a dict that can be JSON-
serialized), an optional remediation hint, and a tuple of structured
fix suggestions (AISO-210) that the rendering layer groups by scope
+ risk.

AuditReport is the top-level artifact the CLI writes to disk.

The `fixes` field is optional and defaults to an empty tuple so every
constructor that pre-dates AISO-210 still works unchanged. The dataclass
holds opaque Python objects; type info is only consulted when serialising.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    INFO = "INFO"
    WARN = "WARN"
    CRITICAL = "CRITICAL"


# Scope constants for structured fix suggestions (AISO-210). Mirrored
# in fix_suggestions.py; kept here so models can reference the value
# strings without importing the full library at dataclass-build time.
FIX_SCOPE_LOCAL_CONFIG = "local_config"
FIX_SCOPE_APP_CONFIG = "app_config"
FIX_SCOPE_DNS_BLOCK = "dns_block"
FIX_SCOPE_WAF = "waf"
FIX_SCOPE_KERNEL_PARAM = "kernel_param"


@dataclass
class Finding:
    module: str
    severity: Severity
    title: str
    description: str
    details: dict = field(default_factory=dict)
    recommendation: str = ""
    # AISO-210: structured fix-suggestion layer. The field is opaque
    # at the models layer; rendering + consolidation lives in
    # ``fix_suggestions.py``. Type hint is left simple (untyped tuple)
    # to keep the dataclass field-discovery robust across Python
    # versions (PEP 649 + PEP 563 strings).
    fixes: tuple = ()

    def to_dict(self) -> dict:
        out: dict = {
            "module": self.module,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "details": self.details,
            "recommendation": self.recommendation,
        }
        # Only serialise fixes when the field was touched AND each
        # entry has the structured shape we expect. Older tests that
        # bypass fix_suggestions and pass plain tuples of strings
        # stay green via the getattr + isinstance guard.
        if self.fixes:
            payload: list = []
            for entry in self.fixes:
                to_dict = getattr(entry, "to_dict", None)
                if callable(to_dict):
                    result = to_dict()
                    if isinstance(result, dict):
                        payload.append(result)
                elif isinstance(entry, dict):
                    payload.append(entry)
            if payload:
                out["fixes"] = payload
        return out


@dataclass
class AuditReport:
    timestamp: str
    hostname: str
    findings: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
        }
