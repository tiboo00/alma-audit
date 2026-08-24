"""Streaming aggregator for the ssl_cert analyzer.

Holds O(unique-certs) state. The detection rules in `rules.py` read
this state to emit findings. The aggregator is intentionally thin —
cert parsing already happens once per file in `parser.py` — but the
class exists so future rules (per-CA rollups, SAN coverage, signature
algorithm enumeration) have a place to grow without refactoring the
rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .parser import CertInfo


@dataclass
class CertAggregator:
    """Streaming aggregator. Call `add(cert)` per parsed cert, then `finalize()`."""

    certs: list[CertInfo] = field(default_factory=list)
    parsed_files: int = 0
    malformed_files: int = 0
    skipped_non_pem: int = 0

    def add(self, cert: CertInfo) -> None:
        self.certs.append(cert)
        self.parsed_files += 1

    def note_malformed(self) -> None:
        self.malformed_files += 1

    def note_non_pem(self) -> None:
        self.skipped_non_pem += 1

    def extend(self, certs: Iterable[CertInfo]) -> None:
        for c in certs:
            self.add(c)

    def finalize(self) -> dict[str, int]:
        return {
            "parsed_files": self.parsed_files,
            "malformed_files": self.malformed_files,
            "skipped_non_pem": self.skipped_non_pem,
            "cert_count": len(self.certs),
        }