"""Streaming aggregator for the ssh_hardening analyzer.

Holds the final state of every relevant sshd directive (last-wins,
matching sshd's own behaviour — drop-ins override the main file).
The detection rules in ``rules.py`` read this state to emit findings.

The aggregator is deliberately a ``dict``-shaped snapshot (not a
streaming ``add()`` API) because sshd_config is small (~100 lines
typical) and the last-wins rule makes streaming semantics
counter-intuitive (a drop-in can clear a directive set in the main
file by re-stating it as ``no``, and a third drop-in can then flip
it back to ``yes``). The aggregator builds the snapshot once.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable

from .parser import SshdDirective


@dataclass
class SshdConfigSnapshot:
    """Final post-Include state of an sshd_config tree.

    Each ``directives`` entry carries its ``source_path`` /
    ``source_line`` so the rule layer can put them in finding
    ``details`` (per acceptance criterion 4).
    """

    directives: dict[str, SshdDirective]
    raw_count: int
    malformed_count: int
    sources: list[str]
    # Per-directive occurrence count (drop-ins can re-state the same
    # keyword — the operator's eye needs to see that). Kept separate
    # from the last-wins ``directives`` so the rule layer can decide
    # whether to mention it.
    occurrence_count: Counter[str]

    @property
    def total_directives(self) -> int:
        return len(self.directives)


def aggregate(directives: Iterable[SshdDirective]) -> SshdConfigSnapshot:
    """Reduce a stream of ``SshdDirective`` into a last-wins snapshot."""
    last_wins: dict[str, SshdDirective] = {}
    occurrences: Counter[str] = Counter()
    sources: set[str] = set()
    for d in directives:
        # sshd keywords are case-INsensitive — store under the
        # lower-cased keyword so later overrides (different case)
        # replace earlier ones.
        key = d.keyword.lower()
        occurrences[key] += 1
        last_wins[key] = d
        sources.add(d.source_path)
    return SshdConfigSnapshot(
        directives=last_wins,
        raw_count=sum(occurrences.values()),
        malformed_count=0,  # parser doesn't currently produce malformed; reserved.
        sources=sorted(sources),
        occurrence_count=occurrences,
    )


def finalize(snap: SshdConfigSnapshot) -> dict[str, Any]:
    """Render the snapshot to a JSON-serialisable summary."""
    return {
        "directive_count": snap.total_directives,
        "raw_directive_count": snap.raw_count,
        "sources": snap.sources,
        "occurrence_count": dict(snap.occurrence_count),
    }
