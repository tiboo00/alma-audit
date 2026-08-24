"""Streaming aggregator for the ssh_hardening analyzer.

Holds the final state of every relevant sshd directive, applying the
**OpenSSH first-obtained-wins** rule for scalar directives
(`sshd_config(5)`: "Unless noted otherwise, for each keyword, the
first obtained value will be used.") and the documented
**additive** exception for a small whitelist of directives
(`Port`, `AcceptEnv`, `AllowGroups`, `AllowUsers`, `DenyGroups`,
`DenyUsers`, `ListenAddress`).

The detection rules in ``rules.py`` read this state to emit findings.

The aggregator is exposed as a pair of functions — ``new_snapshot()``
to allocate an empty state and ``apply_directive(snap, directive)``
to fold one parsed ``SshdDirective`` into it. The analyzer walks the
``Include`` graph inline (lex-sorted glob expansion at the position
of each ``Include`` directive) so the strict order OpenSSH honours
is preserved.

The stream shape (rather than a ``dict``-snapshot of last values) is
deliberate: sshd_config is small (~100 lines typical) but its
semantics depend on *position*, not just on the final value. A
drop-in that re-states ``PermitRootLogin no`` after the main file's
``PermitRootLogin yes`` does NOT override the earlier value — the
first obtained value wins.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

from .parser import SshdDirective


# Directives whose value is additive across occurrences. Per
# `sshd_config(5)`:
#   * Port — "Multiple options of this type are permitted."
#   * AcceptEnv / AllowGroups / AllowUsers / DenyGroups / DenyUsers /
#     ListenAddress — "This keyword may appear multiple times in
#     sshd_config with each instance appending to the list."
# The aggregator keeps the *first* SshdDirective for each scalar
# directive (first-obtained-wins) and APPENDS the values tuple for
# every directive in this set.
_ADDITIVE_DIRECTIVES: frozenset[str] = frozenset({
    "port",
    "acceptenv",
    "allowgroups",
    "allowusers",
    "denygroups",
    "denyusers",
    "listenaddress",
})


@dataclass
class SshdConfigSnapshot:
    """Final post-Include state of an sshd_config tree.

    For scalar directives (``PermitRootLogin``, ``Protocol``,
    ``PasswordAuthentication``, ``MaxAuthTries``, ...) the value is
    the **first** directive observed in stream order (matching
    OpenSSH semantics). For additive directives (``Port``,
    ``AllowUsers``, ...) the values accumulate across every
    occurrence.

    Each directive entry carries its ``source_path`` /
    ``source_line`` so the rule layer can put them in finding
    ``details`` (per acceptance criterion 4).
    """

    directives: dict[str, SshdDirective] = field(default_factory=dict)
    # Additive directives carry every occurrence's values tuple in
    # stream order. The first occurrence is still ``directives[key]``
    # for source attribution; the additional occurrences live here.
    directive_extras: dict[str, list[tuple[str, ...]]] = field(default_factory=dict)
    raw_count: int = 0
    malformed_count: int = 0
    sources: list[str] = field(default_factory=list)
    # Per-directive occurrence count (drop-ins can re-state the same
    # keyword — the operator's eye needs to see that). Kept separate
    # from the directive map so the rule layer can decide whether to
    # mention it.
    occurrence_count: Counter[str] = field(default_factory=Counter)

    @property
    def total_directives(self) -> int:
        return len(self.directives)


def new_snapshot() -> SshdConfigSnapshot:
    """Allocate an empty snapshot."""
    return SshdConfigSnapshot()


def apply_directive(snap: SshdConfigSnapshot, directive: SshdDirective) -> None:
    """Fold one parsed ``SshdDirective`` into the snapshot.

    Implements the OpenSSH first-obtained-wins rule for scalar
    directives (per ``sshd_config(5)``) and the documented additive
    exception for ``Port`` / ``AcceptEnv`` / ``AllowGroups`` /
    ``AllowUsers`` / ``DenyGroups`` / ``DenyUsers`` /
    ``ListenAddress``.

    The ``Include`` directive itself is NOT recorded here — the
    analyzer's include-expansion loop calls back into ``apply_``
    functions on the inner lines, so the final snapshot never
    carries an ``Include`` entry. ``Include`` is counted under
    ``occurrence_count`` for diagnostic completeness.
    """
    key = directive.keyword.lower()
    snap.occurrence_count[key] += 1
    if not snap.directives.get(key):
        # First (or only) occurrence — wins.
        snap.directives[key] = directive
        if key in _ADDITIVE_DIRECTIVES:
            snap.directive_extras[key] = []
        return
    # Subsequent occurrence.
    if key in _ADDITIVE_DIRECTIVES:
        # Per the man-page note, additive directives accumulate.
        snap.directive_extras[key].append(directive.values)
        return
    # Scalar directive — first obtained value wins; later
    # occurrences are intentionally NOT reflected in the snapshot
    # (they would be by OpenSSH's parse rule).


def aggregate(directives: Iterable[SshdDirective]) -> SshdConfigSnapshot:
    """Reduce a stream of ``SshdDirective`` into a first-wins snapshot.

    Convenience wrapper around ``apply_directive`` for callers that
    already have the full directive list (e.g. unit tests). The
    analyzer itself drives the stream line-by-line so the Include
    graph can be expanded at the right position.
    """
    snap = new_snapshot()
    for d in directives:
        apply_directive(snap, d)
    snap.sources = sorted({d.source_path for d in directives})
    return snap


def finalize(snap: SshdConfigSnapshot) -> dict[str, Any]:
    """Render the snapshot to a JSON-serialisable summary."""
    return {
        "directive_count": snap.total_directives,
        "raw_directive_count": sum(snap.occurrence_count.values()),
        "sources": snap.sources,
        "occurrence_count": dict(snap.occurrence_count),
    }
