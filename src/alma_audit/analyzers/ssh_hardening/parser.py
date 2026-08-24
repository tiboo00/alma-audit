"""sshd_config parser.

Pure parser: input lines (a list of strings) → a list of
``SshdDirective`` records. The aggregator lives in ``aggregator.py``;
the detection rules live in ``rules.py``.

sshd(8) has a deliberately forgiving line grammar:

  * ``#`` starts a comment (mid-line too);
  * ``key value`` (whitespace separated) is the normal shape, but
    ``key=value`` (no space) is also accepted by OpenSSH;
  * lines may be split with a trailing backslash continuation;
  * the first token is case-INsensitive (the keyword is canonicalised
    to the OpenSSH man-page spelling); argument values are NOT
    case-folded (e.g. ``yes`` / ``Yes`` / ``YES`` all count, but
    ``aes128-ctr`` vs ``AES128-CTR`` is the same algorithm);
  * ``Match`` blocks (introduced by a ``Match`` directive, terminated
    by the next ``Match`` / EOF) re-define every keyword on a
    per-user / per-group basis. The analyzer's contract is the
    top-level config posture, so ``Match`` blocks are skipped.

The parser is forgiving about lines it can't classify: malformed
lines are silently skipped (the aggregator counts them under
``malformed_lines``). OpenSSH itself logs the line number on parse
error — we don't try to do the same; the operator can rerun
``sshd -T -f /etc/ssh/sshd_config`` if they need the exact line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SshdDirective:
    """One classified sshd_config line.

    ``keyword`` is the canonical OpenSSH man-page spelling (case-
    normalised to the spelling the parser was given — we don't try
    to re-spell). ``values`` is the (already split) tail of the
    line; for most directives that's a single token (``yes``,
    ``no``, ``2``, ...) but for ``Ciphers`` / ``MACs`` it's a list.

    ``source_path`` records which file the directive came from —
    ``/etc/ssh/sshd_config`` or one of the ``sshd_config.d/*.conf``
    drop-ins. Each finding's ``details`` carries ``source_line`` so
    the operator can grep the original config.
    """

    keyword: str
    values: tuple[str, ...]
    source_path: str
    source_line: str


# Strip ``#``-style comments. We do NOT honor an escaped ``\#`` —
# OpenSSH doesn't either.
_COMMENT_RE = re.compile(r"^([^#]*?)(?:\s*#.*)?$")


def _strip_comment(line: str) -> str:
    m = _COMMENT_RE.match(line)
    assert m is not None  # regex always matches
    return m.group(1).rstrip()


def _split_directive(stripped: str) -> tuple[str, tuple[str, ...]] | None:
    """Split ``key value1 value2`` / ``key=value1`` into key + values.

    Returns ``None`` for empty / whitespace-only inputs. Empty values
    are tolerated (sshd would warn at runtime; we record them as-is
    so the operator can see the broken line).
    """
    if not stripped:
        return None
    # ``key=value`` is accepted by OpenSSH; ``key value`` is the
    # conventional form. Normalise to ``key value`` here.
    normalised = stripped.replace("=", " ", 1) if "=" in stripped.split(" ", 1)[0] else stripped
    parts = normalised.split()
    if not parts:
        return None
    keyword = parts[0]
    return keyword, tuple(parts[1:])


def parse_sshd_config(
    lines: list[str],
    *,
    source_path: str = "<input>",
    known_keywords: set[str] | None = None,
) -> tuple[list[SshdDirective], int]:
    """Parse ``lines`` into directives + a malformed-line count.

    Parameters
    ----------
    lines:
        Input lines verbatim (no pre-stripping — the parser handles
        leading whitespace).
    source_path:
        Path / label recorded on each directive. Used in finding
        details so the operator knows which drop-in (if any) the
        flag came from.
    known_keywords:
        Set of keywords to classify. ``Match`` and unknown keywords
        are silently skipped. Defaults to the
        ``_KNOWN_DIRECTIVES`` set in ``settings``.

    Returns
    -------
    (directives, malformed_count)
    """
    from .settings import _KNOWN_DIRECTIVES  # local to avoid circular import

    kw_set = known_keywords if known_keywords is not None else _KNOWN_DIRECTIVES
    directives: list[SshdDirective] = []
    malformed = 0
    in_match = False

    for raw in lines:
        stripped = _strip_comment(raw.strip())
        parsed = _split_directive(stripped)
        if parsed is None:
            continue
        keyword, values = parsed
        # sshd keywords are case-INsensitive; OpenSSH normalises to
        # the man-page spelling. We compare against the canonical
        # set case-insensitively and store the keyword as the user
        # wrote it (the aggregator case-folds for comparison).
        canonical = keyword  # keep verbatim; aggregator case-folds
        if canonical.lower() == "match":
            in_match = True
            continue
        if in_match:
            # Skip until next Match / EOF.
            if canonical.lower() == "match":
                # stay in_match = True; nested Match blocks are not
                # permitted by OpenSSH but we still treat this line
                # as the boundary.
                continue
            # An empty line in a Match block is tolerated by sshd
            # but doesn't end the block — only another Match does.
            # For our purposes (top-level posture audit) we just
            # skip every line until we see the next ``Match`` /
            # end-of-file.
            continue
        if canonical.lower() not in {k.lower() for k in kw_set}:
            # Unknown keyword — not a config posture concern.
            # We don't even count these as malformed; OpenSSH would
            # warn but accept the line.
            continue
        directives.append(SshdDirective(
            keyword=canonical,
            values=values,
            source_path=source_path,
            source_line=raw.rstrip("\n"),
        ))

    return directives, malformed


def parse_multiple(
    files: list[tuple[str, list[str]]],
    *,
    known_keywords: set[str] | None = None,
) -> tuple[list[SshdDirective], int]:
    """Parse several sshd_config files (main + drop-ins).

    ``files`` is a list of ``(path, lines)`` tuples in the order
    they should be concatenated (the analyzer sorts drop-ins
    alphabetically to match sshd's ``Include`` semantics).
    """
    all_directives: list[SshdDirective] = []
    malformed_total = 0
    for path, lines in files:
        directives, malformed = parse_sshd_config(
            lines, source_path=path, known_keywords=known_keywords,
        )
        all_directives.extend(directives)
        malformed_total += malformed
    return all_directives, malformed_total
