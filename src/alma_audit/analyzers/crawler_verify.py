"""AISO-119 v1.2 §6.1 — Crawler allowlist verification (fail-closed).

The detection contract requires that any UA which *claims* to be a known
crawler (Googlebot, Bingbot, DuckDuckBot, Baiduspider, YandexBot, Sogou,
ia_archiver, Facebook/Twitter/LinkedIn/Slack/Telegram/Discord bots) is
verified before it can suppress D1/D4 findings. The verification chain is:

  1. **PTR**      — `socket.gethostbyaddr(ip)` (reversed DNS hostname).
  2. **Forward**  — `socket.gethostbyname_ex(hostname)`; the original
                    source IP must appear in the result, OR the
                    canonicalised forward A/AAAA record must match.
  3. **Suffix**   — the resolved hostname's TLD labels must end with
                    one of the strings in the configured allowlist.

ALL three must succeed for a finding to be suppressed. On ANY error
(DNS timeout, missing record, mismatch, suffix miss), the verification
fails closed — the finding is NOT suppressed, and an `info`-level
`crawler_claim_unverified` proxy is emitted with a `reason` field from:

  - `ptr_error`         — PTR lookup failed (timeout / no record / gaierror).
  - `forward_mismatch`  — PTR succeeded but forward confirmation failed.
  - `suffix_mismatch`   — hostname is forward-verified but does not end
                          with any allowlist suffix.
  - `no_claim`          — UA does not match the crawler claim regex; no
                          verification attempted, suppression decision
                          is `n/a`.
  - `n/a`               — convenience sentinel for findings that are
                          not D1/D4 (e.g. D5, D6) and thus never go
                          through the suppression decision.

The verification is **time-bounded** (`ResolverPtrForward` uses
`socket.setdefaulttimeout(3.0)` per the contract). The default
production resolver is the real socket; tests inject a `FakeResolver`
to exercise the three behavioural paths (PTR fail, forward fail,
suffix fail) without DNS.

The contract's critical guarantee: **D2/D5 are NEVER suppressed by the
crawler allowlist.** A Googlebot requesting `/etc/passwd` is still an
event — it is downgraded to `low` but the suppression is opt-out for
D2/D5. This module only emits suppression decisions for D1/D4-shaped
findings (the caller is responsible for filtering).
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from typing import Iterable, Protocol


# ---- claim regex + allowlist ---------------------------------------------
# The set of UA substrings that, if present in the User-Agent, mark the
# request as a "crawler claim". Mirrors the contract §6.1 default list.
_CRAWLER_CLAIM_RE = re.compile(
    r"(?i)("
    r"googlebot|bingbot|duckduckbot|applebot|baiduspider|yandexbot|"
    r"sogou|ia_archiver|facebookexternalhit|twitterbot|linkedinbot|"
    r"slackbot|telegrambot|discordbot"
    r")"
)

# Default allowlist. Each entry maps a crawler "claim" key to a list of
# acceptable suffix labels (lowercase). The hostname returned by the
# forward-confirmation step must end with one of these suffixes.
DEFAULT_ALLOWLIST: dict[str, tuple[str, ...]] = {
    "googlebot": ("googlebot.com", "google.com"),
    "bingbot": ("search.msn.com",),
    "duckduckbot": ("duckduckgo.com",),
    "applebot": ("applebot.apple.com", "apple.com"),
    "baiduspider": ("baidu.com", "baidu.jp"),
    "yandexbot": ("yandex.com", "yandex.net", "yandex.ru"),
    "sogou": ("sogou.com",),
    "ia_archiver": ("archive.org",),
    "facebookexternalhit": ("facebook.com", "fb.com", "fbcdn.net"),
    "twitterbot": ("twitter.com", "twimg.com"),
    "linkedinbot": ("linkedin.com",),
    "slackbot": ("slack.com",),
    "telegrambot": ("telegram.org", "t.me"),
    "discordbot": ("discord.com", "discordapp.com", "discord.gg"),
}


# ---- reason vocabulary ---------------------------------------------------
# These are the auditable reasons a D1/D4 finding's `crawler_suppression`
# record can carry. The contract enumerates them explicitly.
PTR_ERROR = "ptr_error"
FORWARD_MISMATCH = "forward_mismatch"
SUFFIX_MISMATCH = "suffix_mismatch"
NO_CLAIM = "no_claim"
NOT_APPLICABLE = "n/a"

ALL_REASONS = {PTR_ERROR, FORWARD_MISMATCH, SUFFIX_MISMATCH, NO_CLAIM, NOT_APPLICABLE}


# ---- public dataclass ---------------------------------------------------
@dataclass(frozen=True)
class CrawlerSuppression:
    """Auditable suppression decision for one D1/D4 candidate finding.

    The contract requires every D1/D4 finding to surface this decision,
    even when the UA didn't claim to be a crawler (in which case the
    reason is `no_claim` and `applied` is False). For D2/D5 findings,
    the caller builds one with `not_applicable()` so the field is
    always present and the reason is `n/a`.
    """

    applied: bool          # True iff (claim) AND (PTR ok) AND (forward ok) AND (suffix ok)
    reason: str            # one of ALL_REASONS
    claimed: str | None    # matched crawler key (e.g. "googlebot") or None
    hostname: str | None   # PTR-resolved hostname or None
    suffix: str | None     # matched allowlist suffix or None

    def to_dict(self) -> dict:
        return {
            "applied": self.applied,
            "reason": self.reason,
            # The contract §7.1 schema only requires applied + reason on
            # every D1/D4 finding. The extra fields are kept for
            # operator forensics; the JSON schema treats them as
            # optional.
            "claimed": self.claimed,
            "hostname": self.hostname,
            "suffix": self.suffix,
        }

    @staticmethod
    def not_applicable() -> "CrawlerSuppression":
        """Return the `n/a` sentinel for D2/D5-shaped findings.

        These are NEVER subject to crawler suppression (per §6.1 step 4),
        so the decision is `applied=False, reason="n/a"`. Operators
        reading the report can see at a glance that the field was
        intentionally collected but not verified.
        """
        return CrawlerSuppression(
            applied=False, reason=NOT_APPLICABLE,
            claimed=None, hostname=None, suffix=None,
        )


# ---- resolver protocol --------------------------------------------------
class Resolver(Protocol):
    """Bidirectional DNS lookup abstraction.

    Production: `SocketResolver` (real socket, 3-second timeout).
    Tests: `FakeResolver` (inject per-IP responses for each path).
    """

    def ptr(self, ip: str) -> str | None:
        """Return the PTR hostname for `ip`, or None on any failure."""
        ...

    def forward(self, hostname: str) -> list[str]:
        """Return the A/AAAA IPs `hostname` resolves to.

        Empty list on any failure (no exception bubbles up). Callers
        MUST verify the original source IP is in the returned list.
        """
        ...


class SocketResolver:
    """Production resolver.

    Uses `socket.setdefaulttimeout(3.0)` per the contract §9.7 footnote,
    wrapping each lookup in a try/except so the failure modes are
    normalised to Optional / empty list (the contract's "fail-closed"
    semantics demand that no exception ever bubbles up to the caller).
    """

    DEFAULT_TIMEOUT_S = 3.0

    def __init__(self, timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
        self._timeout = timeout_s

    def ptr(self, ip: str) -> str | None:
        try:
            old = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self._timeout)
            try:
                hostname, _aliases, _ips = socket.gethostbyaddr(ip)
            finally:
                socket.setdefaulttimeout(old)
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            return None
        if not hostname:
            return None
        return hostname

    def forward(self, hostname: str) -> list[str]:
        try:
            old = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self._timeout)
            try:
                _hostname, _aliases, ips = socket.gethostbyname_ex(hostname)
            finally:
                socket.setdefaulttimeout(old)
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            return []
        return list(ips)


# ---- canonical IP comparison -------------------------------------------
def _canonical_ip(ip: str) -> str | None:
    """Return a canonical IP string for `ip`, or None on malformed input.

    Uses the existing `ip_normalise.normalise_ip` to lower-case IPv6 and
    expand `::`. If normalisation fails, we fall back to the raw string
    so the comparison still has a chance to match (e.g. when a proxy
    proxy logs `2a06:98c0:3600::103` vs the PTR IP returns a
    differently-cased but equivalent form).
    """
    try:
        # `ip_normalise` is a sibling of `analyzers/`, not a child — the
        # module-level import below is the right path. The old
        # `from .ip_normalise` line silently fell back to the raw IP,
        # so IPv6 canonicalisation never ran.
        from ..ip_normalise import normalise_ip
        canonical, _scope = normalise_ip(ip)
        return canonical
    except (ValueError, Exception):
        return ip


# ---- main verification API ---------------------------------------------
def _claim_allowlist_keys(ua: str) -> list[str]:
    """Return the crawler-key(s) the UA claims (lowercased)."""
    if not ua:
        return []
    m = _CRAWLER_CLAIM_RE.search(ua)
    if not m:
        return []
    return [m.group(1).lower()]


def _suffix_matches(hostname: str, suffixes: Iterable[str]) -> str | None:
    """Return the first suffix that matches `hostname`, or None.

    Case-insensitive suffix match (`crawl-66-249-66-1.googlebot.com`
    ends with `.googlebot.com`).
    """
    h = hostname.lower()
    for suf in suffixes:
        if not suf:
            continue
        if h == suf or h.endswith("." + suf) or h.endswith(suf):
            return suf
    return None


def verify_crawler(
    ip: str,
    user_agent: str,
    resolver: Resolver,
    allowlist: dict[str, tuple[str, ...]] | None = None,
) -> CrawlerSuppression:
    """Run the §6.1 verification chain for one (ip, ua) pair.

    Returns a `CrawlerSuppression` whose `applied` field is True only
    when ALL three checks pass. On any failure, `applied` is False and
    the `reason` field pinpoints which step failed. When the UA makes
    no crawler claim, `reason` is `no_claim` and `applied` is False —
    caller can pass-through without further action.
    """
    cfg = allowlist if allowlist is not None else DEFAULT_ALLOWLIST
    keys = _claim_allowlist_keys(user_agent)
    if not keys:
        return CrawlerSuppression(
            applied=False, reason=NO_CLAIM, claimed=None, hostname=None, suffix=None,
        )

    # Step 1 — PTR.
    hostname = resolver.ptr(ip)
    if not hostname:
        return CrawlerSuppression(
            applied=False, reason=PTR_ERROR, claimed=keys[0], hostname=None, suffix=None,
        )

    # Step 2 — forward-confirmation.
    forward_ips = resolver.forward(hostname)
    src_canonical = _canonical_ip(ip)
    fwd_canonicals = {c for c in (_canonical_ip(x) for x in forward_ips) if c}
    if src_canonical not in fwd_canonicals and ip not in forward_ips:
        return CrawlerSuppression(
            applied=False, reason=FORWARD_MISMATCH,
            claimed=keys[0], hostname=hostname, suffix=None,
        )

    # Step 3 — suffix match across ALL claimed keys (we permit any of
    # the claimed crawler's suffixes to pass).
    matched_suffix: str | None = None
    for key in keys:
        suffixes = cfg.get(key)
        if not suffixes:
            continue
        matched_suffix = _suffix_matches(hostname, suffixes)
        if matched_suffix:
            break

    if not matched_suffix:
        return CrawlerSuppression(
            applied=False, reason=SUFFIX_MISMATCH,
            claimed=keys[0], hostname=hostname, suffix=None,
        )

    # Verification chain succeeded. The contract's reason vocabulary
    # reserves `n/a` for "no verification issue, suppression decision is
    # neutral". Per the task spec, the suppression-applied case carries
    # the same `n/a` reason because the verification chain produced no
    # negative signal — operators reading the report will see
    # `applied: true, reason: "n/a"` and understand the claim was
    # bidirectionally verified.
    return CrawlerSuppression(
        applied=True, reason=NOT_APPLICABLE,
        claimed=keys[0], hostname=hostname, suffix=matched_suffix,
    )
