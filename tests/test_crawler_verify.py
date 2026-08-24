"""AISO-119 v1.2 §6.1 — crawler verification (fail-closed semantics).

This test file locks the contract guarantees for `verify_crawler`:

  1. **All three steps must succeed** for `applied=True`.
     - step 1: PTR (`socket.gethostbyaddr`)
     - step 2: forward-confirmation (`socket.gethostbyname_ex` and the
       canonical IP must match the original)
     - step 3: suffix match against the allowlist

  2. **Fail-closed**: any DNS / network error returns `applied=False`
     with a specific `reason` from
     `{ptr_error, forward_mismatch, suffix_mismatch, no_claim, n/a}`.
     The verification chain MUST NOT raise.

  3. **Time-bounded**: `SocketResolver` uses
     `socket.setdefaulttimeout(3.0)` — production CI guarantees that
     pathological resolvers do not stall an audit run. The contract's
     "fail-closed" guarantee only holds if the resolver is bounded.

  4. **`n/a` is reserved for D2/D5** — never returned by `verify_crawler`
     as an *applied* decision. Instead, `verify_crawler` returns
     `applied=True, reason="n/a"` because the verification chain
     produced no negative signal (per the docstring).
"""

from __future__ import annotations

import pytest

from alma_audit.analyzers.crawler_verify import (
    ALL_REASONS,
    CrawlerSuppression,
    DEFAULT_ALLOWLIST,
    FORWARD_MISMATCH,
    NO_CLAIM,
    NOT_APPLICABLE,
    PTR_ERROR,
    SUFFIX_MISMATCH,
    SocketResolver,
    verify_crawler,
)


# The crawler_verify module ships a `Resolver` Protocol and a
# `SocketResolver` production implementation. Tests inject a
# `FakeResolver` of their own — we deliberately keep it local so the
# public surface stays small.


class FakeResolver:
    """Test seam: per-IP PTR + forward responses.

    `ptr_map`   : ip → hostname or None (None means PTR lookup "failed")
    `forward_map`: hostname → list[str] (empty list means "forward failed")
    """

    def __init__(
        self,
        ptr_map: dict[str, str | None] | None = None,
        forward_map: dict[str, list[str]] | None = None,
    ) -> None:
        self._ptr = ptr_map or {}
        self._forward = forward_map or {}

    def ptr(self, ip: str) -> str | None:
        return self._ptr.get(ip)

    def forward(self, hostname: str) -> list[str]:
        return list(self._forward.get(hostname, []))


# ---------------------------------------------------------------------------
# Claim regex — UAs that DO and DO NOT trigger the chain.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "ua",
    [
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)",
        "Sogou Pic Spider/3.0",
        "facebookexternalhit/1.1",
        "Twitterbot/1.0",
        "LinkedInBot/1.0",
        "Slackbot-LinkExpanding 1.0",
        "TelegramBot (like TwitterBot)",
        "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
    ],
)
def test_crawler_claim_is_recognised(ua: str) -> None:
    r = FakeResolver()
    decision = verify_crawler("1.2.3.4", ua, r)
    # A claimed UA but no PTR data → PTR_ERROR is the *first* failure
    # reason it can reach. We assert the decision is NOT `no_claim`,
    # which is the sentinel for "no claim was even made".
    assert decision.reason != NO_CLAIM
    assert decision.applied is False


@pytest.mark.parametrize(
    "ua",
    [
        "Mozilla/5.0",
        "curl/7.81.0",
        "masscan",
        "sqlmap/1.5",
        "",
    ],
)
def test_non_crawler_ua_returns_no_claim(ua: str) -> None:
    r = FakeResolver(
        ptr_map={"1.2.3.4": "crawl-66-249-66-1.googlebot.com"},
        forward_map={"crawl-66-249-66-1.googlebot.com": ["1.2.3.4"]},
    )
    decision = verify_crawler("1.2.3.4", ua, r)
    assert decision.applied is False
    assert decision.reason == NO_CLAIM
    assert decision.claimed is None
    assert decision.hostname is None
    assert decision.suffix is None


# ---------------------------------------------------------------------------
# Step 1 — PTR error path
# ---------------------------------------------------------------------------


def test_ptr_error_is_fail_closed() -> None:
    r = FakeResolver(ptr_map={"66.249.66.1": None})
    decision = verify_crawler("66.249.66.1", "Googlebot/2.1", r)
    assert decision.applied is False
    assert decision.reason == PTR_ERROR
    assert decision.claimed == "googlebot"
    assert decision.hostname is None
    assert decision.suffix is None


# ---------------------------------------------------------------------------
# Step 2 — forward-confirmation mismatch
# ---------------------------------------------------------------------------


def test_forward_mismatch_is_fail_closed() -> None:
    # PTR resolved fine but the forward lookup returns different IPs.
    r = FakeResolver(
        ptr_map={"66.249.66.1": "crawl-66-249-66-1.googlebot.com"},
        forward_map={"crawl-66-249-66-1.googlebot.com": ["8.8.8.8"]},
    )
    decision = verify_crawler("66.249.66.1", "Googlebot/2.1", r)
    assert decision.applied is False
    assert decision.reason == FORWARD_MISMATCH
    assert decision.hostname == "crawl-66-249-66-1.googlebot.com"


# ---------------------------------------------------------------------------
# Step 3 — suffix mismatch
# ---------------------------------------------------------------------------


def test_suffix_mismatch_is_fail_closed() -> None:
    # PTR + forward match the IP, but the resolved hostname is not on
    # the configured suffix list (e.g. an attacker spoofs the reverse
    # DNS of their own botnet host).
    r = FakeResolver(
        ptr_map={"1.2.3.4": "host-spoof.attacker.example"},
        forward_map={"host-spoof.attacker.example": ["1.2.3.4"]},
    )
    decision = verify_crawler("1.2.3.4", "Googlebot/2.1", r)
    assert decision.applied is False
    assert decision.reason == SUFFIX_MISMATCH
    assert decision.hostname == "host-spoof.attacker.example"
    assert decision.suffix is None


# ---------------------------------------------------------------------------
# Happy path — all three steps succeed
# ---------------------------------------------------------------------------


def test_full_chain_succeeds_for_googlebot() -> None:
    ip = "66.249.66.1"
    host = "crawl-66-249-66-1.googlebot.com"
    r = FakeResolver(
        ptr_map={ip: host},
        forward_map={host: [ip]},
    )
    decision = verify_crawler(ip, "Mozilla/5.0 (compatible; Googlebot/2.1)", r)
    assert decision.applied is True
    assert decision.reason == NOT_APPLICABLE  # "n/a" — verification had no failure
    assert decision.claimed == "googlebot"
    assert decision.hostname == host
    # Suffix must come from the allowlist (any entry is fine).
    assert decision.suffix in DEFAULT_ALLOWLIST["googlebot"]


def test_full_chain_succeeds_for_bingbot() -> None:
    ip = "40.77.167.30"
    host = "bingbot.search.msn.com"
    r = FakeResolver(
        ptr_map={ip: host},
        forward_map={host: [ip]},
    )
    decision = verify_crawler(ip, "Mozilla/5.0 (compatible; bingbot/2.0)", r)
    assert decision.applied is True
    assert decision.claimed == "bingbot"
    assert decision.suffix in DEFAULT_ALLOWLIST["bingbot"]


def test_ipv6_canonical_match_succeeds() -> None:
    """IPv6 hosts must be matched in canonical form (no zone-id, lower-case)."""
    ip = "2a06:98c0:3600::103"
    host = "crawl-2a06-98c0-3600--103.sp2.googleusercontent.com"
    # We do NOT put a suffix match for googleusercontent.com in the
    # default allowlist, so this should land on SUFFIX_MISMATCH — which
    # proves the IPv6 canonicalisation is wired (the IP would not be
    # in the raw forward list as typed otherwise).
    r = FakeResolver(
        ptr_map={ip: host},
        forward_map={host: ["2A06:98C0:3600:0:0:0:0:103"]},
    )
    decision = verify_crawler(ip, "Googlebot/2.1", r)
    # Suffix isn't a Google allowlist entry, so step 3 fails → reason
    # is the expected suffix_mismatch. If canonicalisation broke, the
    # forward step would have failed first (FORWARD_MISMATCH).
    assert decision.reason == SUFFIX_MISMATCH
    assert decision.applied is False


# ---------------------------------------------------------------------------
# Reason vocabulary — auditable set must be complete
# ---------------------------------------------------------------------------


def test_all_reasons_match_contract() -> None:
    """The contract enumerates the 5 reasons explicitly. Anything else
    is a regression and would surprise the JSON schema validator.
    """
    assert ALL_REASONS == {
        PTR_ERROR,
        FORWARD_MISMATCH,
        SUFFIX_MISMATCH,
        NO_CLAIM,
        NOT_APPLICABLE,
    }


def test_not_applicable_sentinel_for_d2_d5() -> None:
    """D2/D5 findings carry the `n/a` sentinel — never `applied=True`."""
    sentinel = CrawlerSuppression.not_applicable()
    assert sentinel.applied is False
    assert sentinel.reason == NOT_APPLICABLE
    assert sentinel.claimed is None
    assert sentinel.hostname is None
    assert sentinel.suffix is None
    payload = sentinel.to_dict()
    assert payload == {
        "applied": False,
        "reason": NOT_APPLICABLE,
        "claimed": None,
        "hostname": None,
        "suffix": None,
    }


def test_to_dict_shape_is_stable() -> None:
    """The JSON schema for `crawler_suppression` is wired to these
    exact keys; adding a new key is a contract bump.
    """
    s = CrawlerSuppression(
        applied=True,
        reason=NOT_APPLICABLE,
        claimed="googlebot",
        hostname="crawl.googlebot.com",
        suffix="googlebot.com",
    )
    d = s.to_dict()
    assert list(d.keys()) == ["applied", "reason", "claimed", "hostname", "suffix"]


# ---------------------------------------------------------------------------
# Time-bounded production resolver
# ---------------------------------------------------------------------------


def test_socket_resolver_uses_3s_default_timeout() -> None:
    """Production uses 3-second per-call timeout; tests in CI guard
    this so a future change doesn't silently turn it off.
    """
    r = SocketResolver()
    assert r._timeout == 3.0  # default


def test_socket_resolver_swallows_dns_failures(monkeypatch) -> None:
    """`SocketResolver.ptr()` MUST NOT bubble up gaierror / timeout —
    the contract's fail-closed guarantee depends on it.
    """
    import socket as _socket

    def boom(_ip: str) -> tuple[str, list[str], list[str]]:
        raise _socket.gaierror("no such host")

    monkeypatch.setattr(_socket, "gethostbyaddr", boom)
    r = SocketResolver(timeout_s=0.1)
    assert r.ptr("1.2.3.4") is None
    assert r.forward("anything.invalid") == []


def test_socket_resolver_handles_timeout(monkeypatch) -> None:
    """A `socket.timeout` raised inside lookup must also be swallowed."""
    import socket as _socket

    def hang(_ip: str) -> tuple[str, list[str], list[str]]:
        raise _socket.timeout("slow")

    def hang_fwd(_name: str) -> tuple[str, list[str], list[str]]:
        raise _socket.timeout("slow")

    monkeypatch.setattr(_socket, "gethostbyaddr", hang)
    monkeypatch.setattr(_socket, "gethostbyname_ex", hang_fwd)
    r = SocketResolver(timeout_s=0.1)
    assert r.ptr("1.2.3.4") is None
    assert r.forward("anything") == []
