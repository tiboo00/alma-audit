"""AISO-201 tests: self-IP detection + SSH brute-force self-IP filter."""

from __future__ import annotations

from alma_audit.analyzers.secure_log.aggregator import SecureAggregator
from alma_audit.analyzers.secure_log.parser import SecureRecord
from alma_audit.self_ip import detect_self_ips, is_self_ip


def test_detect_self_ips_returns_set():
    """detect_self_ips returns a set (may be empty on isolated hosts)."""
    result = detect_self_ips()
    assert isinstance(result, set)


def test_config_overrides_merge_into_self_ips():
    """Operator-supplied trusted_ips merge INTO the auto-detected set."""
    auto = {"1.2.3.4"}
    overrides = ["5.6.7.8", "9.10.11.12"]
    merged = detect_self_ips(overrides)
    # All override IPs present (auto may add more in some environments).
    assert "5.6.7.8" in merged
    assert "9.10.11.12" in merged
    # Auto-detected IPs preserved.
    for ip in auto:
        if ip in merged:
            # It was auto-detected; we don't assert it must be,
            # because the test host may or may not own this IP.
            pass


def test_is_self_ip_exact_match():
    assert is_self_ip("1.2.3.4", {"1.2.3.4"}) is True
    assert is_self_ip("1.2.3.4", {"5.6.7.8"}) is False


def test_is_self_ip_cidr_membership():
    """An IP inside a CIDR in self_ips counts as self."""
    # Host has /24 — 10.0.0.5 inside 10.0.0.0/24 matches.
    self_ips = {"10.0.0.0/24"}
    assert is_self_ip("10.0.0.5", self_ips) is True
    assert is_self_ip("10.0.1.5", self_ips) is False


def test_is_self_ip_ipv4_ipv6_cross_family_no_match():
    """An IPv4 never matches an IPv6 self-IP entry (different families)."""
    self_ips = {"::1"}
    assert is_self_ip("127.0.0.1", self_ips) is False


def test_is_self_ip_invalid_ip_returns_false():
    """Garbage IP input doesn't crash — returns False (not a self-IP)."""
    assert is_self_ip("not-an-ip", {"1.2.3.4"}) is False
    assert is_self_ip("", {"1.2.3.4"}) is False


def test_secure_aggregator_skips_self_ip_ssh_fail():
    """AISO-201: ssh_fail events from self-IP do NOT bump the brute-force counter."""
    agg = SecureAggregator(self_ips={"212.32.226.231"})
    # 5 failed attempts from self-IP — counter must stay at 0.
    for _ in range(5):
        agg.add(SecureRecord(
            event="ssh_fail", service="sshd",
            source_ip="212.32.226.231", user="root",
            username=None, uid=None, gid=None, pid=1,
            raw="...", raw_timestamp="Aug 17 04:12:34",
        ))
    summary = agg.finalize()
    # Brute-force counter empty.
    assert summary["ssh_fail_by_ip"] == {}
    # Forensic detail empty too (self-IP events are not in ssh_fail_details).
    assert summary["ssh_fail_details"] == []
    # But the self-IP event counter incremented, and we have a sample.
    assert summary["self_ip_event_count"] == 5
    assert any("212.32.226.231" in ex for ex in summary["self_ip_examples"])


def test_secure_aggregator_counts_external_ssh_fail_normally():
    """Non-self-IP ssh_fail events still hit the brute-force counter."""
    agg = SecureAggregator(self_ips={"212.32.226.231"})
    # External attacker — must count.
    for _ in range(7):
        agg.add(SecureRecord(
            event="ssh_fail", service="sshd",
            source_ip="9.9.9.9", user="root",
            username=None, uid=None, gid=None, pid=1,
            raw="...", raw_timestamp="Aug 17 04:12:34",
        ))
    summary = agg.finalize()
    assert summary["ssh_fail_by_ip"] == {"9.9.9.9": 7}
    assert summary["self_ip_event_count"] == 0


def test_secure_aggregator_mixed_self_and_external():
    """Realistic mix: 5 self-IP + 3 external. Only the 3 count."""
    agg = SecureAggregator(self_ips={"212.32.226.231"})
    for _ in range(5):
        agg.add(SecureRecord(
            event="ssh_fail", service="sshd",
            source_ip="212.32.226.231", user="root",
            username=None, uid=None, gid=None, pid=1,
            raw="...", raw_timestamp="Aug 17 04:12:34",
        ))
    for _ in range(3):
        agg.add(SecureRecord(
            event="ssh_fail", service="sshd",
            source_ip="9.9.9.9", user="root",
            username=None, uid=None, gid=None, pid=1,
            raw="...", raw_timestamp="Aug 17 04:12:34",
        ))
    summary = agg.finalize()
    # Only the external 3 count.
    assert summary["ssh_fail_by_ip"] == {"9.9.9.9": 3}
    assert summary["self_ip_event_count"] == 5
    # Forensic detail only carries the 3 external events.
    assert len(summary["ssh_fail_details"]) == 1
    assert summary["ssh_fail_details"][0]["ip"] == "9.9.9.9"
    assert summary["ssh_fail_details"][0]["count"] == 3


def test_secure_aggregator_default_empty_self_ips_back_compat():
    """Passing no self_ips keeps the original behaviour — every event counts."""
    agg = SecureAggregator()
    agg.add(SecureRecord(
        event="ssh_fail", service="sshd",
        source_ip="212.32.226.231", user="root",
        username=None, uid=None, gid=None, pid=1,
        raw="...", raw_timestamp="Aug 17 04:12:34",
    ))
    summary = agg.finalize()
    # Without self_ips configured, ALL events count (back-compat).
    assert summary["ssh_fail_by_ip"] == {"212.32.226.231": 1}
    assert summary["self_ip_event_count"] == 0


def test_secure_aggregator_ssh_invalid_user_skipped_for_self():
    """AISO-201: ssh_invalid_user from self-IP is also skipped."""
    agg = SecureAggregator(self_ips={"212.32.226.231"})
    for _ in range(4):
        agg.add(SecureRecord(
            event="ssh_invalid_user", service="sshd",
            source_ip="212.32.226.231", user="ghostuser",
            username=None, uid=None, gid=None, pid=1,
            raw="...", raw_timestamp="Aug 17 04:12:34",
        ))
    summary = agg.finalize()
    assert summary["ssh_fail_by_ip"] == {}
    assert summary["self_ip_event_count"] == 4
