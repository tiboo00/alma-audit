"""Tests for the secure_log analyzer."""

from __future__ import annotations

from alma_audit.analyzers.secure_log import (
    SecureAggregator,
    analyze_secure_logs,
    parse_line,
)
from alma_audit.models import Severity
from alma_audit.runners import FakeFileSystem


# Sample syslog lines in the canonical RHEL `secure` format. The
# timestamp is the standard "Mon DD HH:MM:SS host service[pid]:" header.
SAMPLE_SECURE = """\
Aug 17 04:12:34 host sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 12345 ssh2
Aug 17 04:12:35 host sshd[1234]: Failed password for root from 1.2.3.4 port 12345 ssh2
Aug 17 04:12:36 host sshd[1234]: Failed password for invalid user root from 5.6.7.8 port 12346 ssh2
Aug 17 04:12:37 host sshd[1234]: Accepted password for admin from 5.6.7.8 port 12346 ssh2
Aug 17 04:12:38 host sshd[1235]: Invalid user evil from 9.10.11.12 port 12347
Aug 17 04:12:39 host sudo: pam_unix(sudo:auth): authentication failure; user=root tty=pts/0 ruser=root rhost= user=admin
Aug 17 04:12:40 host sudo: pam_unix(sudo:auth): authentication failure; user=admin tty=pts/1 ruser=root
Aug 17 04:12:41 host useradd[1236]: new user: name=evil, UID=0, GID=0, home=/home/evil, shell=/bin/bash
Aug 17 04:12:42 host useradd[1237]: new user: name=joebloggs, UID=1001, GID=1001, home=/home/joebloggs, shell=/bin/bash
Aug 17 04:12:43 host groupadd[1238]: new group: name=evil, GID=0
Aug 17 04:12:44 host passwd[1239]: password changed for user admin
Aug 17 04:12:45 host cron[1240]: (*system*) RELOAD (/etc/cron.d/clamav)
"""


# --- parser ---------------------------------------------------------------


def test_parse_line_ssh_failed_password():
    rec = parse_line(
        "Aug 17 04:12:34 host sshd[1234]: "
        "Failed password for invalid user admin from 1.2.3.4 port 12345 ssh2"
    )
    assert rec is not None
    assert rec.event == "ssh_fail"
    assert rec.source_ip == "1.2.3.4"
    assert rec.user == "admin"
    assert rec.service == "sshd"


def test_parse_line_ssh_invalid_user():
    rec = parse_line(
        "Aug 17 04:12:34 host sshd[1234]: Invalid user evil from 9.10.11.12"
    )
    assert rec is not None
    assert rec.event == "ssh_invalid_user"
    assert rec.source_ip == "9.10.11.12"
    assert rec.user == "evil"


def test_parse_line_ssh_accept():
    rec = parse_line(
        "Aug 17 04:12:37 host sshd[1234]: "
        "Accepted password for admin from 5.6.7.8 port 12346 ssh2"
    )
    assert rec is not None
    assert rec.event == "ssh_accept"
    assert rec.source_ip == "5.6.7.8"


def test_parse_line_sudo_failure():
    rec = parse_line(
        "Aug 17 04:12:39 host sudo: pam_unix(sudo:auth): "
        "authentication failure; user=root tty=pts/0 ruser=root"
    )
    assert rec is not None
    assert rec.event == "sudo_fail"
    assert rec.user == "root"


def test_parse_line_useradd_root():
    rec = parse_line(
        "Aug 17 04:12:41 host useradd[1236]: "
        "new user: name=evil, UID=0, GID=0, home=/home/evil, shell=/bin/bash"
    )
    assert rec is not None
    assert rec.event == "useradd"
    assert rec.username == "evil"
    assert rec.uid == 0


def test_parse_line_groupadd():
    rec = parse_line(
        "Aug 17 04:12:43 host groupadd[1238]: new group: name=evil, GID=0"
    )
    assert rec is not None
    assert rec.event == "groupadd"
    assert rec.username == "evil"
    assert rec.gid == 0


def test_parse_line_passwd_change():
    rec = parse_line(
        "Aug 17 04:12:44 host passwd[1239]: password changed for user admin"
    )
    assert rec is not None
    assert rec.event == "passwd_change"
    assert rec.username == "admin"


def test_parse_line_unrelated_cron_returns_none():
    rec = parse_line(
        "Aug 17 04:12:45 host cron[1240]: (*system*) RELOAD (/etc/cron.d/clamav)"
    )
    assert rec is None


def test_parse_line_malformed_returns_none():
    # No service tag at all.
    assert parse_line("garbage line with no service tag") is None
    # Service tag but no recognisable verb.
    assert parse_line("Aug 17 04:12:00 host sshd[1234]: doing some random thing") is None


# --- aggregator ----------------------------------------------------------


def test_aggregator_counts_classified_lines_and_malformed():
    agg = SecureAggregator()
    for line in SAMPLE_SECURE.splitlines():
        rec = parse_line(line)
        if rec is not None:
            agg.add(rec)
        elif line.strip():
            agg.note_malformed()
    summary = agg.finalize()
    assert summary["classified_lines"] >= 9
    assert summary["malformed_lines"] == 1  # the cron line
    # AISO-203: `ssh_fail` events from 1.2.3.4 are 2 — the parser
    # counts each `Failed password` line as one event. The aggregator
    # used to lump `ssh_invalid_user` into `ssh_fail_by_ip`; after
    # the split, ONLY `ssh_fail` events count there.
    assert summary["ssh_fail_by_ip"]["1.2.3.4"] == 2
    assert summary["ssh_fail_by_ip"]["5.6.7.8"] == 1
    # AISO-203: 9.10.11.12 only emitted `Invalid user evil` (one
    # line) — it goes into `ssh_invalid_user_by_ip`, NOT into
    # `ssh_fail_by_ip`.
    assert summary["ssh_fail_by_ip"].get("9.10.11.12", 0) == 0
    assert summary["ssh_invalid_user_by_ip"]["9.10.11.12"] == 1
    # `root` is the most-tried username (2x across the three failure
    # lines), `admin` is second. The fixture intentionally mixes
    # `Failed password for root` and `Failed password for invalid user root`
    # so the aggregator surfaces both.
    assert summary["ssh_invalid_users_top"][0][0] == "root"
    assert summary["ssh_invalid_users_top"][1][0] == "admin"


def test_aggregator_invalid_user_contributes_to_separate_counter():
    """AISO-203: `Invalid user X from Y` goes into `ssh_invalid_user_by_ip`,
    NOT `ssh_fail_by_ip` (rotating-username enumeration is a distinct
    attack class from single-account credential stuffing). The rule
    layer still combines both for the brute-force *finding*, so an
    attacker that only rotates usernames still trips D8.
    """
    agg = SecureAggregator()
    for _ in range(5):
        rec = parse_line("Aug 17 04:12:34 host sshd[1234]: Invalid user evil from 9.10.11.12")
        agg.add(rec)
    # ssh_invalid_user_by_ip takes the invalid-user burst.
    assert agg.ssh_invalid_user_by_ip["9.10.11.12"] == 5
    # ssh_fail_by_ip stays empty for that IP.
    assert agg.ssh_fail_by_ip.get("9.10.11.12", 0) == 0


def test_aggregator_split_counters_same_ip_separately():
    """AISO-203 AC#4: same IP emits 5 `ssh_fail` + 5 `ssh_invalid_user`.
    Each counter tracks ONLY its own pattern — no carry-over between
    them. This is the regression test for the original bug where
    `ssh_invalid_user` was silently folded into `ssh_fail_by_ip`.
    """
    agg = SecureAggregator()
    # 5 `Failed password for root from 1.2.3.4` → ssh_fail_by_ip.
    for _ in range(5):
        agg.add(parse_line(
            "Aug 17 04:12:34 host sshd[1234]: "
            "Failed password for root from 1.2.3.4 port 12345 ssh2"
        ))
    # 5 `Invalid user ghost from 1.2.3.4` → ssh_invalid_user_by_ip.
    for _ in range(5):
        agg.add(parse_line(
            "Aug 17 04:12:34 host sshd[1234]: Invalid user ghost from 1.2.3.4"
        ))
    summary = agg.finalize()
    # Same IP in both counters, with the exact per-pattern counts.
    assert summary["ssh_fail_by_ip"] == {"1.2.3.4": 5}
    assert summary["ssh_invalid_user_by_ip"] == {"1.2.3.4": 5}
    # Total forensic detail: 2 entries (one per (ip, user) bucket) —
    # `ssh_fail_by_ip_user` keys by user, so 1.2.3.4 has one entry
    # per distinct attempted username (root + ghost).
    assert len(summary["ssh_fail_details"]) == 2
    users = sorted(d["user"] for d in summary["ssh_fail_details"])
    assert users == ["ghost", "root"]


def test_aggregator_invalid_user_only_no_carry_to_fail_counter():
    """AISO-203 AC#5: feed only `ssh_invalid_user` events. The new
    `ssh_invalid_user_by_ip` counter is populated; `ssh_fail_by_ip`
    stays empty for that IP — no carry-over between the two.
    """
    agg = SecureAggregator()
    for _ in range(3):
        agg.add(parse_line(
            "Aug 17 04:12:34 host sshd[1234]: Invalid user ghostuser from 7.7.7.7"
        ))
    summary = agg.finalize()
    assert summary["ssh_invalid_user_by_ip"] == {"7.7.7.7": 3}
    assert summary["ssh_fail_by_ip"] == {}
    # Forensic detail still records the invalid-user events.
    assert len(summary["ssh_fail_details"]) == 1
    assert summary["ssh_fail_details"][0]["ip"] == "7.7.7.7"
    assert summary["ssh_fail_details"][0]["user"] == "ghostuser"


def test_aggregator_invalid_user_only_still_triggers_brute_force_rule():
    """AISO-203: D8 combines the two counters for the brute-force
    *finding*, so an attacker that ONLY rotates usernames still
    trips D8 with a sane threshold.
    """
    from alma_audit.analyzers.secure_log.rules import rule_ssh_brute_force

    agg = SecureAggregator()
    for _ in range(5):
        agg.add(parse_line(
            "Aug 17 04:12:34 host sshd[1234]: Invalid user ghostuser from 7.7.7.7"
        ))
    findings = rule_ssh_brute_force(agg, settings={
        "ssh_fail_warn": 5, "ssh_fail_crit": 50,
    })
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.WARN
    # The finding surfaces the per-pattern split in its details.
    assert f.details["source_ip"] == "7.7.7.7"
    assert f.details["ssh_fail_count"] == 0
    assert f.details["ssh_invalid_user_count"] == 5
    assert f.details["fail_count"] == 5


def test_aggregator_useradd_uid_zero_is_separate():
    agg = SecureAggregator()
    agg.add(parse_line(
        "Aug 17 04:12:41 host useradd[1236]: "
        "new user: name=evil, UID=0, GID=0, home=/home/evil, shell=/bin/bash"
    ))
    agg.add(parse_line(
        "Aug 17 04:12:42 host useradd[1237]: "
        "new user: name=joebloggs, UID=1001, GID=1001, home=/home/joebloggs, shell=/bin/bash"
    ))
    assert any(e["uid"] == 0 for e in agg.useradds)
    assert any(e["uid"] == 1001 for e in agg.useradds)


# --- analyzer ------------------------------------------------------------


def test_analyzer_emits_ssh_brute_force_warn():
    """A 1.2.3.4 burst that crosses the warn threshold must surface as WARN.

    We override the warn threshold to 2 in this test so the existing
    SAMPLE_SECURE fixture (2 failures from 1.2.3.4) trips it. The
    default threshold (5) is verified by the boundary test below.
    """
    fs = FakeFileSystem(files={"/var/log/secure": SAMPLE_SECURE})
    findings = analyze_secure_logs(
        ["/var/log/secure"], fs,
        rules={"ssh_fail_warn": 2, "ssh_fail_crit": 50},
    )
    by_sev: dict[Severity, list] = {sev: [] for sev in Severity}
    for f in findings:
        by_sev[f.severity].append(f)
    assert any("1.2.3.4" in f.title for f in by_sev[Severity.WARN]), (
        f"Expected WARN for 1.2.3.4 brute-force; got: "
        f"{[f.title for f in findings]}"
    )


def test_analyzer_emits_root_account_critical():
    fs = FakeFileSystem(files={"/var/log/secure": SAMPLE_SECURE})
    findings = analyze_secure_logs(["/var/log/secure"], fs)
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert any("evil" in f.title and "UID=0" in f.title for f in crit), (
        f"Expected CRITICAL for root-level useradd; got: "
        f"{[f.title for f in crit]}"
    )


def test_analyzer_emits_sudo_failure_findings():
    log = "\n".join([
        "Aug 17 04:12:39 host sudo: pam_unix(sudo:auth): "
        "authentication failure; user=root tty=pts/0 ruser=root"
    ] * 5)
    fs = FakeFileSystem(files={"/var/log/secure": log})
    findings = analyze_secure_logs(["/var/log/secure"], fs)
    sudo = [f for f in findings if "sudo" in f.title.lower()]
    assert sudo, f"Expected sudo findings; got: {[f.title for f in findings]}"
    assert sudo[0].severity == Severity.WARN


def test_analyzer_missing_log_root_emits_info_only():
    fs = FakeFileSystem()
    findings = analyze_secure_logs(["/var/log/secure"], fs)
    assert all(f.severity == Severity.INFO for f in findings)
    assert any("No secure" in f.title for f in findings)


def test_analyzer_skips_compressed_files_silently():
    fs = FakeFileSystem(files={
        "/var/log/secure.1.gz": SAMPLE_SECURE,
        "/var/log/secure": SAMPLE_SECURE,
    })
    findings = analyze_secure_logs(
        ["/var/log/secure.1.gz", "/var/log/secure"], fs,
    )
    summary = next(f for f in findings if "Scanned" in f.title)
    assert "/var/log/secure.1.gz" in summary.details["skipped_compressed"]


def test_analyzer_emits_warn_for_unreadable_log_file():
    """Regression: AISO-188 supervisor finding #2.

    When the secure/auth log exists but the audit user cannot read
    it (PermissionError), the analyzer must emit a structured WARN
    naming the path. Previously the permissive `open_text()` swallowed
    the OSError and the analyzer reported "Scanned 1 file, 0 lines".
    """
    import pytest as _pytest

    fs = FakeFileSystem()
    fs.add_file("/var/log/secure", SAMPLE_SECURE)
    monkey = _pytest.MonkeyPatch()
    def _deny(path, max_lines=None):
        raise PermissionError(13, "Permission denied: /var/log/secure")
    monkey.setattr(fs, "read_text", _deny)
    try:
        findings = analyze_secure_logs(["/var/log/secure"], fs)
    finally:
        monkey.undo()
    warns = [f for f in findings if f.severity == Severity.WARN]
    assert any("could not be read" in f.title.lower() for f in warns), (
        f"Expected unreadable-file WARN; got titles: {[f.title for f in findings]}"
    )
    matching = [f for f in warns if "could not be read" in f.title.lower()]
    paths_in_details = [
        item["path"]
        for f in matching
        for item in f.details.get("unreadable", [])
    ]
    assert "/var/log/secure" in paths_in_details


def test_analyzer_no_warn_when_compressed_file():
    """Compressed rotations raise FileNotFoundError, NOT OSError.
    The strict read_text treats them as out-of-scope (skipped),
    not as unreadable — so they don't generate a WARN.
    """
    fs = FakeFileSystem(files={
        "/var/log/secure.1.gz": SAMPLE_SECURE,
        "/var/log/secure": SAMPLE_SECURE,
    })
    findings = analyze_secure_logs(
        ["/var/log/secure.1.gz", "/var/log/secure"], fs,
    )
    warns = [f for f in findings if f.severity == Severity.WARN]
    assert not any("could not be read" in f.title.lower() for f in warns)


def test_analyzer_respects_max_files_cap():
    """max_files=2 means at most 2 files are scanned."""
    fs = FakeFileSystem(files={
        f"/var/log/secure.{i}": SAMPLE_SECURE for i in range(5)
    })
    findings = analyze_secure_logs(
        [f"/var/log/secure.{i}" for i in range(5)],
        fs,
        rules={"max_files": 2},
    )
    summary = next(f for f in findings if "Scanned" in f.title)
    # files_scanned counts files that opened (we test with a single
    # pattern that matches all `secure.N`). The check is that the
    # analyzer stopped iterating at the cap.
    assert summary.details["files_scanned"] <= 2


def test_analyzer_records_malformed_lines():
    log = "\n".join([
        "Aug 17 04:12:34 host sshd[1234]: Failed password for root from 1.2.3.4 port 12345 ssh2",
        "this is not a syslog line",
        "neither is this",
    ])
    fs = FakeFileSystem(files={"/var/log/secure": log})
    findings = analyze_secure_logs(["/var/log/secure"], fs)
    summary = next(f for f in findings if "Scanned" in f.title)
    assert summary.details["classified_lines"] == 1
    assert summary.details["malformed_lines"] == 2


def test_analyzer_duplicate_suppression_keeps_each_burst_once():
    """The same IP appearing in 2 rules does NOT produce a duplicate finding.

    Each rule (ssh_brute_force, sudo_failures, etc.) emits zero or one
    finding per (ip, count) tuple. We verify by counting the 1.2.3.4
    findings — should be at most one for ssh brute-force.
    """
    fs = FakeFileSystem(files={"/var/log/secure": SAMPLE_SECURE})
    findings = analyze_secure_logs(
        ["/var/log/secure"], fs,
        rules={"ssh_fail_warn": 2},
    )
    brute = [f for f in findings if "1.2.3.4" in f.title and "brute-force" in f.title.lower()]
    assert len(brute) == 1


def test_analyzer_certificate_expiry_boundary_thresholds(tmp_path):
    """At the exact threshold the severity must escalate.

    Boundary cases:
      count == ssh_fail_warn  → WARN
      count == ssh_fail_crit  → CRITICAL
      count <  ssh_fail_warn  → no finding
    """
    def _log_with_n_fails(n: int) -> str:
        lines = []
        for i in range(n):
            lines.append(
                f"Aug 17 04:12:{i:02d} host sshd[1234]: "
                f"Failed password for root from 1.2.3.4 port {12345 + i} ssh2"
            )
        return "\n".join(lines)

    # Below warn → no finding for this IP.
    fs = FakeFileSystem(files={"/var/log/secure": _log_with_n_fails(4)})
    findings = analyze_secure_logs(["/var/log/secure"], fs)
    brute = [f for f in findings if "1.2.3.4" in f.title]
    assert brute == []

    # At warn (5) → WARN.
    fs = FakeFileSystem(files={"/var/log/secure": _log_with_n_fails(5)})
    findings = analyze_secure_logs(["/var/log/secure"], fs)
    brute = [f for f in findings if "1.2.3.4" in f.title]
    assert len(brute) == 1
    assert brute[0].severity == Severity.WARN

    # At crit (20) → CRITICAL.
    fs = FakeFileSystem(files={"/var/log/secure": _log_with_n_fails(20)})
    findings = analyze_secure_logs(["/var/log/secure"], fs)
    brute = [f for f in findings if "1.2.3.4" in f.title]
    assert len(brute) == 1
    assert brute[0].severity == Severity.CRITICAL