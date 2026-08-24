"""AISO-121 v1.2 — crawler verification wired into the access_log analyzer.

The integration tests assert the §6.1 contract requirement that
**only D1/D4 candidates may be crawler-suppressed**; D2 (injection /
known-probe paths) and D5 (unusual HTTP methods) MUST continue to
fire regardless of whether the source UA claimed to be a crawler. The
ModSecurity analyzer is owned by a separate module and is not touched
here — its CRITICAL findings live in the report untouched.

Every suppression is auditable: the finding's `details` carries a
`crawler_suppression` dict with `{applied, reason, claimed, hostname,
suffix}` so the operator can see which verification step passed /
failed.
"""

from __future__ import annotations

from alma_audit.analyzers.access_log import analyze_access_logs
from alma_audit.models import Severity


class FakeResolver:
    """Test seam: per-IP PTR + forward responses."""

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


def _top_share_finding(findings, ip: str):
    return next(
        (
            f for f in findings
            if ip in f.title
            and ("concentration" in f.title.lower()
                 or "traffic" in f.title.lower()
                 or "suppressed" in f.title.lower())
        ),
        None,
    )


def _probe_finding(findings):
    return next(
        (f for f in findings if "probe paths" in f.title.lower()),
        None,
    )


def _weird_finding(findings):
    return next(
        (f for f in findings if "unusual" in f.title.lower()),
        None,
    )


def _error_burst_finding(findings):
    return next(
        (f for f in findings
         if "error rate" in f.title.lower() or "error burst" in f.title.lower()),
        None,
    )


# ---------------------------------------------------------------------------
# Helpers — build a one-Googlebot-dominated log
# ---------------------------------------------------------------------------

def _bot_log(bot_ip: str, ua: str, n_bot: int = 9, other_ip: str = "10.0.0.1") -> str:
    lines = []
    for i in range(n_bot):
        lines.append(
            f'{bot_ip} - - [17/Aug/2026:04:12:{i:02d} +0000] '
            f'"GET /index.html HTTP/1.1" 200 100 "-" "{ua}"'
        )
    lines.append(
        f'{other_ip} - - [17/Aug/2026:04:13:00 +0000] '
        '"GET /x HTTP/1.1" 200 100 "-" "Mozilla/5.0"'
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# D1 — top-host concentration: verifiable crawler SUPPRESSES the finding.
# ---------------------------------------------------------------------------

def test_d1_top_host_suppressed_by_verified_crawler(make_fs) -> None:
    """A 90% share from a verified Googlebot IP drops to INFO with
    `crawler_suppression.applied=True`.
    """
    googlebot_ip = "66.249.66.1"
    host = "crawl-66-249-66-1.googlebot.com"
    log = _bot_log(
        googlebot_ip,
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    )
    fs = make_fs({"/var/log/apache2/access_log": log})
    resolver = FakeResolver(
        ptr_map={googlebot_ip: host},
        forward_map={host: [googlebot_ip]},
    )
    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"], fs, resolver=resolver,
    )

    suppressed = _top_share_finding(findings, googlebot_ip)
    assert suppressed is not None, "expected a top-host finding"
    assert suppressed.severity == Severity.INFO
    assert "suppressed" in suppressed.title.lower()
    sup = suppressed.details["crawler_suppression"]
    assert sup["applied"] is True
    assert sup["claimed"] == "googlebot"
    assert sup["hostname"] == host


def test_d1_top_host_NOT_suppressed_for_claim_without_verification(make_fs) -> None:
    """A Googlebot-claiming host whose PTR returns the wrong hostname
    is NOT suppressed — the D1 finding fires as CRITICAL.
    """
    bot_ip = "1.2.3.4"
    log = _bot_log(bot_ip, "Googlebot/2.1")
    fs = make_fs({"/var/log/apache2/access_log": log})
    # PTR resolves but the hostname is on attacker's domain, not Google's.
    resolver = FakeResolver(
        ptr_map={bot_ip: "spoof.attacker.example"},
        forward_map={"spoof.attacker.example": [bot_ip]},
    )
    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"], fs, resolver=resolver,
    )

    suppressed = _top_share_finding(findings, bot_ip)
    assert suppressed is not None
    assert suppressed.severity == Severity.CRITICAL
    assert "dominates" in suppressed.title.lower()
    sup = suppressed.details["crawler_suppression"]
    assert sup["applied"] is False
    assert sup["reason"] == "suffix_mismatch"
    assert sup["hostname"] == "spoof.attacker.example"


def test_d1_top_host_with_ptr_error_fails_closed(make_fs) -> None:
    """DNS lookup fails → `ptr_error` → no suppression → CRITICAL fires."""
    bot_ip = "1.2.3.4"
    log = _bot_log(bot_ip, "Googlebot/2.1")
    fs = make_fs({"/var/log/apache2/access_log": log})
    resolver = FakeResolver()  # no PTR entry ⇒ None
    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"], fs, resolver=resolver,
    )

    suppressed = _top_share_finding(findings, bot_ip)
    assert suppressed is not None
    assert suppressed.severity == Severity.CRITICAL
    sup = suppressed.details["crawler_suppression"]
    assert sup["applied"] is False
    assert sup["reason"] == "ptr_error"


def test_d1_top_host_with_no_crawler_claim_unaffected(make_fs) -> None:
    """A single-IP-dominated log with NO crawler claim fires as before."""
    fs = make_fs({"/var/log/apache2/access_log": (
        "\n".join(
            f'10.0.0.1 - - [17/Aug/2026:04:12:{i:02d} +0000] '
            f'"GET /page{i} HTTP/1.1" 200 100 "-" "ua{i}"'
            for i in range(80)
        )
        + '\n10.0.0.2 - - [17/Aug/2026:04:13:00 +0000] '
        '"GET /x HTTP/1.1" 200 100 "-" "ua"\n'
    )})
    resolver = FakeResolver()
    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"], fs, resolver=resolver,
    )
    suppressed = _top_share_finding(findings, "10.0.0.1")
    assert suppressed is not None
    assert suppressed.severity == Severity.CRITICAL
    sup = suppressed.details["crawler_suppression"]
    assert sup["applied"] is False
    assert sup["reason"] == "no_claim"


# ---------------------------------------------------------------------------
# D2 — known probe paths: NEVER crawler-suppressible.
# ---------------------------------------------------------------------------

def test_d2_probe_paths_never_suppressed(make_fs) -> None:
    """A Googlebot IP that scans /.env MUST still trigger the probe finding."""
    googlebot_ip = "66.249.66.1"
    host = "crawl-66-249-66-1.googlebot.com"
    lines = []
    for i in range(25):
        lines.append(
            f'{googlebot_ip} - - [17/Aug/2026:04:12:{i:02d} +0000] '
            '"GET /.env HTTP/1.1" 404 - "-" '
            '"Mozilla/5.0 (compatible; Googlebot/2.1)"'
        )
    log = "\n".join(lines)

    fs = make_fs({"/var/log/apache2/access_log": log})
    resolver = FakeResolver(
        ptr_map={googlebot_ip: host},
        forward_map={host: [googlebot_ip]},
    )
    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"], fs, resolver=resolver,
    )

    probe = _probe_finding(findings)
    assert probe is not None, "expected a probe-path finding"
    assert probe.severity in (Severity.WARN, Severity.CRITICAL)
    sup = probe.details["crawler_suppression"]
    assert sup["applied"] is False
    assert sup["reason"] == "n/a"


# ---------------------------------------------------------------------------
# D5 — unusual HTTP methods: NEVER crawler-suppressible.
# ---------------------------------------------------------------------------

def test_d5_weird_methods_never_suppressed(make_fs) -> None:
    """A Googlebot IP using PROPFIND MUST still trigger the method finding."""
    googlebot_ip = "66.249.66.1"
    host = "crawl-66-249-66-1.googlebot.com"
    lines = []
    for i in range(10):
        lines.append(
            f'{googlebot_ip} - - [17/Aug/2026:04:12:{i:02d} +0000] '
            '"PROPFIND / HTTP/1.1" 405 235 "-" '
            '"Mozilla/5.0 (compatible; Googlebot/2.1)"'
        )
    log = "\n".join(lines)

    fs = make_fs({"/var/log/apache2/access_log": log})
    resolver = FakeResolver(
        ptr_map={googlebot_ip: host},
        forward_map={host: [googlebot_ip]},
    )
    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"], fs, resolver=resolver,
    )

    weird = _weird_finding(findings)
    assert weird is not None, "expected an unusual-method finding"
    assert weird.severity == Severity.WARN
    sup = weird.details["crawler_suppression"]
    assert sup["applied"] is False
    assert sup["reason"] == "n/a"


# ---------------------------------------------------------------------------
# D4 — error-rate burst: suppression gated by the burst host.
# ---------------------------------------------------------------------------

def test_d4_error_burst_suppressed_by_verified_crawler(make_fs) -> None:
    """A 50% error rate from a verified Googlebot IP drops to INFO."""
    googlebot_ip = "66.249.66.1"
    host = "crawl-66-249-66-1.googlebot.com"
    lines = []
    # 10 lines, 5 of them 4xx → 50% error rate from the bot.
    for i in range(5):
        lines.append(
            f'{googlebot_ip} - - [17/Aug/2026:04:12:{i:02d} +0000] '
            '"GET /missing HTTP/1.1" 404 - "-" '
            '"Mozilla/5.0 (compatible; Googlebot/2.1)"'
        )
    for i in range(5, 10):
        lines.append(
            f'{googlebot_ip} - - [17/Aug/2026:04:12:{i:02d} +0000] '
            f'"GET /page{i} HTTP/1.1" 200 100 "-" '
            '"Mozilla/5.0 (compatible; Googlebot/2.1)"'
        )
    # One small non-bot hit ⇒ bot is the burst host.
    lines.append(
        '10.0.0.1 - - [17/Aug/2026:04:13:00 +0000] '
        '"GET /x HTTP/1.1" 200 100 "-" "Mozilla/5.0"'
    )
    log = "\n".join(lines)

    fs = make_fs({"/var/log/apache2/access_log": log})
    resolver = FakeResolver(
        ptr_map={googlebot_ip: host},
        forward_map={host: [googlebot_ip]},
    )
    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"], fs, resolver=resolver,
    )

    burst = _error_burst_finding(findings)
    assert burst is not None, "expected an error-rate/burst finding"
    assert burst.severity == Severity.INFO
    assert "suppressed" in burst.title.lower()
    sup = burst.details["crawler_suppression"]
    assert sup["applied"] is True
    assert sup["claimed"] == "googlebot"


def test_d4_error_burst_unverified_stays_at_orig_severity(make_fs) -> None:
    """An unverified claim leaves the D4 finding's severity unchanged."""
    bot_ip = "1.2.3.4"
    lines = []
    for i in range(8):
        lines.append(
            f'{bot_ip} - - [17/Aug/2026:04:12:{i:02d} +0000] '
            '"GET /missing HTTP/1.1" 404 - "-" "Googlebot/2.1"'
        )
    for i in range(8, 10):
        lines.append(
            f'{bot_ip} - - [17/Aug/2026:04:12:{i:02d} +0000] '
            f'"GET /p{i} HTTP/1.1" 200 100 "-" "Googlebot/2.1"'
        )
    log = "\n".join(lines)

    fs = make_fs({"/var/log/apache2/access_log": log})
    # Unverified: PTR returns attacker's hostname (suffix mismatch).
    resolver = FakeResolver(
        ptr_map={bot_ip: "spoof.attacker.example"},
        forward_map={"spoof.attacker.example": [bot_ip]},
    )
    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"], fs, resolver=resolver,
    )

    burst = _error_burst_finding(findings)
    assert burst is not None
    # Severity is determined by `error_rate` thresholds — must NOT be
    # silently downgraded to INFO. (8/10 = 80% > crit=20%.)
    assert burst.severity == Severity.CRITICAL
    sup = burst.details["crawler_suppression"]
    assert sup["applied"] is False
    assert sup["reason"] == "suffix_mismatch"


# ---------------------------------------------------------------------------
# Summary detail — capped reads and skipped files must be reported.
# ---------------------------------------------------------------------------

def test_summary_lists_skipped_compressed_files(make_fs) -> None:
    """`.gz` rotation files are silently skipped; the operator sees the
    list in the summary's `details`.
    """
    fs = make_fs({"/var/log/apache2/access_log.gz": "garbage"})
    findings = analyze_access_logs(
        ["/var/log/apache2/access_log.gz"], fs,
    )
    scan = next(f for f in findings if "scanned" in f.title.lower())
    assert "/var/log/apache2/access_log.gz" in scan.details["skipped_compressed"]


def test_summary_lists_truncated_files_at_line_cap(make_fs) -> None:
    """A file over the per-file line cap is reported as truncated."""
    big_line = (
        '1.2.3.4 - - [17/Aug/2026:04:12:00 +0000] '
        '"GET /a HTTP/1.1" 200 1 "-" "ua"\n'
    )
    log = big_line * 50  # 50 valid lines — over a 10-line cap
    fs = make_fs({"/var/log/apache2/access_log": log})
    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"], fs,
        rules={"max_lines_per_file": 10},
    )
    scan = next(f for f in findings if "scanned" in f.title.lower())
    assert "/var/log/apache2/access_log" in scan.details["files_truncated_at_cap"]
    # Total lines must reflect the cap, not the underlying file size.
    assert scan.details["total_lines"] <= 10
