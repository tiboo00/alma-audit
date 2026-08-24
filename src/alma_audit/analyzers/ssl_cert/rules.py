"""Detection rules for the ssl_cert analyzer.

Two rules:

  D12 — Certificate expiry. Each cert in the aggregator emits zero or
        one finding: CRITICAL if already expired, CRITICAL if expiry
        is within `expiry_crit_days`, WARN if within `expiry_warn_days`,
        nothing otherwise. The thresholds are operator-tunable.
  D13 — Read / parse errors. Each malformed file emits one WARN finding
        naming the path. Operators use these to triage bad
        permissions or unsupported formats.

The crawler-suppressibility distinction does NOT apply — these are
non-HTTP findings.
"""

from __future__ import annotations

import datetime
from typing import Any

from ...models import Finding, Severity
from ..crawler_verify import CrawlerSuppression
from .aggregator import CertAggregator


def _now_utc() -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.timezone.utc)


def rule_certificate_expiry(
    agg: CertAggregator,
    settings: dict[str, Any],
) -> list[Finding]:
    """D12 — emit one finding per cert whose expiry window breaches."""
    n_a = CrawlerSuppression.not_applicable().to_dict()
    findings: list[Finding] = []
    now = _now_utc()
    for cert in agg.certs:
        days = cert.days_until_expiry(now=now)
        if days < 0:
            sev = Severity.CRITICAL
            title = f"Certificate expired {abs(days)} day(s) ago: {cert.subject_cn or cert.path}"
            description = (
                f"Certificate at {cert.path!r} expired on "
                f"{cert.not_after.isoformat()}. Browsers and clients "
                "will reject connections."
            )
            recommendation = "Renew the certificate (e.g. `cpanelsync` or Let's Encrypt)."
        elif days <= settings["expiry_crit_days"]:
            sev = Severity.CRITICAL
            title = f"Certificate expires in {days} day(s): {cert.subject_cn or cert.path}"
            description = (
                f"Certificate at {cert.path!r} expires on "
                f"{cert.not_after.isoformat()} ({days} day(s) from "
                "now). Below the `expiry_crit_days` threshold."
            )
            recommendation = (
                "Renew immediately — clients that haven't refreshed "
                "their CRL cache will start rejecting connections."
            )
        elif days <= settings["expiry_warn_days"]:
            sev = Severity.WARN
            title = f"Certificate expires in {days} day(s): {cert.subject_cn or cert.path}"
            description = (
                f"Certificate at {cert.path!r} expires on "
                f"{cert.not_after.isoformat()} ({days} day(s) from "
                "now). Within the `expiry_warn_days` threshold."
            )
            recommendation = (
                "Schedule renewal in the next maintenance window."
            )
        else:
            continue
        findings.append(Finding(
            module="ssl_cert",
            severity=sev,
            title=title,
            description=description,
            details={
                "path": cert.path,
                "subject_cn": cert.subject_cn,
                "subject": cert.subject,
                "issuer_cn": cert.issuer_cn,
                "serial": cert.serial,
                "not_before": cert.not_before.isoformat(),
                "not_after": cert.not_after.isoformat(),
                "days_until_expiry": days,
                "crawler_suppression": n_a,
            },
            recommendation=recommendation,
        ))
    return findings


def rule_read_errors(
    agg: CertAggregator,
    malformed_paths: list[str],
) -> list[Finding]:
    """D13 — emit one WARN per malformed / unreadable cert file."""
    n_a = CrawlerSuppression.not_applicable().to_dict()
    if not malformed_paths:
        return []
    return [Finding(
        module="ssl_cert",
        severity=Severity.WARN,
        title=f"{len(malformed_paths)} certificate file(s) could not be parsed",
        description=(
            "One or more files in the configured cert roots did not "
            "parse as a PEM X.509 certificate. This may indicate "
            "permission problems, non-PEM content (DER, PKCS7), or "
            "truncated files."
        ),
        details={
            "malformed_paths": malformed_paths,
            "crawler_suppression": n_a,
        },
        recommendation=(
            "Verify the audit user has read+execute on the cert "
            "directories. If a file is in DER format, convert with "
            "`openssl x509 -inform DER -in <f> -out <f.pem>`."
        ),
    )]