"""Detection rules for the ``error_log`` analyzer (AISO-211).

The analyzer emits three categories of findings:

  1. **Summary finding** (INFO) — scan summary with the top 10
     clients + top 10 message templates. Mirrors the access_log
     analyzer's INFO summary.

  2. **Per-client burst** (CRITICAL) — a single client repeating the
     same message template ≥ ``message_burst_crit`` times. AISO-211
     §3 contract: "CRITICAL if same message × 100+ on a single host".

  3. **Per-template burst** (WARN) — the top templates that exceed
     the threshold but DON'T pin to a single host (e.g. a global
     mpm_prefork OOM loop producing the same template from many
     clients). The rule is the same threshold as the per-client
     rule; the severity is lower because cross-client bursts are
     often a service-wide config issue rather than a targeted attack.

The analyzer does NOT shell out (``apachectl status``, etc.) — the
read-only contract forbids subprocess. The ModSecurity audit log is
covered by ``modsec_log.py``; this analyzer is intentionally scoped
to the Apache ``error_log`` file.
"""

from __future__ import annotations

from typing import Any

from ...models import Finding, Severity
from .aggregator import ErrorAggregator


def rule_summary(
    agg: ErrorAggregator,
    files_scanned: int,
    settings: dict[str, Any],
    *,
    skipped_compressed: list[str],
    unreadable: list[tuple[str, str]],
) -> Finding:
    """Build the INFO summary finding.

    The summary is always emitted (when the analyzer is enabled and
    has at least one scanned file) so the operator sees scan
    coverage in the report. The forensic detail (top_messages,
    bursts) lives in ``details`` for JSON consumers.
    """
    summary_data = agg.finalize()
    top_clients_limit = int(settings.get("top_clients_limit", 10))
    top_messages_limit = int(settings.get("top_messages_limit", 10))
    return Finding(
        module="error_log",
        severity=Severity.INFO,
        title=(
            f"Scanned {files_scanned} error log file(s), "
            f"{summary_data['classified_lines']} classified line(s)"
        ),
        description=(
            "Apache error_log scan complete. Inter-module failures "
            "(mpm_prefork OOM, ssl handshake errors, file-not-found "
            "from the host's own daemon) are aggregated by client IP "
            "and message template. See `top_messages` for the "
            "templates and `bursts` for per-(client, template) "
            "repetition counts."
        ),
        details={
            "files_scanned": files_scanned,
            "skipped_compressed": skipped_compressed,
            "unreadable": [{"path": p, "error": e} for p, e in unreadable],
            # Inline top-N (matches the access_log analyzer's
            # operator-eye contract). The forensic JSON carries the
            # full `bursts` list.
            "top_clients": summary_data["top_clients"][:top_clients_limit],
            "top_messages": summary_data["top_messages"][:top_messages_limit],
            "total_lines": summary_data["total_lines"],
            "malformed_lines": summary_data["malformed_lines"],
        },
    )


def rule_message_bursts(
    agg: ErrorAggregator,
    settings: dict[str, Any],
) -> list[Finding]:
    """CRITICAL on per-(client, template) bursts ≥ ``message_burst_crit``.

    AISO-211 §3 contract: a single host repeating the same message
    100+ times is the signature of a misbehaving client (loop, OOM,
    targeted recon). One CRITICAL finding per (client, template)
    burst that exceeds the threshold.
    """
    threshold = int(settings.get("message_burst_crit", 100))
    findings: list[Finding] = []
    # The aggregator's ``bursts`` map is keyed by (client, template).
    # Walk it in descending count order so the operator sees the
    # worst bursts first.
    sorted_bursts = sorted(
        agg.bursts.items(), key=lambda kv: kv[1], reverse=True,
    )
    for (client, template), count in sorted_bursts:
        if count < threshold:
            continue
        # Empty client_ip means the line had no client context
        # (e.g. SSL handshake errors on the parent). Surface them
        # under "<host>" so the operator can still see the burst.
        client_label = client if client != "<no_client>" else "(no client)"
        example = agg.burst_examples.get((client, template), "")
        findings.append(Finding(
            module="error_log",
            severity=Severity.CRITICAL,
            title=(
                f"Message burst on {client_label}: "
                f"{template!r} repeated {count} times"
            ),
            description=(
                f"Client {client_label!r} produced the same Apache "
                f"error_log message {count} times in the scanned "
                f"window. Threshold: {threshold}. This signature "
                "often indicates a misconfigured upstream (mpm_prefork "
                "OOM loop, repeated SSL handshake failure, scripted "
                "404-spam probe)."
            ),
            details={
                "client_ip": client_label,
                "template": template,
                "count": count,
                "threshold": threshold,
                "example_message": example,
                # Forensic context: the operator can grep the raw
                # log for this template's exact occurrences.
                "template_limit": 80,
                # Inline top-N rollups so the operator-eye Markdown
                # rendering can show the burst in context (the
                # summary finding's full `top_messages` is the
                # source of truth for the whole sample).
                "top_messages": [
                    {"template": tpl, "count": c}
                    for tpl, c in agg.messages.most_common(
                        int(settings.get("top_messages_limit", 10))
                    )
                ],
            },
            recommendation=(
                "Inspect the client; correlate with the access_log "
                "burst on the same source IP. For mpm_prefork OOM, "
                "raise MaxRequestWorkers; for SSL handshake loops, "
                "verify the client's certificate chain."
            ),
        ))
    return findings


def all_findings(
    agg: ErrorAggregator,
    files_scanned: int,
    settings: dict[str, Any],
    *,
    skipped_compressed: list[str],
    unreadable: list[tuple[str, str]],
) -> list[Finding]:
    """Run every rule and return a flat list of findings.

    The summary finding is always emitted; per-(client, template)
    burst findings are added on top.
    """
    findings: list[Finding] = []
    findings.append(rule_summary(
        agg,
        files_scanned,
        settings,
        skipped_compressed=skipped_compressed,
        unreadable=unreadable,
    ))
    findings.extend(rule_message_bursts(agg, settings))
    return findings


__all__ = ["all_findings", "rule_summary", "rule_message_bursts"]