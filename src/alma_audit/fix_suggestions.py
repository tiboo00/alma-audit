"""Structured fix-suggestion layer (AISO-210).

Operators reading the audit want a *concrete* next-action for every
finding — where to apply the fix, what command to run, how to roll
back, and what the security trade-off is. The legacy ``recommendation``
string carried none of that. ``FindingFix`` is the structured carrier.

Each fix is keyed by ``(finding_key, scope)`` in ``FIX_LIBRARY`` so a
single finding (e.g. ``D5 weird_methods``) can carry N fixes from
different scopes (Apache config, .htaccess, Cloudflare WAF, ModSec).
The render layer groups by scope and orders by risk; the operator
walks the list top-down and stops at the first fix that's tractable
in their environment.

The library is intentionally operator-facing prose, NOT a control plane:
no command is ever executed. Everything in ``commands`` is copy-paste
documentation for the operator to run after review — this keeps the
read-only contract intact.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Iterable

if TYPE_CHECKING:
    from .models import Finding

# Scope string constants. Mirrored on ``models.FIX_SCOPE_*`` — keep
# both lists in sync; the duplicate keeps ``fix_suggestions`` a leaf
# that does not depend on the higher-level ``models`` constants.
SCOPE_LOCAL_CONFIG = "local_config"   # .htaccess, sshd_config, /etc/hosts
SCOPE_APP_CONFIG = "app_config"       # Apache httpd.conf (requires restart)
SCOPE_DNS_BLOCK = "dns_block"         # hosts.deny / csf.deny / Cloudflare IP block
SCOPE_WAF = "waf"                     # Cloudflare WAF / ModSecurity rules
SCOPE_KERNEL_PARAM = "kernel_param"   # sysctl / sshd_config Protocol 2

# Render-order scope sequence. Operators walk from the cheapest,
# lowest-blast-radius fix up to the network-wide mitigation. The
# local config fix is almost always enough on its own.
SCOPE_ORDER: tuple = (
    SCOPE_LOCAL_CONFIG,
    SCOPE_WAF,
    SCOPE_APP_CONFIG,
    SCOPE_DNS_BLOCK,
    SCOPE_KERNEL_PARAM,
)

# Risk tiers — used as the secondary sort key inside each scope.
RISK_ORDER: dict = {"low": 0, "medium": 1, "high": 2}


@dataclass
class FindingFix:
    """A single concrete remediation suggestion.

    Attributes:
        what: One-line human description of the action.
        why: Why the action closes the finding (the security trade-off).
        scope: Where the operator applies the fix (one of ``SCOPE_*``).
        risk: ``low`` / ``medium`` / ``high`` — operator uses this to
            decide whether to schedule the change or hot-fix.
        commands: List of shell / config snippets. Multi-line strings
            are allowed. Commands are NEVER executed by the audit;
            operators copy-paste them after review.
        rollback: One-line description + optional commands for the
            undo path. Empty string means "no automated rollback —
            revert manually".
        finding_key: Internal key tying this fix to a specific rule
            (e.g. ``"D5:weird_methods"``). Used by ``FIX_LIBRARY`` for
            lookup; ignored by the renderer.
    """

    what: str
    why: str
    scope: str
    risk: str
    commands: list = field(default_factory=list)
    rollback: str = ""
    finding_key: str = ""

    def to_dict(self) -> dict:
        return {
            "what": self.what,
            "why": self.why,
            "scope": self.scope,
            "risk": self.risk,
            "commands": list(self.commands),
            "rollback": self.rollback,
        }


def _build_fix_library() -> dict:
    """Return the curated fix catalogue.

    Wrapped in a function so the dataclass definitions above are
    evaluated before any ``FindingFix(...)`` constructor call.
    """
    return {
        # ----------------------------------------------------------------
        # D2 — known probe paths (/.env, /wp-login.php, ...).
        # ----------------------------------------------------------------
        "D2:probe_hits": [
            FindingFix(
                finding_key="D2:probe_hits",
                what="Block known scanner UAs / probe paths in .htaccess",
                why=(
                    "Stops the requests at the edge of the doc-root so the "
                    "attacker never reaches PHP / the framework — no Apache "
                    "restart, no WAF credentials needed."
                ),
                scope=SCOPE_LOCAL_CONFIG,
                risk="low",
                commands=[
                    "# Per-doc-root .htaccess — drops the request before PHP runs.",
                    "RewriteEngine On",
                    "RewriteCond %{REQUEST_URI} ^/(wp-login\\.php|xmlrpc\\.php|administrator/|\\.env|phpmyadmin) [NC]",
                    "RewriteRule ^.*$ - [F,L]",
                ],
                rollback=(
                    "Remove the Rewrite* lines from .htaccess; Apache will "
                    "serve the original 404 again."
                ),
            ),
            FindingFix(
                finding_key="D2:probe_hits",
                what="Add a Cloudflare WAF managed rule for known scanner paths",
                why=(
                    "Blocks the scan before it reaches the origin. Use when "
                    "the site is on Cloudflare; the WAF UI ships tuned "
                    "managed rule sets for WordPress / Joomla / generic scanners."
                ),
                scope=SCOPE_WAF,
                risk="low",
                commands=[
                    "# Cloudflare dashboard -> Security -> WAF -> Managed rules:",
                    "# enable rules with tag 'WordPress' or 'Scanner'. ",
                    "# OR via API:",
                    "curl -X POST 'https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/firewall/rules' \\",
                    "  -H 'Authorization: Bearer $CF_API_TOKEN' \\",
                    "  -d '{\"filter\":{\"expression\":\"(http.request.uri.path contains \\\"/wp-login.php\\\") or (http.request.uri.path contains \\\"/.env\\\")\"},\"action\":\"block\"}'",
                ],
                rollback=(
                    "Disable / delete the WAF rule in the Cloudflare dashboard "
                    "or DELETE it via the same API endpoint."
                ),
            ),
            FindingFix(
                finding_key="D2:probe_hits",
                what="fail2ban jail for probe-path Apache errors (if available)",
                why=(
                    "Persistent scanners that rotate IPs are caught by "
                    "fail2ban's recidive jail. Use this when .htaccess / WAF "
                    "are not blocking enough."
                ),
                scope=SCOPE_APP_CONFIG,
                risk="medium",
                commands=[
                    "# /etc/fail2ban/filter.d/apache-probes.conf",
                    "[Definition]",
                    "failregex = ^<HOST> .*\"(GET|POST|HEAD) /(wp-login|xmlrpc|administrator|\\.env|phpmyadmin)",
                    "ignoreregex =",
                    "",
                    "# /etc/fail2ban/jail.local",
                    "[apache-probes]",
                    "enabled = true",
                    "filter  = apache-probes",
                    "logpath = /var/log/apache2/access_log",
                    "maxretry = 10",
                    "findtime = 600",
                    "bantime  = 86400",
                    "",
                    "systemctl restart fail2ban",
                ],
                rollback=(
                    "Set ``enabled = false`` in jail.local + "
                    "``fail2ban-client set apache-probes unban --all``."
                ),
            ),
        ],
        # ----------------------------------------------------------------
        # D5 — unusual HTTP methods (TRACE, PROPFIND, CONNECT, ...).
        # ----------------------------------------------------------------
        "D5:weird_methods": [
            FindingFix(
                finding_key="D5:weird_methods",
                what="Disable Apache mod_trace (TraceEnable Off)",
                why=(
                    "TRACE is the canonical XST / cross-site-tracing vector. "
                    "Disabling it is one line, no functional impact on browsers, "
                    "and removes the largest source of TRACE hits."
                ),
                scope=SCOPE_APP_CONFIG,
                risk="low",
                commands=[
                    "# /etc/httpd/conf/httpd.conf (or ssl.conf)",
                    "TraceEnable Off",
                    "",
                    "apachectl -t && systemctl reload httpd",
                ],
                rollback=(
                    "Set ``TraceEnable On`` and reload Apache."
                ),
            ),
            FindingFix(
                finding_key="D5:weird_methods",
                what="Rewrite WebDAV/TRACE verbs at the doc-root",
                why=(
                    "If you can't edit httpd.conf (shared host / cPanel), "
                    ".htaccess can still deny these methods per-vhost."
                ),
                scope=SCOPE_LOCAL_CONFIG,
                risk="low",
                commands=[
                    "# .htaccess — only do this if the app does NOT use WebDAV.",
                    "<LimitExcept GET POST HEAD OPTIONS>",
                    "    Require all denied",
                    "</LimitExcept>",
                ],
                rollback=(
                    "Remove the <LimitExcept> block from .htaccess."
                ),
            ),
            FindingFix(
                finding_key="D5:weird_methods",
                what="Cloudflare WAF rule: block TRACE / PROPFIND / OPTIONS-with-body",
                why=(
                    "Catches the requests at the edge for any site behind "
                    "Cloudflare, including weird-UA scanners that bypass "
                    ".htaccess (which they don't, but defence-in-depth)."
                ),
                scope=SCOPE_WAF,
                risk="low",
                commands=[
                    "# Cloudflare firewall rule expression:",
                    "# (http.request.method eq 'TRACE') or ",
                    "# (http.request.method eq 'PROPFIND') or ",
                    "# (http.request.method eq 'DEBUG')",
                    "curl -X POST 'https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/firewall/rules' \\",
                    "  -H 'Authorization: Bearer $CF_API_TOKEN' \\",
                    "  -d '{\"filter\":{\"expression\":\"(http.request.method eq \\\"TRACE\\\") or (http.request.method eq \\\"PROPFIND\\\")\"},\"action\":\"block\"}'",
                ],
                rollback=(
                    "DELETE the WAF rule via the same API endpoint."
                ),
            ),
            FindingFix(
                finding_key="D5:weird_methods",
                what="ModSecurity rule to block TRACE / PROPFIND at the app",
                why=(
                    "Last-line defence when neither WAF nor .htaccess is in "
                    "play (rare on cPanel — mod_security is usually on by "
                    "default). Use the OWASP CRS as a base."
                ),
                scope=SCOPE_WAF,
                risk="medium",
                commands=[
                    "# /etc/modsecurity/owasp-crs/rules/REQUEST-901-INIT-RULES.conf append:",
                    "SecRule REQUEST_METHOD \"@pm TRACE PROPFIND CONNECT DEBUG\" \\",
                    "  \"id:1009001,phase:1,deny,status:405,log,msg:'Disallowed HTTP method'\"",
                    "",
                    "apachectl -t && systemctl reload httpd",
                ],
                rollback=(
                    "Remove the SecRule and reload Apache / ModSec."
                ),
            ),
        ],
        # ----------------------------------------------------------------
        # D7 — domlog filename anomalies (fuzzing / shell-metadata).
        # ----------------------------------------------------------------
        "D7:domlog_anomalies": [
            FindingFix(
                finding_key="D7:domlog_anomalies",
                what="Review cPanel logrotate config + quarantine the bad files",
                why=(
                    "The anomalies are filenames that no legitimate cPanel "
                    "account would emit — they are almost always scanner / "
                    "injection probes. Quarantine + rotate the affected log "
                    "to drop them from the live trail."
                ),
                scope=SCOPE_APP_CONFIG,
                risk="low",
                commands=[
                    "# Inspect the offenders:",
                    "ls -la /var/log/apache2/domlogs/<account>/ | grep -E '(.)\\1{6,}|\\$\\(|<|>|\"|\\|'",
                    "",
                    "# Move them aside (do NOT delete until reviewed):",
                    "mkdir -p /root/alma-audit-quarantine/domlogs-$(date +%F)",
                    "mv /var/log/apache2/domlogs/<account>/<bad-file> /root/alma-audit-quarantine/domlogs-$(date +%F)/",
                    "",
                    "# Verify logrotate cycles them on the next rotation:",
                    "cat /etc/logrotate.d/* | grep -i domlogs",
                ],
                rollback=(
                    "Move files back: ``mv /root/alma-audit-quarantine/... "
                    "/var/log/apache2/domlogs/<account>/``."
                ),
            ),
            FindingFix(
                finding_key="D7:domlog_anomalies",
                what="Add a ModSecurity rule that drops filename-injection requests",
                why=(
                    "Stops the request that would have created the anomaly "
                    "in the first place. Pair with the logrotate fix above "
                    "for defence-in-depth."
                ),
                scope=SCOPE_WAF,
                risk="medium",
                commands=[
                    "# /etc/modsecurity/owasp-crs/rules/REQUEST-901-INIT-RULES.conf append:",
                    "SecRule REQUEST_URI \"@rx [\\$\\\\(\\\\)\\\\'\\\"]\" \\",
                    "  \"id:1009002,phase:1,deny,status:400,log,msg:'Shell-metachar in URL'\"",
                    "",
                    "apachectl -t && systemctl reload httpd",
                ],
                rollback=(
                    "Remove the SecRule and reload Apache / ModSec."
                ),
            ),
        ],
        # ----------------------------------------------------------------
        # D8 — SSH brute-force burst per source IP.
        # ----------------------------------------------------------------
        "D8:ssh_brute_force": [
            FindingFix(
                finding_key="D8:ssh_brute_force",
                what="Enable + tune the fail2ban ssh jail",
                why=(
                    "Recidive scanners rotate IPs — the ssh jail (5 fail / 10m "
                    "default) bans the worst offenders automatically. Recidive "
                    "jail for the long-tail."
                ),
                scope=SCOPE_APP_CONFIG,
                risk="medium",
                commands=[
                    "# /etc/fail2ban/jail.local",
                    "[sshd]",
                    "enabled = true",
                    "backend = systemd",
                    "maxretry = 5",
                    "findtime = 600",
                    "bantime  = 3600",
                    "",
                    "[sshd-recidive]",
                    "enabled = true",
                    "filter  = recidive",
                    "logpath = /var/log/fail2ban.log",
                    "maxretry = 5",
                    "findtime = 86400",
                    "bantime  = 604800",
                    "",
                    "systemctl enable --now fail2ban",
                ],
                rollback=(
                    "``fail2ban-client unban --all`` + set ``enabled = false`` "
                    "in jail.local."
                ),
            ),
            FindingFix(
                finding_key="D8:ssh_brute_force",
                what="Add the top offender to /etc/hosts.deny (manual, per-IP)",
                why=(
                    "Belt-and-braces for the single worst IP — works even on "
                    "hosts without fail2ban, only needs ``tcp_wrappers`` in "
                    "the SSH build (default on cPanel)."
                ),
                scope=SCOPE_DNS_BLOCK,
                risk="low",
                commands=[
                    "# /etc/hosts.deny",
                    "sshd: <IP>",
                    "",
                    "# Optional: a tighter ALL:ALL with allowlist in hosts.allow",
                    "# sshd: ALL",
                    "# /etc/hosts.allow",
                    "# sshd: 10. 192.168. .trusted.example",
                ],
                rollback=(
                    "Remove the line from /etc/hosts.deny; SSH immediately "
                    "accepts the IP again."
                ),
            ),
            FindingFix(
                finding_key="D8:ssh_brute_force",
                what="Cloudflare WAF blocklist entry for the top offender (external IPs only)",
                why=(
                    "Use when the brute-force IP is external — Cloudflare's "
                    "edge blocks the next probing round before it reaches sshd."
                ),
                scope=SCOPE_WAF,
                risk="low",
                commands=[
                    "# Add to Cloudflare IP Access Rules (Tools -> IP Access Rules):",
                    "curl -X POST 'https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/firewall/access_rules/rules' \\",
                    "  -H 'Authorization: Bearer $CF_API_TOKEN' \\",
                    "  -d '{\"mode\":\"block\",\"configuration\":{\"target\":\"ip\",\"value\":\"<IP>\"},\"notes\":\"alma-audit ssh brute force\"}'",
                ],
                rollback=(
                    "DELETE the rule from the Cloudflare dashboard / API."
                ),
            ),
        ],
        # ----------------------------------------------------------------
        # D9 — sudo authentication failure burst per user.
        # ----------------------------------------------------------------
        "D9:sudo_failures": [
            FindingFix(
                finding_key="D9:sudo_failures",
                what="Review the user's sudoers entry — restrict NOPASSWD / drop unused commands",
                why=(
                    "Repeated sudo-fail for a single user is either a typo on "
                    "the operator's side, a misconfigured sudoers rule, or "
                    "credential stuffing against a wheel account. The fix is "
                    "the same: tighten the rule."
                ),
                scope=SCOPE_LOCAL_CONFIG,
                risk="low",
                commands=[
                    "# Inspect what was attempted:",
                    "journalctl -u sudo --since '-1 hour' | grep -i '<user>'",
                    "",
                    "# Tighten the rule in /etc/sudoers.d/<user>:",
                    "# Avoid blanket NOPASSWD: ALL — list the specific commands.",
                    "<user> ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart httpd",
                    "",
                    "# Validate before saving:",
                    "visudo -c -f /etc/sudoers.d/<user>",
                ],
                rollback=(
                    "Restore the previous /etc/sudoers.d/<user> file."
                ),
            ),
            FindingFix(
                finding_key="D9:sudo_failures",
                what="Audit accounts with NOPASSWD: ALL — replace with explicit command lists",
                why=(
                    "NOPASSWD: ALL on any account is an audit finding on its "
                    "own (see cis-catalog Level 2). The fix above also helps "
                    "this; run ``sudo -l -U <user>`` first."
                ),
                scope=SCOPE_LOCAL_CONFIG,
                risk="medium",
                commands=[
                    "# List accounts with blanket NOPASSWD:",
                    "grep -r 'NOPASSWD: ALL' /etc/sudoers /etc/sudoers.d/",
                    "",
                    "# For each, replace with the explicit commands they need.",
                ],
                rollback=(
                    "Keep a copy of the original sudoers.d file before "
                    "editing; restore if a service breaks."
                ),
            ),
        ],
    }


FIX_LIBRARY: dict = _build_fix_library()


def lookup_fixes(finding_key: str) -> list:
    """Return the catalogue entry for ``finding_key`` (empty list if absent)."""
    return list(FIX_LIBRARY.get(finding_key, ()))


def merge_fixes(*lists: Iterable) -> tuple:
    """Combine multiple fix lists, deduping by (scope, what).

    Deduplication key is ``(scope, what)`` — operators reading a finding
    titled "weird methods" should see the Apache fix once even if it
    shows up on the same finding from two call-sites. The richer of
    the two (longer ``commands`` list, longer ``why``) wins, so a
    refined override can replace a template without losing detail.
    """
    by_key: dict = {}
    for lst in lists:
        for fix in lst:
            key = (fix.scope, fix.what)
            existing = by_key.get(key)
            if existing is None:
                by_key[key] = fix
                continue
            # Pick the "richer" record — longer commands list wins.
            if len(fix.commands) > len(existing.commands):
                by_key[key] = fix
            elif (
                len(fix.commands) == len(existing.commands)
                and len(fix.why) > len(existing.why)
            ):
                by_key[key] = fix
    return tuple(by_key.values())


def attach_fixes(
    finding: "Finding",
    *fixes_or_lists,
):
    """Return a copy of ``finding`` with the given fixes attached.

    Existing ``fixes`` on the finding are merged with the new ones
    via :func:`merge_fixes` — call-sites can attach in any order and
    the dedup guarantees operators never see the same fix twice on
    one finding.
    """
    flat: list = []
    for entry in fixes_or_lists:
        if isinstance(entry, FindingFix):
            flat.append(entry)
        else:
            flat.extend(entry)
    merged = merge_fixes(finding.fixes, flat)
    return replace(finding, fixes=merged)


def sort_fixes(fixes: Iterable) -> list:
    """Sort by (scope-order, risk-order, what) — stable for deterministic output."""
    scope_index = {s: i for i, s in enumerate(SCOPE_ORDER)}

    def _key(fix):
        return (
            scope_index.get(fix.scope, len(SCOPE_ORDER)),
            RISK_ORDER.get(fix.risk, 99),
            fix.what,
        )

    return sorted(fixes, key=_key)


def fixes_for_finding(finding: "Finding") -> tuple:
    """Return the already-attached fixes on a finding, unchanged."""
    return tuple(finding.fixes)


def all_fixes_from_findings(findings: Iterable) -> tuple:
    """Deduplicate + sort the union of every finding's fixes.

    Used by the forensic JSON ``fixes_recommended`` array. Dedup key
    matches ``merge_fixes`` so the rules-layer and the consumer see
    the same set.
    """
    collected: list = []
    for finding in findings:
        collected.extend(fixes_for_finding(finding))
    return merge_fixes(collected)
