"""Structured fix-suggestion layer (AISO-210).

Operators reading the audit want a *concrete* next-action for every
finding — where to apply the fix, what command to run, how to roll
back, and what the security trade-off is. The legacy ``recommendation``
string carried none of that. ``FindingFix`` is the structured carrier.

Each fix in ``FIX_LIBRARY`` is keyed by ``f"{finding_key}|{scope}"`` —
i.e. finding-key + scope combined into a single string key. This is the
canonical contract the AC#1 of AISO-210 mandates:

    FIX_LIBRARY: dict[str, FindingFix]   # key == "{finding_key}|{scope}"

Storing each fix as a single ``dict`` entry (not a list inside a
finding-key bucket) gives:

* **Unambiguous lookup** by ``(finding_key, scope)`` pair. The two
  ``waf`` fixes attached to D5 — Cloudflare WAF vs. ModSecurity — each
  get their own row; a consumer can fetch one without scanning a list.
* **Greppable keys** — operators can ``grep '"D5:weird_methods|waf'``
  in the JSON to see every WAF-scoped fix for D5.
* **Deterministic iteration order** — Python 3.7+ dicts preserve
  insertion order; the catalogue emits the rows in their canonical
  scope order (see ``SCOPE_ORDER``), which is also the operator-eye
  reading order.

Backwards-compat: ``lookup_fixes(finding_key)`` (the previous list-style
helper) still returns a tuple of every fix attached to that finding_key,
so the four rule-layer call-sites (``access_log/rules.py``,
``secure_log/rules.py``, ``domlog_inventory.py``) keep working without
edits. ``lookup_fix(finding_key, scope)`` is the new targeted helper.

The library is intentionally operator-facing prose, NOT a control plane:
no command is ever executed. Everything in ``commands`` is copy-paste
documentation for the operator to run after review — this keeps the
read-only contract intact.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Iterable

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


# Public compound-key helpers. The pipe character (``|``) is used to
# separate ``finding_key`` from ``scope``; finding keys and scope
# constants are alphanumeric/underscore, so this delimiter is safe and
# greppable. AISO-215 acceptance criterion mandates this exact shape.
def _library_key(finding_key: str, scope: str) -> str:
    """Build the canonical ``FIX_LIBRARY`` key for a (finding_key, scope) pair."""
    return f"{finding_key}|{scope}"


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


def _build_fix_library() -> dict[str, FindingFix]:
    """Return the curated fix catalogue as ``{finding_key|scope: FindingFix}``.

    AISO-215 acceptance criterion: every entry is a single
    ``FindingFix``, NOT a list — so the two D5/WAF fixes (Cloudflare vs
    ModSecurity) live at distinct keys and can be looked up
    independently via ``lookup_fix("D5:weird_methods", SCOPE_WAF)``,
    ``lookup_fix("D5:weird_methods", "waf:modsec")``, etc.

    Wrapped in a function so the dataclass definitions above are
    evaluated before any ``FindingFix(...)`` constructor call.

    Insertion order matches ``SCOPE_ORDER`` for the renderer's benefit:
    iterating ``FIX_LIBRARY.values()`` walks fixes in canonical
    (scope → risk) reading order without an extra sort.
    """
    lib: dict[str, FindingFix] = {}

    # ----------------------------------------------------------------
    # D2 — known probe paths (/.env, /wp-login.php, ...).
    # 3 fixes: local_config (.htaccess), waf (Cloudflare), app_config (fail2ban).
    # ----------------------------------------------------------------
    _add(
        lib,
        "D2:probe_hits", SCOPE_LOCAL_CONFIG,
        what="Block known scanner UAs / probe paths in .htaccess",
        why=(
            "Stops the requests at the edge of the doc-root so the "
            "attacker never reaches PHP / the framework — no Apache "
            "restart, no WAF credentials needed."
        ),
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
    )
    _add(
        lib,
        "D2:probe_hits", SCOPE_WAF,
        what="Add a Cloudflare WAF managed rule for known scanner paths",
        why=(
            "Blocks the scan before it reaches the origin. Use when "
            "the site is on Cloudflare; the WAF UI ships tuned "
            "managed rule sets for WordPress / Joomla / generic scanners."
        ),
        risk="low",
        commands=[
            "# Cloudflare dashboard -> Security -> WAF -> Managed rules:",
            "# enable rules with tag 'WordPress' or 'Scanner'. ",
            "# OR via API:",
            "curl -X POST 'https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/firewall/rules' \\",
            "  -H 'Authorization: Bearer ***' \\",
            "  -d '{\"filter\":{\"expression\":\"(http.request.uri.path contains \\\"/wp-login.php\\\") or (http.request.uri.path contains \\\"/.env\\\")\"},\"action\":\"block\"}'",
        ],
        rollback=(
            "Disable / delete the WAF rule in the Cloudflare dashboard "
            "or DELETE it via the same API endpoint."
        ),
    )
    _add(
        lib,
        "D2:probe_hits", SCOPE_APP_CONFIG,
        what="fail2ban jail for probe-path Apache errors (if available)",
        why=(
            "Persistent scanners that rotate IPs are caught by "
            "fail2ban's recidive jail. Use this when .htaccess / WAF "
            "are not blocking enough."
        ),
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
    )

    # ----------------------------------------------------------------
    # D5 — unusual HTTP methods (TRACE, PROPFIND, CONNECT, ...).
    # 4 fixes (AISO-215 AC): app_config (Apache TraceEnable), local_config
    # (.htaccess), then two distinct WAF scopes — Cloudflare (waf:cflare)
    # and ModSecurity (waf:modsec). The two WAF fixes were anonymous list
    # items before; they now each live at their own library key, so a
    # consumer can fetch only the Cloudflare one without scanning the
    # list for the right scope.
    # ----------------------------------------------------------------
    _add(
        lib,
        "D5:weird_methods", SCOPE_APP_CONFIG,
        what="Disable Apache mod_trace (TraceEnable Off)",
        why=(
            "TRACE is the canonical XST / cross-site-tracing vector. "
            "Disabling it is one line, no functional impact on browsers, "
            "and removes the largest source of TRACE hits."
        ),
        risk="low",
        commands=[
            "# /etc/httpd/conf/httpd.conf (or ssl.conf)",
            "TraceEnable Off",
            "",
            "apachectl -t && systemctl reload httpd",
        ],
        rollback="Set ``TraceEnable On`` and reload Apache.",
    )
    _add(
        lib,
        "D5:weird_methods", SCOPE_LOCAL_CONFIG,
        what="Rewrite WebDAV/TRACE verbs at the doc-root",
        why=(
            "If you can't edit httpd.conf (shared host / cPanel), "
            ".htaccess can still deny these methods per-vhost."
        ),
        risk="low",
        commands=[
            "# .htaccess — only do this if the app does NOT use WebDAV.",
            "<LimitExcept GET POST HEAD OPTIONS>",
            "    Require all denied",
            "</LimitExcept>",
        ],
        rollback="Remove the <LimitExcept> block from .htaccess.",
    )
    _add(
        lib,
        "D5:weird_methods", "waf:cflare",
        what="Cloudflare WAF rule: block TRACE / PROPFIND / OPTIONS-with-body",
        why=(
            "Catches the requests at the edge for any site behind "
            "Cloudflare, including weird-UA scanners that bypass "
            ".htaccess (which they don't, but defence-in-depth)."
        ),
        risk="low",
        commands=[
            "# Cloudflare firewall rule expression:",
            "# (http.request.method eq 'TRACE') or ",
            "# (http.request.method eq 'PROPFIND') or ",
            "# (http.request.method eq 'DEBUG')",
            "curl -X POST 'https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/firewall/rules' \\",
            "  -H 'Authorization: Bearer ***' \\",
            "  -d '{\"filter\":{\"expression\":\"(http.request.method eq \\\"TRACE\\\") or (http.request.method eq \\\"PROPFIND\\\")\"},\"action\":\"block\"}'",
        ],
        rollback="DELETE the WAF rule via the same API endpoint.",
    )
    _add(
        lib,
        "D5:weird_methods", "waf:modsec",
        what="ModSecurity rule to block TRACE / PROPFIND at the app",
        why=(
            "Last-line defence when neither WAF nor .htaccess is in "
            "play (rare on cPanel — mod_security is usually on by "
            "default). Use the OWASP CRS as a base."
        ),
        risk="medium",
        commands=[
            "# /etc/modsecurity/owasp-crs/rules/REQUEST-901-INIT-RULES.conf append:",
            "SecRule REQUEST_METHOD \"@pm TRACE PROPFIND CONNECT DEBUG\" \\",
            "  \"id:1009001,phase:1,deny,status:405,log,msg:'Disallowed HTTP method'\"",
            "",
            "apachectl -t && systemctl reload httpd",
        ],
        rollback="Remove the SecRule and reload Apache / ModSec.",
    )

    # ----------------------------------------------------------------
    # D7 — domlog filename anomalies (fuzzing / shell-metadata).
    # 2 fixes: app_config (cPanel logrotate review), waf (ModSec rule).
    # ----------------------------------------------------------------
    _add(
        lib,
        "D7:domlog_anomalies", SCOPE_APP_CONFIG,
        what="Review cPanel logrotate config + quarantine the bad files",
        why=(
            "The anomalies are filenames that no legitimate cPanel "
            "account would emit — they are almost always scanner / "
            "injection probes. Quarantine + rotate the affected log "
            "to drop them from the live trail."
        ),
        risk="low",
        commands=[
            "# Inspect the offenders:",
            "ls -la /var/log/apache2/domlogs/<account>/ | grep -E '(.)\\1{6,}|\\$\\(|<|>|\\\"|\\|'",
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
    )
    _add(
        lib,
        "D7:domlog_anomalies", SCOPE_WAF,
        what="Add a ModSecurity rule that drops filename-injection requests",
        why=(
            "Stops the request that would have created the anomaly "
            "in the first place. Pair with the logrotate fix above "
            "for defence-in-depth."
        ),
        risk="medium",
        commands=[
            "# /etc/modsecurity/owasp-crs/rules/REQUEST-901-INIT-RULES.conf append:",
            "SecRule REQUEST_URI \"@rx [\\$\\\\\\(\\\\\\)\\\\\\\'\\\\\\\"]\" \\",
            "  \"id:1009002,phase:1,deny,status:400,log,msg:'Shell-metachar in URL'\"",
            "",
            "apachectl -t && systemctl reload httpd",
        ],
        rollback="Remove the SecRule and reload Apache / ModSec.",
    )

    # ----------------------------------------------------------------
    # D8 — SSH brute-force burst per source IP.
    # 3 fixes: app_config (fail2ban ssh jail), dns_block (hosts.deny),
    # waf (Cloudflare IP block for external IPs).
    # ----------------------------------------------------------------
    _add(
        lib,
        "D8:ssh_brute_force", SCOPE_APP_CONFIG,
        what="Enable + tune the fail2ban ssh jail",
        why=(
            "Recidive scanners rotate IPs — the ssh jail (5 fail / 10m "
            "default) bans the worst offenders automatically. Recidive "
            "jail for the long-tail."
        ),
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
    )
    _add(
        lib,
        "D8:ssh_brute_force", SCOPE_DNS_BLOCK,
        what="Add the top offender to /etc/hosts.deny (manual, per-IP)",
        why=(
            "Belt-and-braces for the single worst IP — works even on "
            "hosts without fail2ban, only needs ``tcp_wrappers`` in "
            "the SSH build (default on cPanel)."
        ),
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
    )
    _add(
        lib,
        "D8:ssh_brute_force", SCOPE_WAF,
        what="Cloudflare WAF blocklist entry for the top offender (external IPs only)",
        why=(
            "Use when the brute-force IP is external — Cloudflare's "
            "edge blocks the next probing round before it reaches sshd."
        ),
        risk="low",
        commands=[
            "# Add to Cloudflare IP Access Rules (Tools -> IP Access Rules):",
            "curl -X POST 'https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/firewall/access_rules/rules' \\",
            "  -H 'Authorization: Bearer ***' \\",
            "  -d '{\"mode\":\"block\",\"configuration\":{\"target\":\"ip\",\"value\":\"<IP>\"},\"notes\":\"alma-audit ssh brute force\"}'",
        ],
        rollback="DELETE the rule from the Cloudflare dashboard / API.",
    )

    # ----------------------------------------------------------------
    # D9 — sudo authentication failure burst per user.
    # 2 fixes: both local_config (sudoers tightening, NOPASSWD audit).
    #
    # AISO-215 follow-up: the two D9 fixes must each get their own
    # library row, not collide on the same ``local_config`` key. The
    # compound key is ``f"{finding_key}|{scope}"`` so two ``local_config``
    # rows collide and the second ``_add`` silently overwrites the first
    # — the per-user sudoers-review fix was lost. Use sub-scoped keys
    # (``local_config:sudoers_review`` / ``local_config:nopasswd_audit``)
    # following the D5 ``waf:cflare`` / ``waf:modsec`` precedent. The
    # renderer groups each sub-scope under its own ``### local_config:
    # <name>`` section (mirroring D5's two WAF subsections); the
    # ``_sort_key``/``_scope_index`` fall back to the bare ``local_config``
    # bucket so the canonical scope ordering stays ``local_config``
    # first — operator-eye reading order is unchanged.
    # ----------------------------------------------------------------
    _add(
        lib,
        "D9:sudo_failures", "local_config:sudoers_review",
        what="Review the user's sudoers entry — restrict NOPASSWD / drop unused commands",
        why=(
            "Repeated sudo-fail for a single user is either a typo on "
            "the operator's side, a misconfigured sudoers rule, or "
            "credential stuffing against a wheel account. The fix is "
            "the same: tighten the rule."
        ),
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
        rollback="Restore the previous /etc/sudoers.d/<user> file.",
    )
    _add(
        lib,
        "D9:sudo_failures", "local_config:nopasswd_audit",
        what="Audit accounts with NOPASSWD: ALL — replace with explicit command lists",
        why=(
            "NOPASSWD: ALL on any account is an audit finding on its "
            "own (see cis-catalog Level 2). The fix above also helps "
            "this; run ``sudo -l -U <user>`` first."
        ),
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
    )

    # ----------------------------------------------------------------
    # D21 — critical service public-bind (AISO-220, listening_ports)
    # Per-service local_config fix — every entry points at the
    # canonical "bind to loopback / private interface" config file
    # for that service. WAF / app_config scopes are not relevant:
    # the WAF cannot help (the port is open on the host), and the
    # ``app_config`` scope here is the same local_config file.
    # ----------------------------------------------------------------
    _add(
        lib,
        "D21:mysql_public_bind", SCOPE_LOCAL_CONFIG,
        what="bind-address = 127.0.0.1 in /etc/my.cnf",
        why=(
            "MySQL must never be reachable from the public internet. "
            "The bind-address directive constrains the daemon to a "
            "single interface; combined with CSF/firewalld IP-restrict "
            "for monitoring, this is the canonical lockdown."
        ),
        risk="low",
        commands=[
            "# /etc/my.cnf or /etc/my.cnf.d/server.cnf (cPanel):",
            "[mysqld]",
            "bind-address = 127.0.0.1",
            "",
            "# Restart (cPanel):",
            "/scripts/restartsrv_mysql",
            "# or: systemctl restart mysql",
        ],
        rollback=(
            "Edit the same file and revert bind-address (or set to "
            "the previous value). Restart MySQL."
        ),
    )
    _add(
        lib,
        "D21:postgres_public_bind", SCOPE_LOCAL_CONFIG,
        what="listen_addresses = 'localhost' in postgresql.conf",
        why=(
            "PostgreSQL defaults to listening on every interface. "
            "Restrict it to localhost unless remote access is required "
            "(in which case scope it via pg_hba.conf + firewall IP allow)."
        ),
        risk="low",
        commands=[
            "# /var/lib/pgsql/data/postgresql.conf (path varies by distro):",
            "listen_addresses = 'localhost'",
            "",
            "# Reload without dropping connections:",
            "systemctl reload postgresql",
        ],
        rollback=(
            "Restore the previous listen_addresses value and "
            "systemctl reload postgresql."
        ),
    )
    _add(
        lib,
        "D21:redis_public_bind", SCOPE_LOCAL_CONFIG,
        what="bind 127.0.0.1 + protected-mode yes in redis.conf",
        why=(
            "Redis on 0.0.0.0 is one of the most common misconfigurations "
            "that leads to ransomware-style data wipe attacks (the "
            "Redlock 'redis-magic' campaign). The bind + protected-mode "
            "pair is the canonical lockdown."
        ),
        risk="low",
        commands=[
            "# /etc/redis/redis.conf:",
            "bind 127.0.0.1",
            "protected-mode yes",
            "",
            "systemctl restart redis",
        ],
        rollback=(
            "Restore the previous bind line and ``systemctl restart redis``."
        ),
    )
    _add(
        lib,
        "D21:memcached_public_bind", SCOPE_LOCAL_CONFIG,
        what="memcached -l 127.0.0.1 in /etc/sysconfig/memcached",
        why=(
            "Memcached on 0.0.0.0 was the basis of a major 2018 DDoS "
            "amplification campaign. Restrict to loopback; remote access "
            "is unsupported by design."
        ),
        risk="low",
        commands=[
            "# /etc/sysconfig/memcached:",
            "OPTIONS=\"-l 127.0.0.1\"",
            "",
            "systemctl restart memcached",
        ],
        rollback=(
            "Restore the previous OPTIONS line and restart memcached."
        ),
    )
    _add(
        lib,
        "D21:mongodb_public_bind", SCOPE_LOCAL_CONFIG,
        what="bindIp: 127.0.0.1 in mongod.conf",
        why=(
            "MongoDB was hit by a wave of ransomware attacks in 2017 "
            "after operators left it bound to 0.0.0.0 with no auth. The "
            "default config now binds to localhost; verify on legacy hosts."
        ),
        risk="low",
        commands=[
            "# /etc/mongod.conf:",
            "net:",
            "  bindIp: 127.0.0.1",
            "",
            "systemctl restart mongod",
        ],
        rollback=(
            "Restore the previous bindIp and restart mongod."
        ),
    )
    _add(
        lib,
        "D21:telnet_public_bind", SCOPE_LOCAL_CONFIG,
        what="telnet server disabled + SSH replaces it",
        why=(
            "telnet is plaintext. Disable the daemon (``systemctl disable "
            "--now telnet.socket``) and use SSH for any remote shell access. "
            "telnet should not be exposed to the network under any "
            "circumstance in 2026."
        ),
        risk="low",
        commands=[
            "systemctl disable --now telnet.socket",
            "systemctl mask telnet.socket",
        ],
        rollback=(
            "Unmask + enable: ``systemctl unmask telnet.socket && "
            "systemctl enable --now telnet.socket``."
        ),
    )
    _add(
        lib,
        "D21:rdp_public_bind", SCOPE_LOCAL_CONFIG,
        what="RDP not on a Linux host — investigate",
        why=(
            "Remote Desktop Protocol (TCP/3389) is a Windows protocol. "
            "Its presence on a Linux host is almost always a leftover "
            "from an old rdesktop / XRDP install, or an accidental "
            "expose via Docker. Remove the binding or close the port "
            "at the firewall."
        ),
        risk="low",
        commands=[
            "# Find the listener:",
            "ss -tlnp 'sport = :3389'",
            "",
            "# If it's xrdp:",
            "systemctl disable --now xrdp",
            "",
            "# If it's Docker / a container:",
            "docker ps --filter 'publish=3389'",
        ],
        rollback=(
            "Re-enable the service if a documented requirement needs it "
            "(rare on a Linux box)."
        ),
    )
    _add(
        lib,
        "D21:pop3_imap_plaintext", SCOPE_LOCAL_CONFIG,
        what="Disable POP3/IMAP, force POP3S/IMAPS",
        why=(
            "Plaintext POP3/IMAP transmits credentials in the clear. "
            "cPanel/WHM allows disabling the plaintext variants via the "
            "Mailserver Configuration UI; do that, then ensure the "
            "encrypted variants are available on 110/143 blocked / "
            "993/995 open."
        ),
        risk="medium",
        commands=[
            "# cPanel/WHM:",
            "# Home -> Server Configuration -> Mailserver Configuration",
            "# Disable: POP3, IMAP (the plaintext protocols)",
            "# Enable:  POP3 with TLS, IMAP with TLS",
        ],
        rollback=(
            "Re-enable via the same WHM UI if a documented client "
            "requires plaintext."
        ),
    )
    _add(
        lib,
        "D21:critical_generic", SCOPE_LOCAL_CONFIG,
        what="Restrict the bind to loopback or a private interface",
        why=(
            "Any service that's not designed for public exposure should "
            "bind to 127.0.0.1, ::1, or a private interface. If remote "
            "access is required, scope it via CSF/firewalld to the "
            "operator's IP range."
        ),
        risk="low",
        commands=[
            "# 1. Find the service config (most 'bind' or 'listen' settings)",
            "# 2. Set bind/listen to 127.0.0.1 or a private IP",
            "# 3. Restart the service",
            "",
            "# Pair with a firewall IP-allowlist:",
            "firewall-cmd --permanent --zone=public --add-rich-rule=' "
            "rule family=ipv4 source address=<admin-ip> port port=<port> "
            "protocol=tcp accept' && firewall-cmd --reload",
        ],
        rollback=(
            "Restore the previous bind value and restart the service. "
            "Remove the firewall rich-rule: "
            "``firewall-cmd --permanent --remove-rich-rule='...'``."
        ),
    )

    # D22 — MySQL bind-address secondary signal (config file pointer)
    _add(
        lib,
        "D22:mysql_bind_address", SCOPE_LOCAL_CONFIG,
        what="bind-address = 127.0.0.1 in /etc/my.cnf (config file)",
        why=(
            "The MySQL config file points to the runtime fix — this "
            "finding complements D21 (the runtime signal). The two "
            "together tell the operator the listener is bound and the "
            "config agrees."
        ),
        risk="low",
        commands=[
            "# /etc/my.cnf or /etc/my.cnf.d/server.cnf:",
            "[mysqld]",
            "bind-address = 127.0.0.1",
            "",
            "/scripts/restartsrv_mysql",
        ],
        rollback=(
            "Edit the same file and restore the previous bind-address "
            "value, then restart MySQL."
        ),
    )

    # D23 — IPv6 dual-stack on a critical port
    _add(
        lib,
        "D23:ipv6_dual_stack", SCOPE_LOCAL_CONFIG,
        what="Bind to BOTH IPv4 loopback AND IPv6 loopback",
        why=(
            "Setting bind-address=127.0.0.1 closes the IPv4 listener but "
            "the IPv6 listener on :: keeps serving. Always pair with the "
            "IPv6-only bind so the same daemon doesn't have a parallel "
            "public path."
        ),
        risk="low",
        commands=[
            "# MySQL example — set BOTH v4 and v6:",
            "# /etc/my.cnf:",
            "[mysqld]",
            "bind-address = 127.0.0.1",
            "",
            "# For v6-only: listen on ::1 — service-specific;",
            "# Redis, Postgres, etc. have their own syntax.",
            "# Verify after restart:",
            "ss -tlnp | grep -E '(:3306|:6379|:5432|:27017)'",
        ],
        rollback=(
            "Restore the previous bind value and restart the service."
        ),
    )

    # ----------------------------------------------------------------
    # D25 — no firewall at all (AISO-220, firewall_state)
    # ----------------------------------------------------------------
    _add(
        lib,
        "D25:no_firewall", SCOPE_LOCAL_CONFIG,
        what="Install + enable CSF (cPanel) or firewalld (AlmaLinux)",
        why=(
            "Every public-facing host should run a host firewall. "
            "Without one, every listening port is reachable from "
            "anywhere by default."
        ),
        risk="low",
        commands=[
            "# cPanel hosts:",
            "cd /usr/src/csf && sh install.sh",
            "csf -e",
            "",
            "# Plain AlmaLinux:",
            "dnf install -y firewalld",
            "systemctl enable --now firewalld",
            "firewall-cmd --permanent --add-service=ssh",
            "firewall-cmd --reload",
        ],
        rollback=(
            "Removing CSF / disabling firewalld reverts the firewall to "
            "host-default (which may mean no firewall at all)."
        ),
    )

    # ----------------------------------------------------------------
    # D26 — engine installed but daemon not running (per engine)
    # ----------------------------------------------------------------
    _add(
        lib,
        "D26:csf_not_running", SCOPE_LOCAL_CONFIG,
        what="csf -e + systemctl enable lfd",
        why=(
            "CSF ships two daemons; csf -e enables both csf (rules "
            "engine) and lfd (login failure blocker). Without lfd, "
            "every brute-force attempt is silent."
        ),
        risk="low",
        commands=[
            "csf -e",
            "systemctl enable lfd",
            "csf -r",
        ],
        rollback=(
            "``csf -x`` disables both daemons temporarily (re-enable with "
            "``csf -e``)."
        ),
    )
    _add(
        lib,
        "D26:firewalld_not_running", SCOPE_LOCAL_CONFIG,
        what="systemctl enable --now firewalld",
        why=(
            "firewalld installed but not active = same as no firewall. "
            "Enable + open the SSH port BEFORE disconnecting, otherwise "
            "you'll lock yourself out of the box."
        ),
        risk="medium",  # medium because of the lockout risk
        commands=[
            "firewall-cmd --permanent --add-service=ssh",
            "firewall-cmd --reload",
            "systemctl enable --now firewalld",
        ],
        rollback=(
            "``systemctl disable --now firewalld`` to revert (host falls "
            "back to no firewall)."
        ),
    )
    _add(
        lib,
        "D26:iptables_not_running", SCOPE_LOCAL_CONFIG,
        what="systemctl enable --now iptables + iptables-restore",
        why=(
            "iptables has no daemon — it relies on a service unit that "
            "restores the rules from /etc/sysconfig/iptables at boot."
        ),
        risk="low",
        commands=[
            "systemctl enable --now iptables",
            "iptables-restore < /etc/sysconfig/iptables",
        ],
        rollback=(
            "``systemctl disable --now iptables`` and clear the rules."
        ),
    )
    _add(
        lib,
        "D26:nftables_not_running", SCOPE_LOCAL_CONFIG,
        what="systemctl enable --now nftables + nft -f /etc/nftables.conf",
        why=(
            "nftables is userspace + kernel — the rules persist in "
            "/etc/nftables.conf and the nftables.service unit loads them "
            "at boot. Enable + restore."
        ),
        risk="low",
        commands=[
            "systemctl enable --now nftables",
            "nft -f /etc/nftables.conf",
        ],
        rollback=(
            "``systemctl disable --now nftables`` and ``nft flush ruleset``."
        ),
    )
    _add(
        lib,
        "D26:generic", SCOPE_LOCAL_CONFIG,
        what="Enable the firewall daemon via systemd",
        why=(
            "An installed firewall whose daemon is not running offers "
            "zero protection. Enable it and verify it survives a reboot."
        ),
        risk="low",
        commands=[
            "systemctl enable --now <firewall-service>",
        ],
        rollback=(
            "``systemctl disable --now <firewall-service>``."
        ),
    )

    # D27 — CSF installed but lfd daemon dead
    _add(
        lib,
        "D27:csf_lfd_dead", SCOPE_LOCAL_CONFIG,
        what="csf -e + systemctl status lfd",
        why=(
            "lfd is the per-event blocker that cPanel + cPHulk + CSF "
            "integrations depend on. Without it, CSF is configuration "
            "without enforcement."
        ),
        risk="low",
        commands=[
            "csf -e",
            "systemctl enable lfd",
            "systemctl status lfd",
            "csf -r",
        ],
        rollback=(
            "``systemctl disable lfd`` and ``csf -x`` to revert."
        ),
    )

    # D28 — running firewall but ruleset empty
    _add(
        lib,
        "D28:iptables_no_rules", SCOPE_LOCAL_CONFIG,
        what="Restore iptables rules from /etc/sysconfig/iptables",
        why=(
            "A running iptables with no rules accepts every packet by "
            "default policy — same as no firewall. Restore the baseline."
        ),
        risk="low",
        commands=[
            "iptables-restore < /etc/sysconfig/iptables",
            "systemctl reload iptables",
        ],
        rollback=(
            "``iptables -F`` flushes the rules (host falls back to no "
            "firewall — DON'T do this on a remote session)."
        ),
    )
    _add(
        lib,
        "D28:nftables_no_rules", SCOPE_LOCAL_CONFIG,
        what="Restore nftables ruleset from /etc/nftables.conf",
        why=(
            "A running nftables with no ruleset accepts every packet. "
            "Restore from the saved config."
        ),
        risk="low",
        commands=[
            "nft -f /etc/nftables.conf",
            "systemctl reload nftables",
        ],
        rollback=(
            "``nft flush ruleset`` removes all rules (host falls back to "
            "no firewall)."
        ),
    )
    _add(
        lib,
        "D28:generic_no_rules", SCOPE_LOCAL_CONFIG,
        what="Populate the firewall ruleset from your baseline config",
        why=(
            "A running firewall with no rules offers zero protection. "
            "Reload the rules from your distro's canonical config file."
        ),
        risk="low",
        commands=[
            "# iptables:",
            "iptables-restore < /etc/sysconfig/iptables",
            "# OR nftables:",
            "nft -f /etc/nftables.conf",
            "# OR CSF:",
            "csf -r",
        ],
        rollback=(
            "Flush: ``iptables -F`` / ``nft flush ruleset`` / ``csf -f`` "
            "(host falls back to no firewall)."
        ),
    )

    return lib


def _add(
    lib: dict,
    finding_key: str,
    scope: str,
    *,
    what: str,
    why: str,
    risk: str,
    commands: list,
    rollback: str,
) -> None:
    """Append a single ``FindingFix`` to ``lib`` under the compound key.

    Internal helper — the four ``rule_*`` modules call ``lookup_fixes``
    to grab every fix for their ``finding_key``, so this builder does
    not have to dedup or sort; it only has to keep the shape stable.
    The ``finding_key`` on the ``FindingFix`` is set so
    ``FindingFix.finding_key`` (the dataclass field) stays consistent
    with the library key — same string, no transformation needed.
    """
    fix = FindingFix(
        finding_key=finding_key,
        what=what,
        why=why,
        scope=scope,
        risk=risk,
        commands=list(commands),
        rollback=rollback,
    )
    lib[_library_key(finding_key, scope)] = fix


def _split_library_key(key: str) -> tuple:
    """Inverse of ``_library_key`` — split a library key back into (finding_key, scope).

    Used by callers that hold a library key and want the (finding_key,
    scope) components — e.g. forensic-JSON writers that emit the key
    next to each fix for machine-readability.
    """
    if "|" not in key:
        # Be loud about malformed keys instead of silently splitting.
        raise ValueError(
            f"malformed FIX_LIBRARY key {key!r}: expected "
            f"'{{finding_key}}|{{scope}}'"
        )
    finding_key, scope = key.rsplit("|", 1)
    return finding_key, scope


# The public catalogue. AISO-215 AC#1: this MUST be
# ``dict[str, FindingFix]``, not a list-of-fixes under a finding-key
# bucket. Built once at import time via ``_build_fix_library``.
FIX_LIBRARY: dict[str, FindingFix] = _build_fix_library()


def lookup_fix(finding_key: str, scope: str) -> FindingFix:
    """Return the single ``FindingFix`` for the exact (finding_key, scope) pair.

    Raises ``KeyError`` when no library entry exists for that pair —
    call-sites that need "every fix for a finding" should use
    :func:`lookup_fixes` instead, which never raises.
    """
    return FIX_LIBRARY[_library_key(finding_key, scope)]


def lookup_fixes(finding_key: str) -> tuple:
    """Return every ``FindingFix`` attached to ``finding_key``, in canonical order.

    Backwards-compatible helper for the rule-layer call-sites (D2, D5,
    D7, D8, D9). Iterates the library once, picks every entry whose key
    starts with ``f"{finding_key}|"``, and returns the fixes sorted by
    ``SCOPE_ORDER`` so the rendering is deterministic.

    Returns an empty tuple when ``finding_key`` is absent from the
    catalogue — silent fallback is intentional so a rule that runs
    against a non-catalogued ``finding_key`` (e.g. a future D10) still
    returns a well-formed finding without a fix attached.
    """
    prefix = f"{finding_key}|"
    scope_index = {s: i for i, s in enumerate(SCOPE_ORDER)}

    def _sort_key(key: str) -> tuple:
        _, scope = _split_library_key(key)
        # Library keys like "D5:weird_methods|waf:cflare" carry a
        # colon-separated sub-scope ("waf:cflare", "waf:modsec"). For
        # sort balancing, fall back to the bare ``waf`` bucket for the
        # index lookup so both D5 WAF fixes land adjacent in the
        # returned tuple (the renderer then orders them by risk).
        primary = scope.split(":", 1)[0]
        return (
            scope_index.get(primary, len(scope_index)),
            scope,
        )

    matched = [
        FIX_LIBRARY[k] for k in FIX_LIBRARY if k.startswith(prefix)
    ]
    matched.sort(key=lambda f: (
        scope_index.get(f.scope.split(":", 1)[0], len(scope_index)),
        f.scope,
        f.risk,
        f.what,
    ))
    return tuple(matched)


def finding_keys() -> tuple:
    """Return the sorted list of distinct finding-keys present in the library.

    AISO-215 shape-regression consumers (tests, ``verify_all.sh``) use
    this to assert the catalogue still covers D2/D5/D7/D8/D9 without
    hardcoding the entry counts.
    """
    seen: set = set()
    for key in FIX_LIBRARY:
        seen.add(_split_library_key(key)[0])
    return tuple(sorted(seen))


def merge_fixes(*lists: Iterable) -> tuple:
    """Combine multiple fix lists, deduping by (scope, what).

    Deduplication key is ``(scope, what)`` — operators reading a finding
    titled "weird methods" should see the Apache fix once even if it
    shows up on the same finding from two call-sites. The richer of
    the two (longer ``commands`` list, longer ``why``) wins, so a
    refined override can replace a template without losing detail.

    NOTE: ``FindingFix`` dataclass is hashable on identity (dataclasses
    without ``eq=False`` compare by ``==`` which compares every field).
    We dedup by the explicit ``(scope, what)`` tuple so two structurally
    identical fixes collapse correctly even when they're distinct
    instances — the way rule-layer overrides typically arrive.
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
    """Sort by (scope-order, risk-order, what) — stable for deterministic output.

    AISO-215 follow-up: sub-scoped library keys (e.g. ``waf:cflare``,
    ``local_config:sudoers_review``) collapse to their primary scope
    (``waf`` / ``local_config``) for the sort index so they land
    adjacent to their bare-scope peers. The full sub-scope string is
    still used as a tiebreaker so the renderer's per-bucket ordering
    stays deterministic. Pre-fix ``sort_fixes`` looked up
    ``fix.scope`` verbatim and put sub-scoped fixes at the bottom of
    the layout — the operator-eye reading order then jumped from
    ``waf:cflare`` (canonical-waf position) to "unknown scope" at the
    end, which broke the cheap-first reading flow.
    """
    scope_index = {s: i for i, s in enumerate(SCOPE_ORDER)}

    def _key(fix):
        # Primary bucket: drop the ``:sub`` tail so sub-scoped fixes
        # sort beside their parent scope. Unknown sub-scope parents
        # (``foo:bar`` for a non-canonical parent) fall through to the
        # unknown-scope bucket at the end.
        primary = fix.scope.split(":", 1)[0]
        return (
            scope_index.get(primary, len(scope_index)),
            fix.scope,
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
