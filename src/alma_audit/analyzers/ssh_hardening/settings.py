"""Defaults for the ssh_hardening analyzer.

The ssh_hardening analyzer inspects ``/etc/ssh/sshd_config`` (and the
``sshd_config.d/*.conf`` drop-ins) and flags weak settings. Operators
override the threshold / pattern list via the YAML config
(``modules.ssh_hardening.*``). The single source of truth for the
defaults lives here so a ``grep default_settings`` finds every tunable
in one place.
"""

from __future__ import annotations

from typing import Any


# Path of the SSH daemon config file. The drop-ins directory lives next
# to it (``/etc/ssh/sshd_config.d/``) and is auto-discovered by the
# analyzer. Both are overridable via the YAML config and the CLI
# (``--ssh-config PATH``).
DEFAULT_SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"
DEFAULT_SSHD_DROP_IN_DIR = "/etc/ssh/sshd_config.d"

# Default rule thresholds. All are YAML-tunable via
# ``modules.ssh_hardening.*``.
DEFAULT_RULES: dict[str, Any] = {
    # ``MaxAuthTries`` greater than this is a WARN. 6 matches the
    # OpenSSH default and is the CIS Benchmark upper bound for the
    # ``SSH MaxAuthTries`` rule.
    "max_auth_tries_warn": 6,
    # ``LoginGraceTime`` (seconds) greater than this is a WARN. 120s
    # is the OpenSSH default and is the CIS Benchmark upper bound.
    "login_grace_time_warn": 120,
}


# Algorithms considered weak for the ``Ciphers`` / ``MACs`` lists.
# Emitted as a single WARN finding listing the offenders (per
# acceptance criterion 3 / WARN for weak Ciphers/MACs).
WEAK_CIPHERS: set[str] = {
    "3des-cbc",
    "blowfish-cbc",
    "cast128-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "rijndael-cbc@lysator.liu.se",
}
WEAK_MACS: set[str] = {
    "hmac-md5",
    "hmac-md5-96",
    "hmac-ripemd160",
    "hmac-sha1-96",
    "umac-64@openssh.com",
}


# Keys whose first token is a known sshd keyword (we only classify
# these). The parser strips ``Match`` blocks entirely — sshd
# ``Match`` directives can re-define most of these keywords on a
# per-user / per-group basis, and the analyzer's contract is the
# top-level config posture, not per-user overrides.
_KNOWN_DIRECTIVES: set[str] = {
    "PermitRootLogin",
    "PermitEmptyPasswords",
    "Protocol",
    "PasswordAuthentication",
    "PubkeyAuthentication",
    "Port",
    "MaxAuthTries",
    "ClientAliveInterval",
    "ClientAliveCountMax",
    "LoginGraceTime",
    "AllowUsers",
    "AllowGroups",
    "DenyUsers",
    "DenyGroups",
    "X11Forwarding",
    "Banner",
    "Ciphers",
    "MACs",
    "KexAlgorithms",
    "PermitUserEnvironment",
    "UsePAM",
    "ChallengeResponseAuthentication",
    "KerberosAuthentication",
    "GSSAPIAuthentication",
    "HostbasedAuthentication",
    "IgnoreRhosts",
    "PrintMotd",
    "TCPKeepAlive",
    "Compression",
    "UseDNS",
    "AcceptEnv",
    "Subsystem",
    "Include",
}
