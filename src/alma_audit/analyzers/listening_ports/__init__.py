"""Public API for the listening_ports analyzer.

Audits the host's TCP/UDP listening ports and surfaces service-exposure
findings: MySQL/Postgres/Redis/Memcached/MongoDB on 0.0.0.0, IPv6
dual-stack listeners on critical ports, and unknown high-port public
binds.

Two data sources, picked automatically:

* **Layer A** — `tools/port_audit.sh` writes ``<output>/port-audit.json``
  with the full listener snapshot (process names, PIDs, firewall-engine
  state). The analyzer reads this when present.
* **Layer B** — pure read-only fallback. The analyzer reads
  ``/proc/net/tcp{,6}`` and ``/proc/net/udp{,6}`` through the injected
  ``FileSystem``. No subprocess, no shelling out — the alma-audit
  read-only contract is intact.

Public entry point: ``analyze_listening_ports``.

Layer A path: caller passes the JSON path via ``rules.layer_a_json_path``
(or the default ``<output>/port-audit.json`` resolved by ``runner.py``).
Layer B path: caller passes ``rules.proc_root`` (default ``/proc``) so
the analyzer can locate the socket tables.

Detection rules (per `plans/AISO-220-listening-ports-and-ffirewall-state.md`
§5.1):

*   **D21** CRITICAL — critical service (MySQL/Postgres/Redis/...) bound
    to 0.0.0.0 / :: (public interface).
*   **D22** INFO    — secondary confirmation: ``mysql_bind_address`` in
    ``/etc/my.cnf`` is 0.0.0.0 / ::, pointing the operator at the
    config-file fix path. Suppressed when D21 already fired CRITICAL.
*   **D23** WARN    — IPv6 dual-stack listener on a critical port
    (closing IPv4 only is insufficient).
*   **D24** INFO    — unknown high port bound to a public interface.

Tests live at ``tests/test_listening_ports.py``.
"""
from __future__ import annotations

from .analyzer import analyze_listening_ports
from .aggregator import (
    ListenerSnapshot,
    add_listener,
    finalize,
    new_snapshot,
)
from .parser import parse_layer_a_json, parse_proc_net
from .settings import (
    CRITICAL_PORTS,
    DEFAULT_RULES,
    PORT_SERVICE_MAP,
    PUBLIC_BIND_VALUES,
)

__all__ = [
    "analyze_listening_ports",
    "ListenerSnapshot",
    "add_listener",
    "finalize",
    "new_snapshot",
    "parse_layer_a_json",
    "parse_proc_net",
    "CRITICAL_PORTS",
    "DEFAULT_RULES",
    "PORT_SERVICE_MAP",
    "PUBLIC_BIND_VALUES",
]