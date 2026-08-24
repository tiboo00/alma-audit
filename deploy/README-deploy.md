# Deployment notes for alma-audit

## Install (systemd timer path)

```bash
# 1. Install the package system-wide.
sudo pip install /path/to/almalinux-whmcs-cpanel-security-audit

# 2. Copy sample config + service files.
sudo mkdir -p /etc/alma-audit
sudo cp examples/config.yaml /etc/alma-audit/config.yaml
sudo cp examples/alma-audit.service /etc/systemd/system/
sudo cp examples/alma-audit.timer /etc/systemd/system/

# 3. Ensure the output dir exists and is writable by root.
sudo mkdir -p /var/log/alma-audit
sudo chmod 750 /var/log/alma-audit

# 4. Enable + start the timer.
sudo systemctl daemon-reload
sudo systemctl enable --now alma-audit.timer

# 5. Inspect what runs / what has run.
systemctl list-timers alma-audit.timer
journalctl -u alma-audit.service -n 50
```

## Install (pure-cron path)

If you prefer cron over systemd timers, drop this into `/etc/cron.d/alma-audit`:

```
15 4 * * * root /usr/local/bin/alma-audit --output /var/log/alma-audit \
    >> /var/log/alma-audit/cron.log 2>&1
```

The toolkit exits non-zero when any WARN/CRITICAL finding is present —
wrap with `|| mail -s "alma-audit on $(hostname)" root@example.invalid`
to get a fail-loud notification.

## Where reports land

Both reports are written to `<output>`:

- `alma-audit-latest.json` — machine-readable, for downstream pipelines.
- `alma-audit-latest.md`   — human-readable, for the operator.

Each run *overwrites* the previous file. If you want history, add a
post-rotate step that copies them into a date-stamped directory.

## Read-only contract — what the toolkit does NOT do

- It does NOT write to source log files (only to the two report files).
- It does NOT modify firewall / fail2ban / cPanel / WHMCS state.
- It does NOT spawn subprocesses (`os.system`, `subprocess.run` etc.).
- It does NOT contact any external service. Reports are local-only.

The systemd unit reinforces this with `ReadOnlyPaths` and `ProtectSystem=strict`.
