# LogWarden — Engineering Report

## Overview

**Project:** LogWarden
**Version:** 1.0
**Author:** Sideways 8 Security Research
**Category:** Log Analysis / Intrusion Detection

LogWarden scans auth logs (SSH, sudo, system auth) for failed login attempts, brute-force patterns, suspicious IPs, and user enumeration. Designed for server admins and SOC analysts who need rapid log triage without standing up a full SIEM pipeline.

---

## Tech Stack

### Language: Python 3.10+

Stdlib everywhere. Log parsing is regex-based and CPU-bound only on very large files (million+ lines). Python's `re` module is fast enough for real-time analysis of typical auth.log sizes.

### Data structures: `collections.Counter` + `defaultdict` (stdlib)

Counter for IP frequency analysis, defaultdict for grouping by username/IP/event type. Both are memory-efficient for the typical data volume (thousands of unique IPs in a log file).

### Output: JSON (stdlib)

Machine-readable output for integration with other tools. The `--summary` flag also prints a human-readable table.

---

## Architecture Decisions

### Why regex over structured parsing?

Auth log formats vary significantly between distributions (Debian vs RHEL vs FreeBSD), SSH implementations (OpenSSH vs Dropbear), and configurations (with/without auditd). Regex catches the common patterns across variants without needing format-specific parsers for each distribution.

### Detection heuristics

- **Rate-based:** > 5 failed attempts from a single IP in 60 seconds = brute-force
- **User-based:** "Invalid user" messages indicate user enumeration scanning
- **Spread-based:** same IP hitting multiple usernames = dictionary attack
- **Timing-based:** connections at 3 AM with no prior history = suspicious

Each heuristic is independently weighted and reported. No ML, no probabilistic models — deterministic rules that a human can audit.

### Summary-first, detail-second output

The default output is a one-screen summary (top IPs, top usernames, time window). The `--verbose` flag dumps every event. This matches the real-world workflow: triage from the summary, drill down on detail.

---

## File Structure

```
LogWarden/
├── logwarden.py         # Log parser and analyzer
├── README.md            # Usage and examples
├── LICENSE              # MIT
├── requirements.txt     # (no external deps)
├── tests/
│   └── test_logwarden.py
└── docs/
    └── engineering-report.md
```

---

## Limitations

1. **auth.log only** — currently parses `/var/log/auth.log` and syslog-format files. Windows Event Log, macOS unified logs, and journalctl-binary formats are not supported.
2. **Regex fragility** — log format variations between distributions can cause missed events. Custom logrotate configurations may change the path.
3. **No IP reputation** — there is no GeoIP or threat intel enrichment. Every IP that appears in the log is treated equally.
4. **No real-time monitoring** — it's a static file analyzer. For real-time alerting, pair with `tail -F` and cron.

---

## Future Work

- Add GeoIP lookup (MaxMind GeoLite2) for origin-country analysis.
- Support for Windows Event Log XML format.
- Add journalctl (`journalctl _COMM=sshd`) integration for systemd-based systems.
- Implement correlation rules (e.g., "SSH brute-force followed by successful login = compromised").
- Add alerting hooks (webhook, email, Slack).
