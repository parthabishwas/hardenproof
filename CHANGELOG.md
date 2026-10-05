# Changelog

## 0.1.0

First public release.

- CIS-mapped, read-only audit for Ubuntu (264 checks with evidence) plus a pinned Lynis run.
- Guarded hardening: dev-sec OS and SSH roles with documented overrides, and a gap-closing
  role for audit rules, AIDE, firewall, password policy, su, banners, cron and mounts.
- Preflight checks, `/etc` backup and a rollback guard that restores SSH, PAM, sudo and the
  firewall when a run cannot prove it still has access.
- Host traits are detected rather than assumed: Docker, sudo-rs, a dedicated audit
  filesystem, IPv6 in use, IPv6 routes from router advertisements.
- Self-contained HTML report per host with a before/after check map, history across audits,
  drift since the previous audit, and a fleet index.
- Accepted-risk register (`exceptions.yml`) with owner and expiry.
- `--fail-on-regression` for scheduled audits.
- Per-family revert playbook.
- Compliance profile switch (`cis`, `pci`), optional TLS log forwarding, optional filter for
  Docker-published ports.

Tested end to end on Ubuntu 26.04, 24.04 and 22.04 virtual machines: baseline audit, hardening,
reboot, re-audit and a second run on a freshly created VM of each release.
