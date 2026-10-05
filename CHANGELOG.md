# Changelog

Versions are those in the `VERSION` file (`./harden.sh --version`). The audit script carries
its own version, recorded in every result file.

## Unreleased

- Documentation: `hardening_audit_lynis` is listed with the other settings and in the example
  overrides file.

## 1.0.2 - 2026-10-05

- `--no-lynis` (or `hardening_audit_lynis: false`) audits with the CIS-mapped checks only:
  Lynis is not downloaded, copied to the target or run. A report whose baseline has a Lynis
  index shows the current one as "not run".
- The report shows the CIS Benchmark section of every check in a **CIS** column (open
  findings, accepted risks, manual review and the control-family tables), not only per family.
- Issue and pull request templates, a code of conduct and README badges.

## 1.0.1 - 2026-10-05

First published version. 0.1.0 was an internal milestone and was never released; everything
below is relative to it.

### Safety

- The rollback guard is re-armed at the start of each guarded stage, and a run now fails
  if the guard fired or is not armed when it should be. Before, a slow run could be rolled
  back underneath itself and still report success.
- The rollback now also restores the account databases and the firewall configuration, puts
  back the network kernel parameters recorded before the run, re-enables a firewall that was
  on before, and reports its own errors.
- New preflight checks: the automation account must be named, must not be root, must have a
  UID of 1000 or more (or be in `os_ignore_users`) and a password younger than the maximum
  age being set; the SSH port must not change during a run.
- IP forwarding is kept on any host that already forwards packets, not only where Docker is
  found. Reverse-path filtering is loose on hosts with several default routes.
- A kernel module that is loaded or backs a mounted filesystem is never disabled; `overlay`
  is kept for every common container runtime, including snap Docker and k3s.
- dev-sec no longer deletes users' `.netrc` and `.rhosts` files; the audit reports them.
- With `hardening_tmp_tmpfs`, the tmpfs unit is staged outside systemd's search path and
  installed only immediately before the reboot. Before, systemd could mount it over the live
  `/tmp` in the middle of a run.
- The password-login probe runs only when the SSH stage ran, so `--tags os` and similar
  staged runs no longer end in a rollback.
- The SSH port is always allowed in the firewall, whatever the allow-list says.

### Audit script (1.3.0)

- SSH checks no longer pass when `sshd -T` returns nothing, are evaluated for a remote
  connection rather than for root on loopback, and a new check flags `Match` blocks.
- Fixed false passes: `Defaults !use_pty`; sudoers files that sudo itself ignores; password
  quality read with the wrong file precedence; a conditional DROP taken for a default-drop
  Docker chain; an empty nftables chain taken for a firewall; any file mentioning "aide"
  taken for a schedule; one privileged-command rule taken for all of them.
- Fixed false failures: phased updates counted as missing patches;
  `kernel.unprivileged_bpf_disabled=2`; `pam_wheel` arguments in the other order;
  `MaxStartups` given as one number; nftables or firewalld hosts reported as having no rules.
- New checks: per-interface redirect, source-route and RA settings (NET-33) and `Match`
  blocks (SSH-25). The role enforces the per-interface settings.
- "No updates pending" is no longer reported against a package index older than two days.
- The audit refuses to run on anything that is not Ubuntu.

### Wrapper and reports

- Adding a host to an inventory no longer overwrites the baselines of the other hosts.
- `--rebaseline` archives the host's old audits instead of producing an inverted comparison.
- `--fail-on-regression` now really exits 3, including for a check that passed before and is
  no longer reported at all. A regression on one host and a failure on another are both
  reported.
- One unreachable host no longer prevents reports for the others.
- `-i` accepts the inventory directory, relative to where the command is typed.
- Text from the audited host is escaped everywhere in the HTML report and the Markdown
  summary; malformed audit files and exception registers are refused with a clear message.
- Audit history per host, drift since the previous audit, a fleet index, and an
  accepted-risk register (`exceptions.yml`) with owner and expiry.
- `./harden.sh revert <family>...`, `--version`, documented exit codes.

### Other

- Packages that later stages depend on (AIDE and what it brings with it) are installed before
  the hardening stages, so a first run no longer leaves setuid clean-up and audit rules for a
  second one.

- `hardening_profile: pci`, optional TLS log forwarding, optional filter for Docker-published
  ports, AIDE rebuilt only when the run changed something, audit rules for 64-bit ARM.
- `revert pam` followed by a new apply now restores lockout and password quality.
- Collections `ansible.posix` and `community.general` are pinned.
- Tests for the report generator and for the wrapper; CI runs them with the linters.
  `tests/e2e.sh` runs the whole cycle, including revert, against a disposable host.

### Known issues

- AIDE 0.19 still walks a tree that is excluded from its database, so a very large or slow
  excluded tree makes a rebuild slow.
- On Ubuntu 22.04 the AIDE packages install postfix. It is restricted to loopback, not
  removed.
- A log file that a service recreates at boot with loose permissions (for example VirtualBox
  Guest Additions) shows up again in the audit after a reboot.

### Tested

By hand, on freshly created x86-64 virtual machines of Ubuntu 26.04, 24.04 and 22.04: baseline
audit, hardening, reboot, re-audit, a second run, revert of all 14 families, a drift audit and
re-hardening. Also: the audit's refusal to run on Debian and AlmaLinux, TLS log forwarding
against a TLS listener, the Docker port filter, the `pci` profile, and a deliberately fired
rollback.

## 0.1.0

Internal milestone, not released: the first working audit, hardening playbooks and report.
