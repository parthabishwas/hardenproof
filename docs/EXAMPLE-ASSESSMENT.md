# Example assessment - Ubuntu 26.04 LTS lab VM

| | |
|---|---|
| Target | `server` - Ubuntu 26.04 LTS, kernel 7.0.0-34, VirtualBox guest (NAT, host port 2222 -> 22), Docker installed |
| Date | 2026-10-01 |
| Benchmark | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0 structure, Level 1 Server (Level 2 reported separately) |
| Cross-reference | ISO/IEC 27001:2022 Annex A, PCI DSS v4.0.1 (control-family level) |
| Tools | `audit/cis_audit.sh` (264 checks, this repo), Lynis 3.1.7, dev-sec `devsec.hardening` 10.6.0, `roles/hardening_extras` (this repo) |

> A worked example: the assessment HardenProof produced for a disposable lab VM, written for
> that VM's owner. The account name and addresses are placeholders. The raw evidence it
> refers to (audit output, run logs, the HTML report) is per-host data and is not published.

## 1. Result

| Measure | Baseline | After hardening |
|---|---|---|
| CIS Level 1 checks passing | 103 of 185 (**55.7%**) | 181 of 183 (**98.9%**) |
| CIS Level 2 checks passing | 5 of 40 (12.5%) | 31 of 39 (79.5%) |
| Additional (non-CIS) checks passing | 5 of 11 | 9 of 11 |
| Lynis hardening index | 65 | 82 |
| Lynis suggestions | 41 | 22 |

108 checks moved from FAIL to PASS, none regressed, and 12 remain open. The system was
rebooted after hardening and came back with SSH, sudo, Docker networking and apt working.

**The VM is not "secure" on the strength of these numbers.** Three of the twelve open items
matter more than the hundred that closed:

1. **The `admin` password is still trivially guessable** (it is in a 17-word dictionary).
   I did not change it - that is your credential. SSH no longer accepts passwords, so it is
   no longer remotely exploitable, but it is still the sudo password and the console
   password. Run `passwd` (the new policy requires 14+ characters).
2. **Logs and the audit trail exist only on the VM.** Whoever gets root can erase them.
3. **A directory of the hypervisor host is mounted read-write inside the VM** (a VirtualBox
   shared folder). Root in the guest can read and modify host files.

Scores are derived from the audit files by `tools/report.py`; the full per-check list with
evidence is in the generated HTML report (`reports/<host>/latest/report.html`).

## 2. Scope, benchmark and limits

- **Why CIS 24.04 and not 26.04:** ComplianceAsCode 0.1.82 has an `ubuntu2604` product but
  only a default profile, no CIS profile, so OpenSCAP could not be used and I did not find a
  published 26.04 benchmark to map to. The checks follow the 24.04 benchmark's sections.
  **Section numbers in this report are section-level; confirm exact recommendation IDs
  against the licensed CIS PDF before quoting them to an auditor.**
- **This is a configuration assessment, not a certification.** ISO 27001 and PCI DSS are
  management-system and scope-wide standards; a hardened host is evidence for a handful of
  their controls (section 8), nothing more. HIPAA was not mapped - its Security Rule is not
  prescriptive at host level and maps through the same technical controls.
- **Out of scope:** application and container hardening (Docker daemon config, images),
  network architecture, backup, vulnerability scanning of installed packages (CVE level).
- **Audit script versions:** the baseline was recorded with v1.0.0, the final audit with
  v1.1.1. The difference is three check corrections found during the work, not remediation:
  SUDO-03 and AUD-12 became N/A (sudo-rs cannot have a sudo log file) and the
  session/login audit-rule checks accept the paths that exist on 26.04.

## 3. How the tools were used

| Tool | Role here | What it does not give you |
|---|---|---|
| Lynis | Independent audit before and after | No benchmark mapping; the index is a heuristic |
| dev-sec `os_hardening`, `ssh_hardening` | Remediation engine for sysctl, mounts, PAM lockout, accounts, auditd install, sshd | No audit rules, AIDE, firewall rules, pwquality/history, su restriction, banners, cron allow-list; several defaults are harmful on this host (section 6) |
| `audit/cis_audit.sh` | CIS-mapped PASS/FAIL with evidence, read-only | Ubuntu only |
| `roles/hardening_extras` | Closes the CIS gaps dev-sec leaves | - |

They are not alternatives: dev-sec changes, Lynis and the audit script measure. The workflow
is audit -> decide -> dry run -> guarded apply -> re-audit -> accept residual risk
(see [`../README.md`](../README.md)).

## 4. Baseline findings, by risk

| Risk | Finding | Evidence (baseline) |
|---|---|---|
| Critical | Guessable password + SSH password authentication + no lockout, on an account with full sudo and `docker`/`lxd` membership (both root-equivalent). The SSH port is forwarded to the host's LAN address. | ACCT-16, SSH-23, PAM-02/05, SUDO-08 |
| High | No host firewall: every listener is reachable; forward policy mixed | FW-01..05 |
| High | No audit trail, no file-integrity monitoring, logs not forwarded | AUD-*, AIDE-*, LOG-06 |
| High | Host directory shared read-write into the guest | ENV-01 |
| Medium | 39 pending package updates | PKG-01 |
| Medium | No password policy: no quality, history, ageing; `nullok` permits empty passwords | PAM-*, ACCT-01/02/06 |
| Medium | SSH: forwarding on, SHA-1/64-bit MACs offered, root login `prohibit-password`, no idle timeout, no user allow-list | SSH-04/07/08/15/20 |
| Medium | Network stack accepts/sends ICMP redirects, accepts IPv6 RAs, loose rp_filter | NET-12..32 |
| Medium | Core dumps, apport and kdump enabled (memory contents written to disk) | PROC-03/05/11 |
| Low | Cron files world-readable, no cron allow-list; telnet and ftp clients installed; OS version in banners; unused filesystem/protocol modules loadable; `/tmp` and `/dev/shm` executable | CRON-*, CLI-*, BAN-*, FS-*, NET-05..07 |

Already good at baseline, unchanged: AppArmor enforcing, chrony, no legacy network services,
passwd/shadow permissions, no duplicate or unowned accounts/files, yescrypt hashing,
unattended security upgrades.

## 5. What was changed, why, and what it costs

One row per control family. The full reasoning - threat, operational impact, validation
command, rollback - is in [`../controls/catalogue.yml`](../controls/catalogue.yml).

| Family | Change | Benefit | Operational impact to expect |
|---|---|---|---|
| SSH | Keys only, no root, `AllowUsers admin`, modern crypto only, MaxAuthTries 4, idle timeout, no forwarding, banner | Removes password guessing and pivoting through the host | **Password logins stop.** `ssh -L/-R/-D`, ProxyJump through this host, VS Code Remote and X11 no longer work. Users outside AllowUsers are refused |
| Firewall | ufw: deny inbound except 22/tcp, deny routed | Unreviewed listeners are unreachable | Any new service needs an entry in `hardening_fw_allow`. Docker-published ports bypass ufw |
| PAM | pwquality (14 chars, 3 classes, dictionary), history 24, lockout 5 tries / 15 min incl. root, no `nullok` | Stops weak passwords being set and online guessing | Applies at next password change only. Lockout can be used to deny service to an account |
| Accounts | Max age 365, min 1, inactive 45, umask 027, `TMOUT=900`, system accounts nologin, homes 0700 | Bounds credential lifetime, private files by default | Idle shells are killed; software expecting world-readable output breaks; service accounts under UID 1000 lose their shell |
| sudo / su | `use_pty`, 15-min cache, su limited to an empty group | Privilege changes are attributable via sudo | `su - user` stops working for non-root; use `sudo -iu` |
| Kernel / process | Core dumps off, apport and kdump masked, kptr/dmesg restricted, ptrace_scope 2, unprivileged BPF and user namespaces off, kexec off | Removes local privilege-escalation primitives and memory-to-disk leaks | No crash dumps; `gdb -p`/`strace -p` need root; rootless containers and bubblewrap sandboxes break |
| Network sysctl | No redirects, no source routing, strict rp_filter, martian logging, no IPv6 RA | Host cannot be re-routed by an on-link attacker | Asymmetric routing on multi-homed hosts breaks; SLAAC-only IPv6 stops |
| Mounts | `noexec` on `/tmp` and `/dev/shm`; apt temp dir moved | No execute from world-writable tmpfs | Installers/JVMs that execute from `/tmp` fail |
| Kernel modules | 11 unused filesystem/protocol modules + usb-storage disabled | Less reachable kernel code; no USB mass storage | USB/virtual-media rescue needs the entry removed first |
| Audit | auditd + 71 rules, `audit=1`, immutable | Kernel-level record of who did what | Disk and CPU cost; rule changes need a reboot |
| AIDE | Baseline database + daily check | Detects modified binaries/config | Every patch run shows as drift until re-baselined |
| Logging | Journal persistent and compressed; log files not world-readable | Logs survive reboot; local users cannot read them | - |
| Patching | 39 updates applied | - | Reboot was required and done |
| Services | 12 hardware/desktop helper units masked (lab only) | Less root-run code parsing untrusted input | Lab-specific list; not a production default |
| Cron, banners, clients | Root-only cron + allow-list; legal banner; telnet/ftp removed | Hygiene | Non-root crontab users must be allow-listed |

## 6. Where a blind run would have hurt

These are the reasons the upstream roles were not applied with defaults. Each is handled in
`playbooks/group_vars/all/baseline.yml` or the extras role, with the reason next to it.

| # | What would have happened | What was done instead |
|---|---|---|
| 1 | dev-sec `ssh_hardening` disables password auth by default. The VM had **no authorized key** - immediate lockout | Key installed and key login proven before the SSH stage; playbook asserts it |
| 2 | dev-sec sets `net.ipv4.ip_forward=0` - **Docker networking breaks** | Docker detected -> forwarding kept, recorded as an exception; container egress tested |
| 3 | dev-sec chroots sftp to `/home/%u`; homes are user-owned -> **every sftp/scp session fails** | `sftp_chroot: false` |
| 4 | dev-sec's `login.defs` template sets `ENCRYPT_METHOD SHA512` - a **downgrade from yescrypt** | Template disabled; four lines edited in place |
| 5 | dev-sec mounts `/proc` with `hidepid=2`, unsupported by systemd (logind/polkit) | `hidepid=0` |
| 6 | dev-sec password max age 60 days and `MaxAuthTries 2` | 365 days; 4 tries |
| 7 | dev-sec sets `/var/log` to 0755 root:root on Ubuntu (it resolves variables by OS *family*); rsyslog runs as `syslog` and needs 0775 root:syslog | Overridden; found by the idempotency run |
| 8 | dev-sec `kexec_load_disabled=1` with kdump-tools enabled -> kdump silently broken | kdump masked deliberately (it also writes RAM to disk) |
| 9 | CIS says add `Defaults logfile=` to sudoers. **Ubuntu 26.04's sudo is sudo-rs, which treats that line as a syntax error** | Role detects sudo-rs, omits the line, validates with the active `visudo` |
| 10 | CIS audit-log settings (`keep_logs`, `single`/`halt` when full) on a single root filesystem -> the VM takes itself offline when `/` fills | Bounded rotation in the lab; two CIS items knowingly left failing |
| 11 | Installing AIDE pulled in **postfix listening on 0.0.0.0:25** via `Recommends` | Caught by the re-audit as a regression; `install_recommends: false`; postfix removed |
| 12 | `noexec` on `/tmp` breaks `dpkg-preconfigure` | apt extract dir moved; package reinstall tested |
| 13 | Ansible cannot escalate through sudo-rs (prompt format) | `ansible_become_exe: sudo.ws` in the inventory |

Item 11 is the important one: the remediation itself introduced an exposed service, and
only the after-audit showed it. Auditing after every change is not optional.

## 7. Open findings and residual risk

| ID | Lvl | Finding | Recommendation | Owner decision |
|---|---|---|---|---|
| ACCT-16 | - | `admin` password is trivially guessable | Change it now (`passwd`) | **Do** |
| ENV-01 | - | Host directory shared read-write into the guest | Remove the shared folder, or make it read-only and narrow | **Do** before putting anything untrusted on the VM |
| LOG-06 | L1 | No remote log forwarding | Set `hardening_syslog_remote_host`; use TLS/RELP in production | Needs a collector |
| BOOT-01 | L1 | No GRUB password | Accept for VMs where hypervisor console access is controlled; otherwise set it in the image with `--unrestricted` on the default entry | Accept / image |
| FS-14/16/18/20/22 | L2 | `/home`, `/var`, `/var/tmp`, `/var/log`, `/var/log/audit` are not separate filesystems | Cannot be retrofitted online. Put an LVM layout in the installer/image | Image |
| AUD-05, AUD-06 | L2 | Audit logs rotate; no halt when full | Switch to the baseline values once `/var/log/audit` is its own filesystem | Follows from above |
| MAC-04 | L2 | 2 AppArmor profiles in complain mode | Review each, then `aa-enforce` | Low |

Not failures, but need a human (MANUAL rows):

- **Docker-published ports bypass ufw** (FW-06). Host ports 80/443/8090 are already forwarded
  to this VM by VirtualBox; the moment a container publishes them they are reachable
  regardless of ufw. Bind to `127.0.0.1` or filter in the `DOCKER-USER` chain.
- **`docker` and `lxd` group membership is root-equivalent** (SUDO-08). `admin` is in both;
  that bypasses sudo, its password and its logging.
- **cloud-init is installed** on a non-cloud VM (ENV-02). Its sshd drop-in re-enabling
  passwords is now ignored, but the package can be purged.
- Third-party apt sources (docker, nodesource) and the 22 SUID/SGID binaries are listed in
  the summary for review (PKG-02, PERM-13).
- Lynis' remaining 22 suggestions are mostly the same partition/GRUB/remote-log items plus
  optional extras (process accounting, malware scanner, debsums, restricting compilers).

Residual risks no host benchmark addresses: AIDE's database and the audit logs live on the
host they protect; `noexec` and module blacklists are speed bumps for an attacker who is
already root; the kernel is only as current as the last reboot.

## 8. Standards cross-reference

| Family | CIS 24.04 section | ISO 27001:2022 Annex A | PCI DSS v4.0.1 | State |
|---|---|---|---|---|
| Patching | 1.2 | A.8.8, A.8.19 | 6.3.3 | Pass |
| Secure configuration (modules, sysctl, mounts, services) | 1.1, 1.5, 2, 3 | A.8.9 | 2.2.1, 2.2.4, 2.2.5, 2.2.6 | Pass, partitioning open |
| Host firewall | 4 | A.8.20, A.8.21, A.8.22 | 1.2.5, 1.3.1, 1.4.1 | Pass, Docker ports manual |
| Remote administration | 5.1 | A.8.5, A.8.24 | 2.2.7, 8.2.8 | Pass |
| Privileged access | 5.2 | A.8.2, A.8.18, A.5.18 | 7.2.1, 10.2.1.2 | Pass, docker group manual |
| Authentication | 5.3, 5.4 | A.5.17, A.8.5 | 8.3.4, 8.3.6, 8.3.7, 8.3.9 | Policy pass; existing weak password open |
| Logging and audit | 6.1, 6.2 | A.8.15, A.8.16 | 10.2, 10.3, 10.5 | Local pass; **central logging (10.3.3) open** |
| Time | 2.3 | A.8.17 | 10.6 | Pass |
| File integrity | 6.3 | A.8.16 | 11.5.2 | Pass |
| Access to system files | 7.1, 7.2 | A.8.3, A.5.15 | 7.2 | Pass |

PCI DSS note: the policy here uses a 365-day password maximum. PCI 8.3.9 requires 90 days
where passwords are the only factor; set `os_auth_pw_max_age: 90` in that scope. PCI 8.3.4 also asks for a
lockout of at least 30 minutes; the applied 15 minutes meets CIS only, so set
`os_auth_lockout_time: 1800` there. Per-setting justification and references:
[`RATIONALE.md`](RATIONALE.md).

## 9. Validation performed

| Test | Result |
|---|---|
| New SSH session with key after the SSH stage | OK |
| SSH with password | `Permission denied (publickey)` |
| sudo through the new PAM stack | OK (both sudo-rs and sudo.ws parse sudoers) |
| Reboot | Came back; `audit=1 audit_backlog_limit=8192` on the kernel command line; no reboot pending |
| Execute a binary from `/tmp` | Permission denied |
| `apt-get install --reinstall tzdata` with noexec `/tmp` | OK |
| Docker: pull image, container reaches the internet | OK |
| Audit rules | 71 loaded, `enabled 2` (immutable), 0 lost events |
| Listening sockets | 22/tcp and the loopback resolver only |
| Failed units | `vboxadd.service` only - **pre-existing**: it failed identically on the boot before any change (Guest Additions 7.2.6 does not build on kernel 7.0) |
| Idempotency | Final re-run (`harden-run5-idempotency.log`): 4 changed tasks, all bookkeeping (new backup, arm and disarm the guard). An earlier re-run exposed three non-idempotent tasks (module list ordering, `/var/log` mode, a setuid bit from a since-removed package), which were fixed |
| Rollback guard, fired deliberately | Timer ran `rollback.sh`: PAM/sudoers/sshd restored, ufw disabled, SSH reachable; hardening then re-applied |
| First apply, failure mid-run | Run 1 stopped in the PAM stage (missing directory) with the guard still armed; fixed and re-run - the guard behaved as designed |

Run logs and the controller log are kept under `reports/_logs/`.

## 10. State of the VM and how to undo it

- **Log in:** `ssh -i <automation key> -p 2222 admin@192.0.2.10`. Password SSH is
  off; the console still takes the password. Add your own public key to
  `~admin/.ssh/authorized_keys` through that session.
- **Full undo:** VirtualBox snapshot `pre-hardening-2026-10-01` (taken live before the first
  change): `VBoxManage controlvm <vm> poweroff; VBoxManage snapshot <vm> restore pre-hardening-2026-10-01`.
- **Partial undo:** `/var/backups/hardening/20261001T044232/etc.tar.gz` is the pristine
  `/etc`; `/var/backups/hardening/rollback.sh` restores the access path from the latest run.
- **Left on the VM by the audit:** `/opt/lynis-3.1.7`, `/var/lib/hardening-audit/`,
  `/var/log/lynis*`.

## 11. Before using this on production

1. Give the benchmark a home: get the CIS PDF for the target release and reconcile the
   check IDs; add RHEL-family support to the audit script if needed.
2. Build partitioning, GRUB password and disk encryption into the image.
3. Stand up central logging first; LOG-06 is the highest-value open control.
4. Fill in the per-environment inventory (allowed SSH users, firewall ports, service
   accounts to ignore, cron users, units to disable) from the application owners.
5. Apply to a clone, run the application's tests, then roll out in rings with console
   access confirmed.
6. Schedule `audit.yml`, keep the results in git, and treat a regression as an incident.
