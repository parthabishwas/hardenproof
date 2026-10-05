# Hardening rationale

Why each setting HardenProof applies has the value it has: what it replaces, why that value
and not another, what it costs you, and the source it rests on.

The values described here are the **baseline defaults** shipped in
[`playbooks/group_vars/all/baseline.yml`](../playbooks/group_vars/all/baseline.yml) and
[`roles/hardening_extras/defaults/main.yml`](../roles/hardening_extras/defaults/main.yml).
Your environment may override any of them; section 12 says where and how to record that.

**How to read the references.** `[CIS x.y]` is a section of the CIS Ubuntu Linux 24.04 LTS
Benchmark v1.0.0. These are section pointers, not recommendation numbers: confirm the exact
number and wording in the licensed document before quoting one. `[R..]` entries are listed in
section 13. Where a choice is engineering judgement rather than something a standard says,
it is labelled **Judgement**.

---

## 1. Should the SSH port be changed?

A common first question, and a good example of how the baseline was decided.

**No. The baseline keeps sshd on port 22.**

| Argument | Detail |
|---|---|
| No benchmark asks for it | Neither CIS [CIS 5.1], the dev-sec SSH baseline [R14] nor PCI DSS [R17] lists a non-default port as a control. An auditor gives no credit for it. |
| It is obscurity, not a control | NIST's server-security guide lists *open design* as a principle: security should not depend on the secrecy of the implementation [R2]. A full TCP scan finds a moved sshd in seconds, and internet scanners index non-standard ports. |
| What it does buy is already bought | Moving the port reduces bot noise in the logs. With the baseline applied bots cannot succeed anyway: passwords are off, `MaxAuthTries 4`, `MaxStartups 10:30:60`, and current OpenSSH penalises abusive sources by default (`PerSourcePenalties`) [R6]. |
| It has costs | Every client config, firewall rule, monitoring check and automation inventory needs the exception. On ports above 1023 an unprivileged local process can bind the port if sshd is down. On RHEL-family systems SELinux must be told about the new port. |
| The effective alternative exists | Restrict *who can reach* the port: a source address in `hardening_fw_allow`, or a bastion or VPN. That removes the exposure instead of relocating it. |

When changing it is reasonable: an internet-facing host where log noise is a real operational
problem and source restriction is impossible. Set `hardening_ssh_port` and the matching
`hardening_fw_allow` entry; the preflight refuses to run if the two disagree. **Judgement:**
treat it as noise reduction, never as a mitigation.

---

## 2. Why these tools and this benchmark

| Choice | Why this one | Why not the alternative |
|---|---|---|
| CIS benchmark as the yardstick | Prescriptive, per-distribution, each item has an audit and a remediation, and PCI DSS names it as an example of an industry-accepted hardening standard (req. 2.2.1) [R1][R17] | ISO 27001 and HIPAA say *that* systems must be securely configured, not *how*; they need a technical baseline underneath [R18] |
| CIS 24.04 structure, also on newer releases | It is the nearest published benchmark where none exists yet for the release in use | Waiting for a new benchmark leaves hosts unhardened in the meantime |
| Level 1 as the target, Level 2 reported | Level 1 is meant to be applicable to most systems without breaking function; Level 2 trades usability for depth [R1] | Blanket Level 2 needs partitioning and audit-log behaviour many hosts cannot support (section 9) |
| dev-sec for remediation | Maintained, tested per distribution, idempotent, widely used [R13][R15] | Hand-written shell is not idempotent or reviewable; CIS's own build kits are members-only |
| Lynis for a second audit | Independent of the remediation code, so it catches what the remediation's authors did not think of [R16] | Auditing with the same logic that made the changes proves only that the code ran |
| Own audit script and extras role | dev-sec is not CIS and leaves gaps (audit rules, AIDE, firewall rules, password quality, `su`, banners); Lynis has no benchmark mapping | - |
| Ansible | Declarative, `--check --diff` shows changes before they happen, the playbook is the audit record | - |

---

## 3. SSH server

Ubuntu's default allows password login, root login with a key, all forwarding, and offers
SHA-1 and 64-bit MACs.

| Setting | Baseline | Why this value | Reference |
|---|---|---|---|
| `PasswordAuthentication` | `no` (keys only) | Removes online password guessing entirely. Not a CIS item: **Judgement**, and the dev-sec default | [R14][R19] |
| `PermitRootLogin` | `no` | Forces a named account plus sudo, so actions are attributable. The default `prohibit-password` still allows direct root with a key | [CIS 5.1][R6] |
| `AllowUsers` | your list (`hardening_ssh_allow_users`) | Default-deny for logins: a new or service account cannot be used over SSH until someone adds it | [CIS 5.1] |
| `MaxAuthTries` | `4` | CIS ceiling. dev-sec's default of 2 fails honest users whose agent offers several keys before the right one. **Judgement** to use 4 | [CIS 5.1] |
| `LoginGraceTime` | `30` | CIS allows up to 60 s; shorter frees unauthenticated connection slots sooner | [CIS 5.1] |
| `MaxStartups` | `10:30:60` | Limits unauthenticated concurrent connections (connection-exhaustion DoS) | [CIS 5.1][R6] |
| `MaxSessions` | `10` | CIS ceiling | [CIS 5.1] |
| `ClientAliveInterval` / `CountMax` | `300` / `3` | Drops dead or abandoned sessions after about 15 minutes; PCI requires re-authentication after 15 idle minutes | [CIS 5.1][R17] 8.2.8 |
| `AllowTcpForwarding`, `AllowAgentForwarding`, `X11Forwarding`, `PermitTunnel` | `no` | A foothold on the host cannot be used to tunnel into the networks it can reach; agent forwarding exposes the user's keys to root on the host | [CIS 5.1][R19] |
| `Ciphers` | chacha20-poly1305, aes-gcm, aes-ctr | No CBC, 3DES or arcfour | [CIS 5.1][R19] |
| `MACs` | sha2-512/256 (etm first), umac-128-etm | Drops SHA-1 and 64-bit-tag MACs | [CIS 5.1] |
| `KexAlgorithms` | sntrup761x25519, curve25519, dh-gex-sha256 | No SHA-1 key exchange, no fixed small DH groups | [CIS 5.1] |
| `LogLevel` | `VERBOSE` | Logs the fingerprint of the key used, so a login can be tied to a specific key | [CIS 5.1][R19] |
| `Banner` | `/etc/issue.net` | Legal notice before authentication, no OS version | [CIS 1.6, 5.1] |
| `Compression`, `UseDNS` | `no` | Smaller pre-auth attack surface; no dependence on reverse DNS | [R14] |
| `ListenAddress` | IPv4, plus IPv6 where the host has a global IPv6 address | dev-sec listens on IPv4 only, which locks out anyone reaching the host over IPv6. **Judgement** | [R6] |
| `Port` | `22` | See section 1 | - |
| sftp subsystem | `internal-sftp`, no chroot | scp and Ansible need sftp. dev-sec's chroot to `/home/%u` requires root-owned home directories and otherwise breaks every session. **Judgement** | [R6] |

**Cost:** password logins stop, so every administrator needs a key first (the playbook
checks this before it proceeds). Tunnels, ProxyJump through the host, remote-IDE sessions and
X11 stop working. Very old clients cannot connect.

A caveat on the crypto: chacha20-poly1305 and the `-etm` MACs are the modes the Terrapin
prefix-truncation attack applies to. It is mitigated by "strict key exchange" in OpenSSH 9.6
and later, but only when the client supports it too. Keep clients current, or drop those
algorithms if you must serve old ones [R7].

---

## 4. Host firewall

Ubuntu ships without an active firewall: every listening port is reachable.

| Setting | Baseline | Why this value | Reference |
|---|---|---|---|
| Tool | ufw | One firewall front end, as CIS requires; shares the netfilter backend Docker uses, so the two coexist | [CIS 4] |
| Inbound default | deny | Turns "what is listening" into a reviewed allow-list; a service started by mistake is not exposed | [CIS 4][R17] 1.3.1, 1.4.1 |
| Outbound default | allow | **Judgement.** Egress filtering is valuable but needs a per-application inventory of destinations; a wrong guess breaks patching and DNS. Add it per environment | - |
| Routed default | deny | A server is not a router; this also contains what container forwarding makes possible | [CIS 4] |
| Allow-list | 22/tcp only | Add your service ports in `hardening_fw_allow` | [R17] 1.2.5 |

**Docker-published ports** are DNATed before the INPUT chain and bypass ufw; Docker's
documentation states the incompatibility [R12]. Two answers: bind published ports to
`127.0.0.1`, or set `hardening_docker_filter: true` with the ports that should be reachable
in `hardening_docker_published_allow`. The filter writes rules to Docker's `DOCKER-USER`
chain and is off by default, because switching it on with an incomplete list cuts off
containers that are serving traffic.

---

## 5. Authentication (PAM)

Ubuntu's default has no quality, history or lockout policy, and `nullok` accepts empty
passwords.

| Setting | Baseline | Why this value | Reference |
|---|---|---|---|
| `minlen` | `14` | CIS floor. Length is the property that actually resists guessing; PCI's floor is 12 | [CIS 5.3][R17] 8.3.6 |
| `minclass` | `3` | PCI requires numeric and alphabetic. **Judgement:** NIST advises *against* composition rules [R3]; 3 of 4 classes is the lightest setting that still satisfies PCI and CIS | [R17] 8.3.6, [R3] |
| `dictcheck`, `usercheck` | on | Rejects dictionary words and the username: the control NIST *does* ask for (screen against known-bad values) | [R3][R22] |
| `maxrepeat`, `maxsequence` | `3` | Rejects `aaaa`, `1234` | [CIS 5.3] |
| `difok` | `2` | New password must differ in at least 2 characters | [CIS 5.3] |
| `enforce_for_root` | on | Otherwise root can set any password for any account | [CIS 5.3] |
| History | `remember=24` | CIS floor; PCI's is 4 | [CIS 5.3][R17] 8.3.7, [R9] |
| Lockout | 5 failures, 900 s, root included | CIS: at most 5 attempts, at least 15 minutes. Temporary rather than permanent, so it cannot be used to lock an administrator out indefinitely | [CIS 5.3][R8] |
| `nullok` | removed | An account with an empty password field could log in | [CIS 5.3] |
| Hash | yescrypt (Ubuntu default, kept) | Memory-hard. dev-sec's `login.defs` template would set SHA-512, so that template is not applied | [CIS 5.3] |

**Cost:** the policy applies at the next password change; existing weak passwords are not
detected or changed. Lockout is also a denial-of-service lever: five bad attempts lock an
account for 15 minutes (`faillock --user <name> --reset` clears it).

**PCI DSS:** requirement 8.3.4 asks for a lockout of at least 30 minutes. 900 s satisfies CIS
but not PCI. In PCI scope set `hardening_profile: pci`, which raises it to 1800 s.

---

## 6. Accounts, sudo and sessions

| Setting | Baseline | Ubuntu default | Why this value | Reference |
|---|---|---|---|---|
| `PASS_MAX_DAYS` | `365` | 99999 | CIS ceiling. **Judgement** not to use dev-sec's 60: NIST says not to force periodic change without evidence of compromise, because it yields predictable passwords [R3]. PCI needs 90 where the password is the only factor | [CIS 5.4][R3][R17] 8.3.9 |
| `PASS_MIN_DAYS` | `1` | 0 | Stops cycling through the history in one sitting | [CIS 5.4] |
| `PASS_WARN_AGE` | `7` | 7 | CIS floor | [CIS 5.4] |
| `INACTIVE` | `45` | never | Dormant accounts lock themselves | [CIS 5.4] |
| `UMASK` | `027` | 022 | New files are not world-readable | [CIS 5.4] |
| `TMOUT` | `900`, readonly | unset | Unattended shells close; matches PCI's 15 minutes | [CIS 5.4][R17] 8.2.8 |
| System accounts | nologin, locked | varies | They never need interactive login | [CIS 5.4] |
| sudo `use_pty` | on | on | A sudo'd program cannot inject keystrokes into the caller's terminal after it exits | [CIS 5.2][R20] |
| sudo `timestamp_timeout` | `15` | 15 | CIS ceiling for credential caching | [CIS 5.2] |
| sudo `logfile` | set, except under sudo-rs | unset | CIS asks for it. On releases where sudo-rs is the default sudo (Ubuntu 25.10 and later), its `visudo` rejects the option as a syntax error, so the role detects sudo-rs and omits the line. sudo events are then in the journal and the audit trail | [CIS 5.2][R21] |
| `su` | members of an empty group only | anyone | Privilege changes go through sudo, which logs who did it. Done with `pam_wheel` rather than dev-sec's `chmod` on the binary, which the next package update undoes | [CIS 5.2][R24] |

**Cost:** a password already older than the maximum expires at once. Service accounts below
UID 1000 lose their shell, so `su - postgres` style administration breaks unless the account
is listed in `os_ignore_users`. `umask 027` breaks software that relies on creating
world-readable files. `su - user` stops working for non-root; use `sudo -iu user`.

---

## 7. Kernel and network parameters

Written to `/etc/sysctl.d/90-dev-sec.conf`. Kernel documentation for the keys: [R10]
(kernel.*), [R23] (fs.*), [R11] (net.*).

| Parameter | Baseline | Why this value | Reference |
|---|---|---|---|
| `kernel.randomize_va_space` | `2` | Full ASLR | [CIS 1.5] |
| `kernel.yama.ptrace_scope` | `2` | Only root may attach to a process, so one compromised process cannot read credentials out of another of the same user. CIS accepts 1; 2 is the dev-sec value | [CIS 1.5][R25] |
| `fs.suid_dumpable` | `0` | Setuid programs never dump core (their memory holds privileged data) | [CIS 1.5][R23] |
| `kernel.kptr_restrict` | `2` | Hides kernel addresses, which exploits need to defeat KASLR | [R10][R13] |
| `kernel.dmesg_restrict` | `1` | Same reason; the kernel log leaks addresses | [R10] |
| `kernel.unprivileged_bpf_disabled` | `1` | The eBPF verifier is a recurring source of local privilege escalation | [R10] |
| `kernel.unprivileged_userns_clone` | `0` | User namespaces expose a large kernel attack surface to unprivileged users | [R13] |
| `kernel.kexec_load_disabled` | `1` | Root cannot replace the running kernel without a reboot | [R10] |
| `kernel.sysrq` | `0` | No console key combination can reboot or dump memory | [R10] |
| `fs.protected_hardlinks/symlinks/fifos/regular` | `1/1/1/2` | Blocks the classic `/tmp` link-following races | [R23] |
| `net.ipv4.conf.*.accept_redirects`, `secure_redirects`, IPv6 equivalents | `0` | An on-link attacker cannot rewrite the host's routes with ICMP redirects | [CIS 3.3][R11] |
| `net.ipv4.conf.*.send_redirects` | `0` | Only routers send redirects | [CIS 3.3] |
| `net.ipv4.conf.*.accept_source_route` (and IPv6) | `0` | Sender-chosen routes bypass network controls | [CIS 3.3] |
| `net.ipv4.conf.*.rp_filter` | `1` (strict) | Drops packets whose source could not be reached through the arriving interface (spoofing) | [CIS 3.3][R27] |
| `net.ipv4.conf.*.log_martians` | `1` | Spoofed or impossible sources are logged | [CIS 3.3] |
| `net.ipv4.tcp_syncookies` | `1` | Service survives a SYN flood | [CIS 3.3] |
| `net.ipv4.icmp_echo_ignore_broadcasts`, `icmp_ignore_bogus_error_responses` | `1` | No smurf amplification; less log noise | [CIS 3.3] |
| `net.ipv6.conf.*.accept_ra` | `0` | A rogue router advertisement cannot become the default route | [CIS 3.3] |
| `net.ipv4.ip_forward` | `0`, or `1` when Docker is detected | CIS wants 0. Docker bridge networking needs forwarding, so the playbook keeps it on where Docker is installed; exposure is then bounded by the FORWARD chain policy (drop) | [CIS 3.3][R12] |
| `net.ipv4.tcp_timestamps` | `1` | dev-sec sets 0. **Judgement** to keep the kernel default: timestamps provide PAWS and RTT measurement; turning them off costs correctness on fast links for a minor uptime-fingerprinting gain. CIS does not ask for 0 | [R26] |
| `net.core.bpf_jit_harden` | `2` | Constant blinding against JIT spraying | [R10] |

**Cost:** attaching a debugger or `strace` to a running process needs root. Rootless
containers, bubblewrap and browser sandboxes need unprivileged user namespaces. kdump and
kexec-based reboots need kexec. Strict reverse-path filtering drops legitimate traffic on
multi-homed hosts with asymmetric routing (use `2` there). Hosts that get their IPv6 address
or default route from router advertisements lose IPv6. Override single keys in
`hardening_sysctl_extra`.

---

## 8. Filesystems, modules, services and software

| Setting | Baseline | Why | Reference |
|---|---|---|---|
| `/tmp`, `/dev/shm` | `nodev,nosuid,noexec` (see note for `/tmp`) | World-writable locations are where a second-stage payload is dropped and run. It is a speed bump (interpreters still work), which is why it is cheap and still worth having | [CIS 1.1.2][R28] |
| Modules cramfs, freevxfs, hfs, hfsplus, jffs2, udf | disabled and blacklisted | Unused filesystem drivers reachable by mounting a crafted image | [CIS 1.1.1] |
| `usb-storage` | disabled | No mass-storage exfiltration or ingress on physical hosts | [CIS 1.1.1] |
| dccp, tipc, rds, sctp | disabled | Rarely used protocol stacks that any user can trigger loading of | [CIS 3.2] |
| overlayfs | disabled, unless Docker, containerd, Podman or CRI-O is installed | CIS Level 2 item; container runtimes cannot work without it, so the role checks first | [CIS 1.1.1] |
| squashfs, vfat | left enabled | snap needs squashfs; EFI system partitions are vfat. **Judgement** | - |
| `/boot/grub/grub.cfg` | mode 0600 | It reveals kernel parameters and would hold a hashed boot password. Ubuntu 22.04 writes it world-readable | [CIS 1.4] |
| postfix, when the AIDE packages pull it in | loopback only | On Ubuntu 22.04 the AIDE packages depend on a mailer, which installs postfix listening on every interface. An integrity checker must not add a network service. A postfix that was already installed is left alone unless `hardening_mta_loopback_only` is set | [CIS 2.1] |
| Core dumps, apport, kdump | off | They write process or kernel memory (keys, tokens) to disk | [CIS 1.5] |
| telnet, ftp, rsh, talk, NIS clients | removed | Cleartext credentials; ready-made lateral-movement tooling | [CIS 2.2] |
| Unneeded services | nothing by default | Whether a unit is unneeded depends on the host: multipathd and iscsid are boot-critical on SAN or iSCSI roots. List them per environment in `hardening_disable_units` | [CIS 2.1][R2] |
| Package updates | reported; installed only with `hardening_apply_updates: true` | Hardening an unpatched system protects very little, but installing updates restarts services and may need a reboot. On a live server that is a change-window decision, so it is off by default and pending updates show as an open finding. **Judgement** | [CIS 1.2][R17] 6.3.3 |
| Cron files | root-only, `cron.allow` | Scheduled jobs are a persistence and escalation path | [CIS 2.4] |
| Banners | legal text, no version | Notice for monitoring and prosecution; no free version disclosure | [CIS 1.6] |
| `/proc` `hidepid` | `0` | dev-sec's default of 2 hides other users' processes but interferes with systemd's session tracking. **Judgement**, not from a cited source | [R29] |

**`/tmp` on older releases:** Ubuntu 26.04 mounts `/tmp` as a tmpfs, so the options apply
directly. On 22.04 and 24.04 `/tmp` is a directory on the root filesystem and cannot take
mount options; `hardening_tmp_tmpfs: true` moves it to a tmpfs at the next boot. It is opt-in
because `/tmp` then lives in memory and is emptied on every reboot.

**Cost:** software that executes from `/tmp` fails (some installers, JVM native-library
extraction). USB or virtual-media rescue needs `usb-storage` re-enabled first. SCTP is used
by telecom signalling and some clustering software. No crash dumps for post-mortem debugging.

---

## 9. Logging, audit and integrity

| Setting | Baseline | Why | Reference |
|---|---|---|---|
| journald `Storage=persistent`, `Compress=yes` | on | Logs survive a reboot | [CIS 6.1] |
| Log file modes | no world read | Logs contain usernames, paths, sometimes secrets | [CIS 6.1] |
| Remote forwarding | off until `hardening_syslog_remote_host` is set | Needs a collector. Usually the most valuable open item: local logs are erased by whoever compromises the host. Set `hardening_syslog_remote_tls: true` to send over TLS with the collector's certificate verified; plain TCP exposes the logs on the network | [CIS 6.1][R5][R17] 10.3.3 |
| auditd with a CIS-style rule set | on | Records what the kernel saw a user do, keeping the original login identity across sudo and su | [CIS 6.2][R30][R17] 10.2.1 |
| `audit=1`, `audit_backlog_limit=8192` | kernel command line | Processes started before auditd are auditable; no dropped events at boot | [CIS 6.2] |
| `-e 2` | immutable rules | An intruder with root cannot silently remove rules without a reboot | [CIS 6.2] |
| `max_log_file_action` | `keep_logs` with a dedicated audit filesystem, otherwise `rotate` | CIS: audit logs are never deleted automatically. Detected per host; see below | [CIS 6.2][R31] |
| `space_left_action` / `admin_space_left_action` | `email` / `single` with a dedicated audit filesystem, otherwise `syslog` / `suspend` | CIS: warn, then stop the system rather than run unaudited | [CIS 6.2][R31] |
| AIDE with a daily check | on; database rebuilt after a run only when files changed | Detects modified binaries and configuration; PCI calls for change detection at least weekly | [CIS 6.3][R32][R17] 11.5.2 |
| Time synchronisation | not changed | Ubuntu already runs a single synchronised source | [CIS 2.3][R17] 10.6 |

**Cost and a necessary deviation.** The CIS audit-log settings assume `/var/log/audit` is its
own filesystem. On a host with a single root filesystem, never deleting logs eventually fills
`/`, and `single` then takes the host off the network. The playbook therefore checks for a
dedicated filesystem: with one it applies the CIS values, without one it uses bounded
rotation (10 files of 50 MB). **Judgement.** In the second case two CIS checks stay open;
record them as accepted risks until the filesystem exists. The immutable flag means rule changes need a reboot. AIDE reports every legitimate
change, including patching, until the database is rebuilt; without a process for that the
report becomes noise.

---

## 10. Deliberately not done

| Not done | Why |
|---|---|
| Change the SSH port | Section 1 |
| Install fail2ban | With passwords off there is nothing to brute-force; OpenSSH's per-source penalties and `MaxStartups` cover connection abuse. One more root-run log parser is attack surface |
| Disable IPv6 | CIS asks only that its status be a decision. Disabling the stack breaks software that binds `::`; filtering it is cleaner |
| GRUB password | Done wrong, every unattended reboot waits at the console. Belongs in the image, with `--unrestricted` on the default entry |
| Strip all unknown setuid bits (a dev-sec option) | Removes setuid from anything not on dev-sec's allow-list, which breaks legitimate vendor binaries |
| Egress firewall rules | Needs application knowledge; section 4 |
| Change or test user passwords | Credentials belong to their owners. The audit flags trivially guessable ones |
| Repartition | Cannot be done online. Put separate `/var`, `/var/log`, `/var/log/audit`, `/home` and `/var/tmp` in the image |
| Move AppArmor profiles from complain to enforce | Each needs testing against its program |

---

## 11. Where the sources disagree

| Topic | CIS | NIST SP 800-63B | PCI DSS v4.0.1 | Baseline |
|---|---|---|---|---|
| Password rotation | at most 365 days | none without evidence of compromise | 90 days if single-factor | 365 |
| Composition rules | configure complexity | advises against | numeric and alphabetic | 3 of 4 classes |
| Minimum length | 14 | 8 (longer encouraged) | 12 | 14 |
| Lockout duration | at least 15 min | rate-limit, no fixed duration | at least 30 min | 15 min |

The stricter requirement wins when a standard is contractually binding; where none is, the
NIST position is the best-evidenced one. `hardening_profile: pci` switches the two values
where PCI is stricter than CIS: 90-day password age and a 30-minute lockout. Every CIS check
still passes with them.

---

## 12. What is decided per host, and how to deviate

Some values cannot be right for every machine, so the playbook inspects the host and prints
what it decided at the start of each run:

| Detected | Effect |
|---|---|
| Docker installed | IPv4 forwarding stays on |
| No dedicated `/var/log/audit` filesystem | Bounded audit-log rotation instead of keep-and-halt |
| A global IPv6 address | sshd listens on IPv6 as well as IPv4 |
| IPv6 default route from kernel router advertisements | The run stops until you choose: keep accepting RAs, or accept losing IPv6 |
| sudo-rs as the default sudo | Automation uses the classic `sudo.ws`; the sudo log-file setting is omitted |
| `/tmp` not a tmpfs | Mount options are skipped unless `hardening_tmp_tmpfs` is set |

Beyond that, every environment has reasons to differ. Two mechanisms keep those differences
visible:

- **Do not apply a control:** set its variable in
  `inventory/<env>/group_vars/<group>/overrides.yml`, with the reason next to it.
- **Accept the resulting finding:** add it to `inventory/<env>/exceptions.yml` with a reason,
  an owner and an expiry date. The report then lists it under accepted risks rather than open
  findings, and returns it to the open list when it expires. An accepted finding still counts
  against the score: accepting a risk does not make the benchmark pass.

---

## 13. References

| | Source |
|---|---|
| R1 | CIS Ubuntu Linux Benchmarks - https://www.cisecurity.org/benchmark/ubuntu_linux |
| R2 | NIST SP 800-123, Guide to General Server Security - https://csrc.nist.gov/pubs/sp/800/123/final |
| R3 | NIST SP 800-63B, Digital Identity Guidelines: Authentication - https://pages.nist.gov/800-63-3/sp800-63b.html (revision 4: https://csrc.nist.gov/pubs/sp/800/63/b/4/final) |
| R4 | NIST SP 800-53 Rev. 5, Security and Privacy Controls - https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final |
| R5 | NIST SP 800-92, Guide to Computer Security Log Management - https://csrc.nist.gov/pubs/sp/800/92/final |
| R6 | OpenSSH `sshd_config(5)` - https://man.openbsd.org/sshd_config |
| R7 | Terrapin attack (CVE-2023-48795) - https://terrapin-attack.com/ |
| R8 | `pam_faillock(8)` - https://man7.org/linux/man-pages/man8/pam_faillock.8.html |
| R9 | `pam_pwhistory(8)` - https://man7.org/linux/man-pages/man8/pam_pwhistory.8.html |
| R10 | Linux kernel documentation, `/proc/sys/kernel` - https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html |
| R11 | Linux kernel documentation, IP sysctl - https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html |
| R12 | Docker, Packet filtering and firewalls - https://docs.docker.com/engine/network/packet-filtering-firewalls/ |
| R13 | DevSec Linux baseline - https://dev-sec.io/baselines/linux/ |
| R14 | DevSec SSH baseline - https://dev-sec.io/baselines/ssh/ |
| R15 | dev-sec ansible-collection-hardening - https://github.com/dev-sec/ansible-collection-hardening |
| R16 | Lynis - https://cisofy.com/lynis/ |
| R17 | PCI DSS v4.0.1 (document library) - https://www.pcisecuritystandards.org/document_library/ |
| R18 | ISO/IEC 27001:2022 - https://www.iso.org/standard/27001 |
| R19 | Mozilla OpenSSH guidelines - https://infosec.mozilla.org/guidelines/openssh |
| R20 | `sudoers(5)` - https://www.sudo.ws/docs/man/sudoers.man/ |
| R21 | sudo-rs - https://github.com/trifectatechfoundation/sudo-rs |
| R22 | libpwquality - https://github.com/libpwquality/libpwquality |
| R23 | Linux kernel documentation, `/proc/sys/fs` - https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html |
| R24 | `pam_wheel(8)` - https://man7.org/linux/man-pages/man8/pam_wheel.8.html |
| R25 | Linux kernel documentation, Yama LSM - https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html |
| R26 | RFC 7323, TCP Extensions for High Performance - https://www.rfc-editor.org/rfc/rfc7323 |
| R27 | RFC 3704, Ingress Filtering for Multihomed Networks - https://www.rfc-editor.org/rfc/rfc3704 |
| R28 | systemd, Using /tmp/ and /var/tmp/ safely - https://systemd.io/TEMPORARY_DIRECTORIES/ |
| R29 | `proc(5)`, `hidepid` mount option - https://man7.org/linux/man-pages/man5/proc.5.html |
| R30 | `audit.rules(7)` - https://man7.org/linux/man-pages/man7/audit.rules.7.html |
| R31 | `auditd.conf(5)` - https://man7.org/linux/man-pages/man5/auditd.conf.5.html |
| R32 | AIDE - https://aide.github.io/ |

The sources were checked to exist in October 2026. Requirement numbers quoted for PCI DSS and
thresholds quoted for CIS and NIST come from working knowledge of those documents and were
not each verified against the text. Check the ones you intend to rely on.
