#!/usr/bin/env bash
# shellcheck disable=SC2015  # "cond && rec PASS || rec FAIL": rec only prints and cannot fail
# cis_audit.sh - read-only host audit mapped to the CIS Ubuntu Linux LTS benchmark structure.
#
# - Makes NO changes to the system. Safe to run repeatedly, before and after hardening.
# - Must run as root (reads /etc/shadow, sshd -T, auditctl, nft ...).
# - Output: TSV on stdout, one line per check:
#     ID  CIS_SECTION  LEVEL  GROUP  STATUS  TITLE  EVIDENCE
#   LEVEL : L1 | L2 (CIS profile level) | X (not a CIS item; added from engineering judgement)
#   STATUS: PASS | FAIL | MANUAL (needs a human decision) | NA (not applicable on this host)
#   GROUP : key into controls/catalogue.yml (why / impact / remediation / validation)
#
# CIS_SECTION is the benchmark *section* the check belongs to (CIS Ubuntu Linux 24.04 LTS
# Benchmark v1.0.0 layout). Exact recommendation numbers differ between benchmark versions;
# confirm against the licensed CIS PDF before quoting them in a formal attestation.

set -u
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
VERSION=1.2.1

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 2; }
# The checks are written for Ubuntu (dpkg, apt, AppArmor, ufw, pam-auth-update). On any other
# system they would not fail loudly - they would report false passes ("package not installed").
OS_ID=$( (. /etc/os-release 2>/dev/null; echo "${ID:-unknown}") )
if [ "$OS_ID" != ubuntu ] && [ "${CIS_AUDIT_FORCE:-0}" != 1 ]; then
  echo "unsupported system: $OS_ID. This audit only supports Ubuntu." >&2
  exit 3
fi

# ---------------------------------------------------------------- helpers ---
rec() { # id cis level group status title evidence
  local ev=${7:-}
  ev=${ev//$'\t'/ }; ev=${ev//$'\n'/; }
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "${ev:0:400}"
}
has() { command -v "$1" >/dev/null 2>&1; }
pkg_installed() { dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null | grep -qx installed; }
unit_on() { systemctl is-enabled "$1" 2>/dev/null | grep -qE '^(enabled|static|alias|generated)' || systemctl is-active --quiet "$1" 2>/dev/null; }

HAS_DOCKER=0; { has dockerd || pkg_installed docker-ce || pkg_installed docker.io; } && HAS_DOCKER=1
# Local filesystems only; never descend into vboxsf/NFS/docker layers or pseudo filesystems.
LOCAL_FS=$(findmnt -rn -o TARGET -t ext2,ext3,ext4,xfs,btrfs,zfs,f2fs | grep -vE '^/var/lib/(docker|containerd)' )
lfind() { local m; for m in $LOCAL_FS; do find "$m" -xdev \( -path /var/lib/docker -o -path /var/lib/containerd -o -path /snap \) -prune -o "$@" -print 2>/dev/null; done; }

# kernel module must be: not loaded, install -> /bin/true|false, blacklisted (or absent from kernel)
chk_mod() { # id cis level group module
  local id=$1 cis=$2 lvl=$3 grp=$4 m=$5 mu=${5//-/_} t="Kernel module '$5' is disabled"
  local fn; fn=$(modinfo -F filename "$m" 2>/dev/null)
  if [ -z "$fn" ]; then rec "$id" "$cis" "$lvl" "$grp" PASS "$t" "module not present in kernel $(uname -r)"; return; fi
  if [ "$fn" = "(builtin)" ]; then rec "$id" "$cis" "$lvl" "$grp" MANUAL "$t" "built into the kernel; cannot be disabled via modprobe"; return; fi
  local why=""
  lsmod | grep -qE "^${mu}\s" && why+="loaded; "
  modprobe -n -v "$m" 2>&1 | grep -qE "install\s+/(usr/)?bin/(true|false)" || why+="no 'install $m /bin/false'; "
  modprobe --showconfig 2>/dev/null | grep -qE "^blacklist\s+${mu}\s*$" || why+="not blacklisted; "
  if [ -z "$why" ]; then rec "$id" "$cis" "$lvl" "$grp" PASS "$t" "install->false, blacklisted, not loaded"
  else rec "$id" "$cis" "$lvl" "$grp" FAIL "$t" "$why"; fi
}

# running value must match; a conflicting persisted value is also a failure
chk_sysctl() { # id cis level group key expected [title]
  local id=$1 cis=$2 lvl=$3 grp=$4 k=$5 exp=$6 t=${7:-"sysctl $5 = $6"}
  local cur; cur=$(sysctl -n "$k" 2>/dev/null | tr '\t' ' ')
  if [ -z "$cur" ]; then rec "$id" "$cis" "$lvl" "$grp" NA "$t" "key not present (feature absent)"; return; fi
  # systemd-analyze prints the sysctl.d files in the order systemd-sysctl applies them, so the
  # last assignment is the one that wins at boot (a plain grep over the directories is not)
  local pers; pers=$(grep -E "^\s*${k//./\\.}\s*=" <<<"$SYSCTL_CONF" | tail -1 | sed 's/.*=\s*//;s/\s*$//')
  local ev="running=$cur persisted=${pers:-<kernel default>}"
  if [ "$cur" = "$exp" ] && { [ -z "$pers" ] || [ "$pers" = "$exp" ]; }; then rec "$id" "$cis" "$lvl" "$grp" PASS "$t" "$ev"
  else rec "$id" "$cis" "$lvl" "$grp" FAIL "$t" "$ev"; fi
}

SYSCTL_CONF=$(systemd-analyze cat-config sysctl.d 2>/dev/null || cat /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null)

chk_perm() { # id cis level group path maxmode(octal) owner group(regex) [title]
  local id=$1 cis=$2 lvl=$3 grp=$4 p=$5 max=$6 own=$7 g=$8 t=${9:-"Permissions on $5 are $6 $7:$8 or stricter"}
  if [ ! -e "$p" ]; then rec "$id" "$cis" "$lvl" "$grp" NA "$t" "file does not exist"; return; fi
  local m o gg; read -r m o gg < <(stat -Lc '%a %U %G' "$p")
  local ev="mode=$m owner=$o group=$gg"
  if [ $(( 0$m & ~0$max )) -eq 0 ] && [ "$o" = "$own" ] && [[ "$gg" =~ ^($g)$ ]]; then rec "$id" "$cis" "$lvl" "$grp" PASS "$t" "$ev"
  else rec "$id" "$cis" "$lvl" "$grp" FAIL "$t" "$ev"; fi
}

chk_pkg_absent() { # id cis level group title pkg...
  local id=$1 cis=$2 lvl=$3 grp=$4 t=$5; shift 5
  local found="" p; for p in "$@"; do pkg_installed "$p" && found+="$p "; done
  if [ -z "$found" ]; then rec "$id" "$cis" "$lvl" "$grp" PASS "$t" "not installed"
  else rec "$id" "$cis" "$lvl" "$grp" FAIL "$t" "installed: $found"; fi
}

# a server role is acceptable only if deliberately required -> report FAIL when present and running
chk_svc_off() { # id cis level group title pkg unit...
  local id=$1 cis=$2 lvl=$3 grp=$4 t=$5 pkg=$6; shift 6
  local on="" u; for u in "$@"; do unit_on "$u" && on+="$u "; done
  if ! pkg_installed "$pkg" && [ -z "$on" ]; then rec "$id" "$cis" "$lvl" "$grp" PASS "$t" "package $pkg not installed"
  elif [ -z "$on" ]; then rec "$id" "$cis" "$lvl" "$grp" PASS "$t" "package $pkg installed but units disabled and inactive"
  else rec "$id" "$cis" "$lvl" "$grp" FAIL "$t" "enabled/active: $on"; fi
}

chk_mnt() { # id cis level group mountpoint option
  local id=$1 cis=$2 lvl=$3 grp=$4 mp=$5 opt=$6 t="$5 is mounted with $6"
  local o; o=$(findmnt -rn -o OPTIONS "$mp" 2>/dev/null | head -1)
  if [ -z "$o" ]; then rec "$id" "$cis" "$lvl" "$grp" NA "$t" "$mp is not a separate mount"; return; fi
  if [[ ",$o," == *",$opt,"* ]]; then rec "$id" "$cis" "$lvl" "$grp" PASS "$t" "$o"; else rec "$id" "$cis" "$lvl" "$grp" FAIL "$t" "$o"; fi
}
chk_part() { # id cis level group mountpoint
  local t="$5 is a separate filesystem"
  if findmnt -rn "$5" >/dev/null 2>&1; then rec "$1" "$2" "$3" "$4" PASS "$t" "$(findmnt -rn -o SOURCE,FSTYPE "$5" | head -1)"
  else rec "$1" "$2" "$3" "$4" FAIL "$t" "lives on the root filesystem"; fi
}

SSHD_T=$(sshd -T -C user=root -C host=localhost -C addr=127.0.0.1 2>/dev/null)
sshd_val() { awk -v k="$1" '$1==k{$1="";sub(/^ /,"");print;exit}' <<<"$SSHD_T"; }
chk_sshd() { # id level key regex title   (regex matched against effective lowercase value)
  local id=$1 lvl=$2 k=$3 re=$4 t=$5 v; v=$(sshd_val "$k")
  if [[ "${v,,}" =~ ^($re)$ ]]; then rec "$id" 5.1 "$lvl" SSH PASS "$t" "$k $v"; else rec "$id" 5.1 "$lvl" SSH FAIL "$t" "$k ${v:-<unset>}"; fi
}
chk_sshd_num() { # id level key min max title
  local id=$1 lvl=$2 k=$3 min=$4 max=$5 t=$6 v; v=$(sshd_val "$k")
  if [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge "$min" ] && [ "$v" -le "$max" ]; then rec "$id" 5.1 "$lvl" SSH PASS "$t" "$k $v"; else rec "$id" 5.1 "$lvl" SSH FAIL "$t" "$k ${v:-<unset>} (want $min..$max)"; fi
}
# effective value of a "key = value" setting across a main file and its drop-in dir (last wins)
conf_val() { # key file dropin-dir
  cat "$2" "$3"/*.conf 2>/dev/null | grep -E "^\s*$1\s*=" | tail -1 | sed 's/^[^=]*=\s*//;s/\s*$//'
}

# ------------------------------------------------------------------- meta ---
echo "#meta	script_version	$VERSION"
echo "#meta	hostname	$(hostname)"
echo "#meta	os	$(. /etc/os-release; echo "$PRETTY_NAME")"
echo "#meta	kernel	$(uname -r)"
echo "#meta	virt	$(systemd-detect-virt 2>/dev/null)"
echo "#meta	date_utc	$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "#meta	docker	$HAS_DOCKER"

# ====================================================== 1 Initial setup =====
# 1.1.1 filesystem kernel modules
chk_mod FS-01 1.1.1 L1 FS-MOD cramfs
chk_mod FS-02 1.1.1 L1 FS-MOD freevxfs
chk_mod FS-03 1.1.1 L1 FS-MOD hfs
chk_mod FS-04 1.1.1 L1 FS-MOD hfsplus
chk_mod FS-05 1.1.1 L1 FS-MOD jffs2
if [ $HAS_DOCKER -eq 1 ]; then rec FS-06 1.1.1 L2 FS-MOD NA "Kernel module 'overlayfs' is disabled" "Docker (overlay2 storage driver) requires overlayfs - documented exception"
else chk_mod FS-06 1.1.1 L2 FS-MOD overlay; fi
if pkg_installed snapd && [ -n "$(ls /snap/*/current 2>/dev/null)" ]; then rec FS-07 1.1.1 L2 FS-MOD NA "Kernel module 'squashfs' is disabled" "snap packages are installed and need squashfs"
else chk_mod FS-07 1.1.1 L2 FS-MOD squashfs; fi
chk_mod FS-08 1.1.1 L2 FS-MOD udf
chk_mod FS-09 1.1.1 L1 FS-MOD usb-storage

# 1.1.2 partitions and mount options
chk_part FS-10 1.1.2 L1 FS-PART /tmp
for o in nodev nosuid noexec; do chk_mnt "FS-11-$o" 1.1.2 L1 FS-PART /tmp $o; done
chk_part FS-12 1.1.2 L1 FS-PART /dev/shm
for o in nodev nosuid noexec; do chk_mnt "FS-13-$o" 1.1.2 L1 FS-PART /dev/shm $o; done
chk_part FS-14 1.1.2 L2 FS-PART /home
for o in nodev nosuid; do chk_mnt "FS-15-$o" 1.1.2 L1 FS-PART /home $o; done
chk_part FS-16 1.1.2 L2 FS-PART /var
for o in nodev nosuid; do chk_mnt "FS-17-$o" 1.1.2 L1 FS-PART /var $o; done
chk_part FS-18 1.1.2 L2 FS-PART /var/tmp
for o in nodev nosuid noexec; do chk_mnt "FS-19-$o" 1.1.2 L1 FS-PART /var/tmp $o; done
chk_part FS-20 1.1.2 L2 FS-PART /var/log
for o in nodev nosuid noexec; do chk_mnt "FS-21-$o" 1.1.2 L1 FS-PART /var/log $o; done
chk_part FS-22 1.1.2 L2 FS-PART /var/log/audit
for o in nodev nosuid noexec; do chk_mnt "FS-23-$o" 1.1.2 L1 FS-PART /var/log/audit $o; done

# 1.2 package management
n_up=$(apt list --upgradable 2>/dev/null | grep -c '/')
n_sec=$(apt list --upgradable 2>/dev/null | grep -c -- '-security')
# "nothing to upgrade" is only meaningful against a fresh package index
idx_ts=$(stat -c %Y /var/lib/apt/periodic/update-success-stamp 2>/dev/null || find /var/lib/apt/lists -maxdepth 1 -type f -printf '%T@\n' 2>/dev/null | sort -n | tail -1 | cut -d. -f1)
idx_age=$(( ( $(date +%s) - ${idx_ts:-0} ) / 86400 ))
if [ "$n_up" -eq 0 ] && [ "$idx_age" -gt 2 ]; then rec PKG-01 1.2 L1 PKG MANUAL "Updates, patches and security software are installed" "0 upgradable packages, but the package index is $idx_age days old - run 'apt update' and audit again"
elif [ "$n_up" -eq 0 ]; then rec PKG-01 1.2 L1 PKG PASS "Updates, patches and security software are installed" "0 upgradable packages (package index $idx_age day(s) old)"
else rec PKG-01 1.2 L1 PKG FAIL "Updates, patches and security software are installed" "$n_up upgradable packages, $n_sec from -security"; fi
rec PKG-02 1.2 L1 PKG MANUAL "Package repositories and GPG keys are approved" "sources: $(ls /etc/apt/sources.list.d 2>/dev/null | tr '\n' ' ')"
uu=$(apt-config dump 2>/dev/null | awk -F'"' '/APT::Periodic::Unattended-Upgrade /{print $2}')
if pkg_installed unattended-upgrades && [ "${uu:-0}" != 0 ]; then rec PKG-03 1.2 X PKG PASS "Automatic security updates are enabled" "APT::Periodic::Unattended-Upgrade=$uu"
else rec PKG-03 1.2 X PKG FAIL "Automatic security updates are enabled" "unattended-upgrades missing or disabled"; fi
if [ -f /var/run/reboot-required ]; then rec PKG-04 1.2 X PKG FAIL "No reboot pending for installed kernel/library updates" "$(cat /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ' ')"
else rec PKG-04 1.2 X PKG PASS "No reboot pending for installed kernel/library updates" "no /var/run/reboot-required"; fi

# 1.3 AppArmor
if pkg_installed apparmor && pkg_installed apparmor-utils; then rec MAC-01 1.3.1 L1 MAC PASS "AppArmor and apparmor-utils are installed" ""
else rec MAC-01 1.3.1 L1 MAC FAIL "AppArmor and apparmor-utils are installed" "apparmor=$(pkg_installed apparmor && echo yes || echo no) apparmor-utils=$(pkg_installed apparmor-utils && echo yes || echo no)"; fi
if grep -qw apparmor /sys/kernel/security/lsm 2>/dev/null && ! grep -qE 'apparmor=0' /proc/cmdline; then rec MAC-02 1.3.1 L1 MAC PASS "AppArmor is enabled at boot" "lsm=$(cat /sys/kernel/security/lsm)"
else rec MAC-02 1.3.1 L1 MAC FAIL "AppArmor is enabled at boot" "lsm=$(cat /sys/kernel/security/lsm 2>/dev/null)"; fi
aa=$(apparmor_status 2>/dev/null)
aa_loaded=$(awk '/profiles are loaded/{print $1}' <<<"$aa"); aa_enf=$(awk '/profiles are in enforce mode/{print $1}' <<<"$aa")
aa_compl=$(awk '/profiles are in complain mode/{print $1}' <<<"$aa"); aa_unconf=$(awk '/processes are unconfined but have a profile/{print $1}' <<<"$aa")
ev="loaded=$aa_loaded enforce=$aa_enf complain=$aa_compl unconfined_with_profile=$aa_unconf"
if [ "${aa_loaded:-0}" -gt 0 ] && [ "${aa_unconf:-0}" -eq 0 ]; then rec MAC-03 1.3.1 L1 MAC PASS "All AppArmor profiles are in enforce or complain mode" "$ev"; else rec MAC-03 1.3.1 L1 MAC FAIL "All AppArmor profiles are in enforce or complain mode" "$ev"; fi
if [ "${aa_loaded:-0}" -gt 0 ] && [ "${aa_compl:-0}" -eq 0 ] && [ "${aa_unconf:-0}" -eq 0 ]; then rec MAC-04 1.3.1 L2 MAC PASS "All AppArmor profiles are enforcing" "$ev"; else rec MAC-04 1.3.1 L2 MAC FAIL "All AppArmor profiles are enforcing" "$ev"; fi

# 1.4 bootloader
if grep -qE '^\s*set superusers' /boot/grub/grub.cfg 2>/dev/null && grep -qE '^\s*password_pbkdf2' /boot/grub/grub.cfg; then rec BOOT-01 1.4 L1 BOOT PASS "Bootloader password is set" "superusers + password_pbkdf2 present"
else rec BOOT-01 1.4 L1 BOOT FAIL "Bootloader password is set" "no superusers/password_pbkdf2 in grub.cfg"; fi
chk_perm BOOT-02 1.4 L1 BOOT /boot/grub/grub.cfg 600 root root "Access to bootloader config is restricted"

# 1.5 process hardening
chk_sysctl PROC-01 1.5 L1 PROC kernel.randomize_va_space 2 "Address space layout randomization is enabled"
pt=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)
if [ "${pt:-0}" -ge 1 ]; then rec PROC-02 1.5 L1 PROC PASS "ptrace_scope is restricted" "kernel.yama.ptrace_scope=$pt"; else rec PROC-02 1.5 L1 PROC FAIL "ptrace_scope is restricted" "kernel.yama.ptrace_scope=${pt:-unset}"; fi
core_lim=$(grep -rhsE '^\s*\*\s+hard\s+core\s+0' /etc/security/limits.conf /etc/security/limits.d 2>/dev/null | head -1)
sd=$(sysctl -n fs.suid_dumpable)
if [ -n "$core_lim" ] && [ "$sd" = 0 ]; then rec PROC-03 1.5 L1 PROC PASS "Core dumps are restricted" "hard core 0; fs.suid_dumpable=0"
else rec PROC-03 1.5 L1 PROC FAIL "Core dumps are restricted" "limits='${core_lim:-<no hard core 0>}' fs.suid_dumpable=$sd"; fi
chk_pkg_absent PROC-04 1.5 L1 PROC "prelink is not installed" prelink
if unit_on apport.service || grep -qsE '^\s*enabled\s*=\s*1' /etc/default/apport; then rec PROC-05 1.5 L1 PROC FAIL "Automatic error reporting (apport) is disabled" "apport enabled"
else rec PROC-05 1.5 L1 PROC PASS "Automatic error reporting (apport) is disabled" "apport disabled or absent"; fi
chk_sysctl PROC-06 1.5 X PROC kernel.kptr_restrict 2 "Kernel pointers are hidden from all users"
chk_sysctl PROC-07 1.5 X PROC kernel.dmesg_restrict 1 "dmesg is restricted to privileged users"
chk_sysctl PROC-08 1.5 X PROC fs.protected_hardlinks 1 "Hardlink protection is enabled"
chk_sysctl PROC-09 1.5 X PROC fs.protected_symlinks 1 "Symlink protection is enabled"
chk_sysctl PROC-10 1.5 X PROC kernel.unprivileged_bpf_disabled 1 "Unprivileged eBPF is disabled"
if unit_on kdump-tools.service; then rec PROC-11 1.5 X PROC FAIL "kdump (kernel crash dumps) is not enabled without a need" "kdump-tools enabled; crashkernel memory reserved and full-RAM dumps written to disk"
else rec PROC-11 1.5 X PROC PASS "kdump (kernel crash dumps) is not enabled without a need" "kdump-tools not enabled"; fi

# 1.6 banners
for f in /etc/motd /etc/issue /etc/issue.net; do
  id="BAN-$(basename $f | tr -d .)"
  if [ ! -s "$f" ] && [ "$f" != /etc/motd ]; then rec "$id" 1.6 L1 BANNER FAIL "$f carries a legal warning banner without OS details" "missing or empty"
  elif grep -qsiE '(\\[mrsv])|ubuntu|debian|linux [0-9]' "$f"; then rec "$id" 1.6 L1 BANNER FAIL "$f carries a legal warning banner without OS details" "$(head -c 80 "$f" | tr '\n' ' ')"
  else rec "$id" 1.6 L1 BANNER PASS "$f carries a legal warning banner without OS details" "$(head -c 60 "$f" 2>/dev/null | tr '\n' ' ')"; fi
  chk_perm "$id-perm" 1.6 L1 BANNER "$f" 644 root root
done
if pkg_installed gdm3; then rec GDM-01 1.7 L1 BANNER MANUAL "GDM is hardened or removed" "gdm3 installed - review 1.7 manually"
else rec GDM-01 1.7 L1 BANNER NA "GDM is hardened or removed" "no display manager installed (server)"; fi

# ============================================================ 2 Services ====
chk_svc_off SVC-01 2.1 L1 SVC "autofs is not in use" autofs autofs.service
chk_svc_off SVC-02 2.1 L1 SVC "avahi daemon is not in use" avahi-daemon avahi-daemon.service avahi-daemon.socket
chk_svc_off SVC-03 2.1 L1 SVC "DHCP server is not in use" isc-dhcp-server isc-dhcp-server.service kea-dhcp4-server.service
chk_svc_off SVC-04 2.1 L1 SVC "DNS server is not in use" bind9 named.service
chk_svc_off SVC-05 2.1 L1 SVC "dnsmasq is not in use" dnsmasq dnsmasq.service
chk_svc_off SVC-06 2.1 L1 SVC "FTP server is not in use" vsftpd vsftpd.service
chk_svc_off SVC-07 2.1 L1 SVC "LDAP server is not in use" slapd slapd.service
chk_svc_off SVC-08 2.1 L1 SVC "Message access (IMAP/POP3) server is not in use" dovecot-core dovecot.service
chk_svc_off SVC-09 2.1 L1 SVC "NFS server is not in use" nfs-kernel-server nfs-server.service
chk_svc_off SVC-10 2.1 L1 SVC "NIS server is not in use" ypserv ypserv.service
chk_svc_off SVC-11 2.1 L1 SVC "Print server (CUPS) is not in use" cups cups.service cups.socket
chk_svc_off SVC-12 2.1 L1 SVC "rpcbind is not in use" rpcbind rpcbind.service rpcbind.socket
chk_svc_off SVC-13 2.1 L1 SVC "rsync daemon is not in use" rsync rsync.service
chk_svc_off SVC-14 2.1 L1 SVC "Samba file server is not in use" samba smbd.service
chk_svc_off SVC-15 2.1 L1 SVC "SNMP daemon is not in use" snmpd snmpd.service
chk_svc_off SVC-16 2.1 L1 SVC "TFTP server is not in use" tftpd-hpa tftpd-hpa.service
chk_svc_off SVC-17 2.1 L1 SVC "Web proxy server is not in use" squid squid.service
chk_svc_off SVC-18 2.1 L1 SVC "Web server is not in use" apache2 apache2.service nginx.service
chk_svc_off SVC-19 2.1 L1 SVC "xinetd is not in use" xinetd xinetd.service
chk_pkg_absent SVC-20 2.1 L2 SVC "X window server is not installed" xserver-common
mta=$(ss -Hltn 2>/dev/null | awk '$4 ~ /:(25|465|587)$/ && $4 !~ /^(127\.|\[::1\])/{print $4}' | tr '\n' ' ')
if [ -z "$mta" ]; then rec SVC-21 2.1 L1 SVC PASS "Mail transfer agent is local-only" "no non-loopback listener on 25/465/587"; else rec SVC-21 2.1 L1 SVC FAIL "Mail transfer agent is local-only" "$mta"; fi
listen=$(ss -Hltnup 2>/dev/null | awk '{split($7,a,"\""); print $1"/"$5"("a[2]")"}' | sort -u | tr '\n' ' ')
rec SVC-22 2.1 L1 SVC MANUAL "Only approved services listen on a network interface" "$listen"
# services that are present on a default Ubuntu server install but rarely needed on a VM/server
for u in ModemManager.service multipathd.service open-iscsi.service iscsid.socket udisks2.service fwupd.service thermald.service upower.service smartmontools.service lxd-installer.socket open-vm-tools.service; do
  unit_on "$u" && extra_on="${extra_on:-}$u "
done
if [ -z "${extra_on:-}" ]; then rec SVC-23 2.1 X SVC PASS "No unneeded hardware/desktop helper services are enabled" ""
else rec SVC-23 2.1 X SVC MANUAL "No unneeded hardware/desktop helper services are enabled" "review: $extra_on"; fi

chk_pkg_absent CLI-01 2.2 L1 CLIENT "NIS client is not installed" nis
chk_pkg_absent CLI-02 2.2 L1 CLIENT "rsh client is not installed" rsh-client
chk_pkg_absent CLI-03 2.2 L1 CLIENT "talk client is not installed" talk
chk_pkg_absent CLI-04 2.2 L1 CLIENT "telnet client is not installed" telnet inetutils-telnet
chk_pkg_absent CLI-05 2.2 L2 CLIENT "LDAP client is not installed" ldap-utils
chk_pkg_absent CLI-06 2.2 L1 CLIENT "ftp client is not installed" ftp tnftp

# 2.3 time
td=""; for u in chrony.service systemd-timesyncd.service ntp.service ntpsec.service; do systemctl is-active --quiet $u 2>/dev/null && td+="$u "; done
if [ "$(wc -w <<<"$td")" -eq 1 ]; then rec TIME-01 2.3 L1 TIME PASS "A single time synchronization daemon is in use" "$td"; else rec TIME-01 2.3 L1 TIME FAIL "A single time synchronization daemon is in use" "active: ${td:-none}"; fi
if [[ "$td" == *chrony* ]]; then
  srcs=$(grep -rhsE '^\s*(server|pool)\s' /etc/chrony/chrony.conf /etc/chrony/sources.d /etc/chrony/conf.d 2>/dev/null | awk '{print $2}' | tr '\n' ' ')
  [ -n "$srcs" ] && rec TIME-02 2.3 L1 TIME PASS "chrony has authorized time sources configured" "$srcs" || rec TIME-02 2.3 L1 TIME FAIL "chrony has authorized time sources configured" "no server/pool lines"
  cu=$(ps -o user= -C chronyd | sort -u | tr '\n' ' ')
  [[ "$cu" == "_chrony " ]] && rec TIME-03 2.3 L1 TIME PASS "chronyd runs as the _chrony user" "$cu" || rec TIME-03 2.3 L1 TIME FAIL "chronyd runs as the _chrony user" "${cu:-not running}"
fi

# 2.4 cron
if unit_on cron.service; then rec CRON-01 2.4 L1 CRON PASS "cron daemon is enabled and active" ""; else rec CRON-01 2.4 L1 CRON FAIL "cron daemon is enabled and active" ""; fi
chk_perm CRON-02 2.4 L1 CRON /etc/crontab 600 root root
i=3; for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do chk_perm "CRON-0$i" 2.4 L1 CRON $d 700 root root; i=$((i+1)); done
if [ -f /etc/cron.allow ] && [ ! -f /etc/cron.deny ]; then chk_perm CRON-08 2.4 L1 CRON /etc/cron.allow 640 root 'root|crontab' "crontab is restricted to authorized users (cron.allow)"
else rec CRON-08 2.4 L1 CRON FAIL "crontab is restricted to authorized users (cron.allow)" "cron.allow=$([ -f /etc/cron.allow ] && echo present || echo missing) cron.deny=$([ -f /etc/cron.deny ] && echo present || echo missing)"; fi
if ! pkg_installed at; then rec CRON-09 2.4 L1 CRON NA "at is restricted to authorized users (at.allow)" "at not installed"
elif [ -f /etc/at.allow ] && [ ! -f /etc/at.deny ]; then chk_perm CRON-09 2.4 L1 CRON /etc/at.allow 640 root 'root|daemon' "at is restricted to authorized users (at.allow)"
else rec CRON-09 2.4 L1 CRON FAIL "at is restricted to authorized users (at.allow)" "at.allow missing or at.deny present"; fi

# ============================================================= 3 Network ====
wl=$(find /sys/class/net/*/ -maxdepth 1 -name wireless 2>/dev/null | wc -l)
[ "$wl" -eq 0 ] && rec NET-01 3.1 L1 NET-DEV PASS "Wireless interfaces are disabled" "no wireless NICs" || rec NET-01 3.1 L1 NET-DEV FAIL "Wireless interfaces are disabled" "$wl wireless NIC(s)"
chk_svc_off NET-02 3.1 L1 NET-DEV "Bluetooth services are not in use" bluez bluetooth.service
rec NET-03 3.1 L1 NET-DEV MANUAL "IPv6 status is identified and intentional" "disable_ipv6(all)=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null); global v6 addrs: $(ip -6 -o addr show scope global 2>/dev/null | wc -l)"

chk_mod NET-04 3.2 L2 NET-MOD dccp
chk_mod NET-05 3.2 L2 NET-MOD tipc
chk_mod NET-06 3.2 L2 NET-MOD rds
chk_mod NET-07 3.2 L2 NET-MOD sctp

if [ $HAS_DOCKER -eq 1 ]; then rec NET-10 3.3 L1 NET-SYSCTL NA "IP forwarding is disabled" "net.ipv4.ip_forward=$(sysctl -n net.ipv4.ip_forward): required by Docker bridge networking - documented exception; forwarding is confined by the FORWARD chain policy"
else chk_sysctl NET-10 3.3 L1 NET-SYSCTL net.ipv4.ip_forward 0 "IP forwarding is disabled"; fi
chk_sysctl NET-11 3.3 L1 NET-SYSCTL net.ipv6.conf.all.forwarding 0 "IPv6 forwarding is disabled"
i=12
for kv in net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0 \
  net.ipv4.icmp_ignore_bogus_error_responses=1 net.ipv4.icmp_echo_ignore_broadcasts=1 \
  net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0 \
  net.ipv6.conf.all.accept_redirects=0 net.ipv6.conf.default.accept_redirects=0 \
  net.ipv4.conf.all.secure_redirects=0 net.ipv4.conf.default.secure_redirects=0 \
  net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1 \
  net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.default.accept_source_route=0 \
  net.ipv6.conf.all.accept_source_route=0 net.ipv6.conf.default.accept_source_route=0 \
  net.ipv4.conf.all.log_martians=1 net.ipv4.conf.default.log_martians=1 \
  net.ipv4.tcp_syncookies=1 \
  net.ipv6.conf.all.accept_ra=0 net.ipv6.conf.default.accept_ra=0; do
  chk_sysctl "NET-$i" 3.3 L1 NET-SYSCTL "${kv%=*}" "${kv#*=}"; i=$((i+1))
done

# ============================================================ 4 Firewall ====
fw=""; ufw_active=0
if has ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then fw+="ufw "; ufw_active=1; fi
systemctl is-active --quiet firewalld 2>/dev/null && fw+="firewalld "
nft_input=$(nft list ruleset 2>/dev/null | grep -E 'hook input' | grep -v 'ufw' | head -3)
[ $ufw_active -eq 0 ] && [ -n "$nft_input" ] && fw+="nftables "
if [ "$(wc -w <<<"$fw")" -eq 1 ]; then rec FW-01 4 L1 FW PASS "A single host firewall is in use" "$fw"; else rec FW-01 4 L1 FW FAIL "A single host firewall is in use" "active: ${fw:-none}"; fi
in_pol=$(nft list ruleset 2>/dev/null | grep -E 'hook input' | grep -oE 'policy (accept|drop)' | sort -u | tr '\n' ' ')
if [ $ufw_active -eq 1 ]; then
  ud=$(ufw status verbose | awk -F: '/^Default/{print $2}')
  [[ "$ud" == *"deny (incoming)"* || "$ud" == *"reject (incoming)"* ]] && rec FW-02 4 L1 FW PASS "Default inbound policy is deny" "$ud" || rec FW-02 4 L1 FW FAIL "Default inbound policy is deny" "$ud"
  [[ "$ud" == *"deny (routed)"* || "$ud" == *"disabled (routed)"* || "$ud" == *"reject (routed)"* ]] && rec FW-03 4 L1 FW PASS "Default routed/forward policy is deny" "$ud" || rec FW-03 4 L1 FW FAIL "Default routed/forward policy is deny" "$ud"
  rules=$(ufw status | awk 'NR>4 && NF{print $1"<-"$NF}' | sort -u | tr '\n' ' ')
  rec FW-04 4 L1 FW MANUAL "Firewall rules exist only for approved open ports" "$rules"
  lo=$(iptables -S ufw-before-input 2>/dev/null | grep -c -- '-i lo -j ACCEPT')
  [ "$lo" -ge 1 ] && rec FW-05 4 L1 FW PASS "Loopback traffic is configured" "ufw-before-input accepts lo" || rec FW-05 4 L1 FW FAIL "Loopback traffic is configured" "no lo accept rule"
else
  if [[ -n "$in_pol" && "$in_pol" != *accept* ]]; then rec FW-02 4 L1 FW PASS "Default inbound policy is deny" "nft input: $in_pol"; else rec FW-02 4 L1 FW FAIL "Default inbound policy is deny" "nft input hooks: ${in_pol:-none (all inbound traffic accepted)}"; fi
  fp=$(nft list ruleset 2>/dev/null | grep -E 'hook forward' | grep -oE 'policy (accept|drop)' | sort -u | tr '\n' ' ')
  [[ -n "$fp" && "$fp" != *accept* ]] && rec FW-03 4 L1 FW PASS "Default routed/forward policy is deny" "nft forward: $fp" || rec FW-03 4 L1 FW FAIL "Default routed/forward policy is deny" "nft forward hooks: ${fp:-none}"
  rec FW-04 4 L1 FW FAIL "Firewall rules exist only for approved open ports" "no host firewall ruleset for inbound traffic"
  rec FW-05 4 L1 FW FAIL "Loopback traffic is configured" "no host firewall"
fi
if [ $HAS_DOCKER -eq 1 ]; then
  pubs=$(docker ps --format '{{.Ports}}' 2>/dev/null | tr '\n' ' ' | head -c 150)
  if iptables -S DOCKER-USER 2>/dev/null | tail -1 | grep -qE -- '-j DROP$'; then
    allowed=$(iptables -S DOCKER-USER 2>/dev/null | grep -oE 'ctorigdstport [0-9]+' | awk '{print $2}' | sort -un | tr '\n' ' ')
    rec FW-06 4 X FW PASS "Docker published ports are filtered (DOCKER-USER chain)" "default drop; allowed from outside: ${allowed:-none}; published: ${pubs:-none}"
  else
    rec FW-06 4 X FW MANUAL "Docker published ports are filtered (DOCKER-USER chain)" "Docker DNAT bypasses INPUT/ufw and DOCKER-USER does not end in DROP; published ports: ${pubs:-none}"
  fi
fi

# ====================================================== 5 Access control ====
# 5.1 SSH server
chk_perm SSH-01 5.1 L1 SSH /etc/ssh/sshd_config 600 root root
bad=$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key' \( -perm /077 -o ! -user root \) 2>/dev/null | tr '\n' ' ')
[ -z "$bad" ] && rec SSH-02 5.1 L1 SSH PASS "SSH private host keys are 0600 root" "" || rec SSH-02 5.1 L1 SSH FAIL "SSH private host keys are 0600 root" "$bad"
bad=$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' \( -perm /022 -o ! -user root \) 2>/dev/null | tr '\n' ' ')
[ -z "$bad" ] && rec SSH-03 5.1 L1 SSH PASS "SSH public host keys are 0644 root or stricter" "" || rec SSH-03 5.1 L1 SSH FAIL "SSH public host keys are 0644 root or stricter" "$bad"
acl="allowusers=$(sshd_val allowusers) allowgroups=$(sshd_val allowgroups) denyusers=$(sshd_val denyusers) denygroups=$(sshd_val denygroups)"
if grep -qE '^(allowusers|allowgroups|denyusers|denygroups) ' <<<"$SSHD_T"; then rec SSH-04 5.1 L1 SSH PASS "SSH access is limited to named users/groups" "$acl"; else rec SSH-04 5.1 L1 SSH FAIL "SSH access is limited to named users/groups" "no AllowUsers/AllowGroups/DenyUsers/DenyGroups"; fi
chk_sshd SSH-05 L1 banner '/.+' "SSH warning banner is configured"
c=$(sshd_val ciphers); weak=$(tr ',' '\n' <<<"$c" | grep -E 'cbc|3des|arcfour|blowfish|cast128|rijndael' | tr '\n' ' ')
[ -z "$weak" ] && rec SSH-06 5.1 L1 SSH PASS "Only strong SSH ciphers are used" "$c" || rec SSH-06 5.1 L1 SSH FAIL "Only strong SSH ciphers are used" "weak: $weak"
cai=$(sshd_val clientaliveinterval); cac=$(sshd_val clientalivecountmax)
if [ "${cai:-0}" -gt 0 ] && [ "${cac:-0}" -gt 0 ]; then rec SSH-07 5.1 L1 SSH PASS "SSH idle timeout (ClientAlive*) is configured" "interval=$cai countmax=$cac"; else rec SSH-07 5.1 L1 SSH FAIL "SSH idle timeout (ClientAlive*) is configured" "interval=$cai countmax=$cac"; fi
if [ "$(sshd_val disableforwarding)" = yes ] || { [ "$(sshd_val allowtcpforwarding)" = no ] && [ "$(sshd_val x11forwarding)" = no ] && [ "$(sshd_val allowagentforwarding)" = no ]; }; then
  rec SSH-08 5.1 L1 SSH PASS "SSH forwarding (TCP, X11, agent) is disabled" "disableforwarding=$(sshd_val disableforwarding) tcp=$(sshd_val allowtcpforwarding) x11=$(sshd_val x11forwarding) agent=$(sshd_val allowagentforwarding)"
else rec SSH-08 5.1 L1 SSH FAIL "SSH forwarding (TCP, X11, agent) is disabled" "disableforwarding=$(sshd_val disableforwarding) tcp=$(sshd_val allowtcpforwarding) x11=$(sshd_val x11forwarding) agent=$(sshd_val allowagentforwarding)"; fi
chk_sshd SSH-09 L1 gssapiauthentication no "SSH GSSAPIAuthentication is disabled"
chk_sshd SSH-10 L1 hostbasedauthentication no "SSH HostbasedAuthentication is disabled"
chk_sshd SSH-11 L1 ignorerhosts yes "SSH IgnoreRhosts is enabled"
k=$(sshd_val kexalgorithms); weak=$(tr ',' '\n' <<<"$k" | grep -E 'sha1$|group1-|group-exchange-sha1' | tr '\n' ' ')
[ -z "$weak" ] && rec SSH-12 5.1 L1 SSH PASS "Only strong SSH key exchange algorithms are used" "$k" || rec SSH-12 5.1 L1 SSH FAIL "Only strong SSH key exchange algorithms are used" "weak: $weak"
chk_sshd_num SSH-13 L1 logingracetime 1 60 "SSH LoginGraceTime is 60 seconds or less"
chk_sshd SSH-14 L1 loglevel 'info|verbose' "SSH LogLevel is INFO or VERBOSE"
m=$(sshd_val macs); weak=$(tr ',' '\n' <<<"$m" | grep -E 'md5|ripemd|sha1|umac-64' | tr '\n' ' ')
[ -z "$weak" ] && rec SSH-15 5.1 L1 SSH PASS "Only strong SSH MACs are used" "$m" || rec SSH-15 5.1 L1 SSH FAIL "Only strong SSH MACs are used" "weak: $weak"
chk_sshd_num SSH-16 L1 maxauthtries 1 4 "SSH MaxAuthTries is 4 or less"
chk_sshd_num SSH-17 L1 maxsessions 1 10 "SSH MaxSessions is 10 or less"
ms=$(sshd_val maxstartups); IFS=: read -r a b c3 <<<"$ms"
if [ "${a:-99}" -le 10 ] && [ "${b:-99}" -le 30 ] && [ "${c3:-999}" -le 60 ]; then rec SSH-18 5.1 L1 SSH PASS "SSH MaxStartups is 10:30:60 or stricter" "$ms"; else rec SSH-18 5.1 L1 SSH FAIL "SSH MaxStartups is 10:30:60 or stricter" "$ms"; fi
chk_sshd SSH-19 L1 permitemptypasswords no "SSH PermitEmptyPasswords is disabled"
chk_sshd SSH-20 L1 permitrootlogin no "SSH root login is disabled"
chk_sshd SSH-21 L1 permituserenvironment no "SSH PermitUserEnvironment is disabled"
chk_sshd SSH-22 L1 usepam yes "SSH UsePAM is enabled"
chk_sshd SSH-23 X passwordauthentication no "SSH password authentication is disabled (keys only)"
nkeys=$(cat /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null | grep -cE '^(ssh-|ecdsa-|sk-)')
rec SSH-24 5.1 X SSH MANUAL "authorized_keys entries are known and approved" "$nkeys key(s) across all users"

# 5.2 privilege escalation
pkg_installed sudo && rec SUDO-01 5.2 L1 SUDO PASS "sudo is installed" "" || rec SUDO-01 5.2 L1 SUDO FAIL "sudo is installed" ""
SUDOERS=$(cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -vE '^\s*#($|[^i])')
grep -qE '^\s*Defaults\s+.*\buse_pty\b' <<<"$SUDOERS" && rec SUDO-02 5.2 L1 SUDO PASS "sudo commands use a pty" "" || rec SUDO-02 5.2 L1 SUDO FAIL "sudo commands use a pty" "no Defaults use_pty"
lf=$(grep -E '^\s*Defaults\s+.*logfile\s*=' <<<"$SUDOERS" | head -1)
SUDO_RS=0; sudo --version 2>/dev/null | grep -q 'sudo-rs' && SUDO_RS=1
if [ -n "$lf" ]; then rec SUDO-03 5.2 L1 SUDO PASS "sudo has a dedicated log file" "$lf"
elif [ $SUDO_RS -eq 1 ]; then rec SUDO-03 5.2 L1 SUDO NA "sudo has a dedicated log file" "active sudo is sudo-rs, which rejects 'Defaults logfile' as a syntax error; sudo events are in journal/auth.log and the audit trail (user_emulation)"
else rec SUDO-03 5.2 L1 SUDO FAIL "sudo has a dedicated log file" "no Defaults logfile="; fi
np=$(grep -E '^[^#].*NOPASSWD' <<<"$SUDOERS" | tr '\n' ';')
[ -z "$np" ] && rec SUDO-04 5.2 L2 SUDO PASS "sudo requires a password (no NOPASSWD)" "" || rec SUDO-04 5.2 L2 SUDO FAIL "sudo requires a password (no NOPASSWD)" "$np"
na=$(grep -E '^[^#].*!authenticate' <<<"$SUDOERS" | tr '\n' ';')
[ -z "$na" ] && rec SUDO-05 5.2 L1 SUDO PASS "sudo re-authentication is not disabled globally" "" || rec SUDO-05 5.2 L1 SUDO FAIL "sudo re-authentication is not disabled globally" "$na"
tt=$(grep -oE 'timestamp_timeout\s*=\s*-?[0-9]+' <<<"$SUDOERS" | grep -oE '\-?[0-9]+$' | tail -1)
if [ -z "$tt" ] || { [ "$tt" -ge 0 ] && [ "$tt" -le 15 ]; }; then rec SUDO-06 5.2 L1 SUDO PASS "sudo authentication timeout is 15 minutes or less" "timestamp_timeout=${tt:-default(15)}"; else rec SUDO-06 5.2 L1 SUDO FAIL "sudo authentication timeout is 15 minutes or less" "timestamp_timeout=$tt"; fi
pw=$(grep -E '^\s*auth\s+required\s+pam_wheel\.so.*use_uid.*group=' /etc/pam.d/su 2>/dev/null)
if [ -n "$pw" ]; then g=$(grep -oE 'group=\S+' <<<"$pw" | cut -d= -f2); rec SUDO-07 5.2 L1 SUDO PASS "Access to su is restricted (pam_wheel)" "group=$g members=$(getent group "$g" | cut -d: -f4)"
elif [ "$(stat -Lc %a /usr/bin/su)" = 750 ] || [ "$(stat -Lc %a /usr/bin/su)" = 4750 ]; then rec SUDO-07 5.2 L1 SUDO PASS "Access to su is restricted (pam_wheel)" "su binary mode $(stat -Lc %a /usr/bin/su) (root only)"
else rec SUDO-07 5.2 L1 SUDO FAIL "Access to su is restricted (pam_wheel)" "pam_wheel not configured in /etc/pam.d/su"; fi
sg=$(getent group sudo | cut -d: -f4); rec SUDO-08 5.2 X SUDO MANUAL "Membership of privileged groups is reviewed" "sudo=[$sg] docker=[$(getent group docker | cut -d: -f4)] lxd=[$(getent group lxd | cut -d: -f4)] adm=[$(getent group adm | cut -d: -f4)] (docker/lxd membership is root-equivalent)"

# 5.3 PAM
CA=/etc/pam.d/common-auth; CP=/etc/pam.d/common-password; CACC=/etc/pam.d/common-account
pkg_installed libpam-pwquality && rec PAM-01 5.3 L1 PAM PASS "libpam-pwquality is installed" "" || rec PAM-01 5.3 L1 PAM FAIL "libpam-pwquality is installed" ""
if grep -qE '^\s*auth\s.*pam_faillock\.so.*preauth' $CA && grep -qE '^\s*auth\s.*pam_faillock\.so.*authfail' $CA && grep -qE '^\s*account\s.*pam_faillock\.so' $CACC; then rec PAM-02 5.3 L1 PAM PASS "pam_faillock is enabled (auth + account)" ""
else rec PAM-02 5.3 L1 PAM FAIL "pam_faillock is enabled (auth + account)" "preauth/authfail/account lines missing"; fi
grep -qE '^\s*password\s.*pam_pwquality\.so' $CP && rec PAM-03 5.3 L1 PAM PASS "pam_pwquality is enabled" "" || rec PAM-03 5.3 L1 PAM FAIL "pam_pwquality is enabled" "not in common-password"
ph=$(grep -E '^\s*password\s.*pam_pwhistory\.so' $CP)
[ -n "$ph" ] && rec PAM-04 5.3 L1 PAM PASS "pam_pwhistory is enabled" "" || rec PAM-04 5.3 L1 PAM FAIL "pam_pwhistory is enabled" "not in common-password"
FL=/etc/security/faillock.conf
fl_deny=$(conf_val deny $FL /etc/security/faillock.conf.d); fl_unlock=$(conf_val unlock_time $FL /etc/security/faillock.conf.d)
if [ -n "$fl_deny" ] && [ "$fl_deny" -ge 1 ] && [ "$fl_deny" -le 5 ]; then rec PAM-05 5.3 L1 PAM PASS "Account lockout threshold is 5 failures or fewer" "deny=$fl_deny"; else rec PAM-05 5.3 L1 PAM FAIL "Account lockout threshold is 5 failures or fewer" "deny=${fl_deny:-<unset>}"; fi
if [ -n "$fl_unlock" ] && { [ "$fl_unlock" -eq 0 ] || [ "$fl_unlock" -ge 900 ]; }; then rec PAM-06 5.3 L1 PAM PASS "Account lockout lasts 15 minutes or more" "unlock_time=$fl_unlock"; else rec PAM-06 5.3 L1 PAM FAIL "Account lockout lasts 15 minutes or more" "unlock_time=${fl_unlock:-<unset>}"; fi
if grep -qsE '^\s*(even_deny_root|root_unlock_time)' $FL; then rec PAM-07 5.3 L2 PAM PASS "Lockout also applies to root" ""; else rec PAM-07 5.3 L2 PAM FAIL "Lockout also applies to root" "no even_deny_root"; fi
PQ=/etc/security/pwquality.conf; PQD=/etc/security/pwquality.conf.d
pq() { conf_val "$1" $PQ $PQD; }
v=$(pq difok);       { [ -n "$v" ] && [ "$v" -ge 2 ]; } && rec PAM-08 5.3 L1 PAM PASS "Password must differ by 2+ characters (difok)" "difok=$v" || rec PAM-08 5.3 L1 PAM FAIL "Password must differ by 2+ characters (difok)" "difok=${v:-<unset>}"
v=$(pq minlen);      { [ -n "$v" ] && [ "$v" -ge 14 ]; } && rec PAM-09 5.3 L1 PAM PASS "Minimum password length is 14 or more" "minlen=$v" || rec PAM-09 5.3 L1 PAM FAIL "Minimum password length is 14 or more" "minlen=${v:-<unset, default 8>}"
mc=$(pq minclass); cr="d=$(pq dcredit) u=$(pq ucredit) l=$(pq lcredit) o=$(pq ocredit)"
if { [ -n "$mc" ] && [ "$mc" -ge 3 ]; } || [[ "$cr" =~ d=-[1-9].*u=-[1-9].*l=-[1-9] ]]; then rec PAM-10 5.3 L1 PAM PASS "Password complexity is enforced" "minclass=$mc $cr"; else rec PAM-10 5.3 L1 PAM FAIL "Password complexity is enforced" "minclass=${mc:-<unset>} $cr"; fi
v=$(pq maxrepeat);   { [ -n "$v" ] && [ "$v" -ge 1 ] && [ "$v" -le 3 ]; } && rec PAM-11 5.3 L1 PAM PASS "Same consecutive characters are limited (maxrepeat)" "maxrepeat=$v" || rec PAM-11 5.3 L1 PAM FAIL "Same consecutive characters are limited (maxrepeat)" "maxrepeat=${v:-<unset>}"
v=$(pq maxsequence); { [ -n "$v" ] && [ "$v" -ge 1 ] && [ "$v" -le 3 ]; } && rec PAM-12 5.3 L1 PAM PASS "Sequential characters are limited (maxsequence)" "maxsequence=$v" || rec PAM-12 5.3 L1 PAM FAIL "Sequential characters are limited (maxsequence)" "maxsequence=${v:-<unset>}"
v=$(pq dictcheck);   [ "${v:-1}" != 0 ] && pkg_installed libpam-pwquality && rec PAM-13 5.3 L1 PAM PASS "Dictionary check is enabled" "dictcheck=${v:-default(1)}" || rec PAM-13 5.3 L1 PAM FAIL "Dictionary check is enabled" "dictcheck=${v:-n/a (pwquality absent)}"
grep -qsE '^\s*enforce_for_root' $PQ $PQD/*.conf && rec PAM-14 5.3 L1 PAM PASS "Password quality is enforced for root" "" || rec PAM-14 5.3 L1 PAM FAIL "Password quality is enforced for root" "no enforce_for_root"
rem=$(grep -oE 'remember=[0-9]+' <<<"$ph" | cut -d= -f2); [ -z "$rem" ] && rem=$(conf_val remember /etc/security/pwhistory.conf /nonexistent)
{ [ -n "$ph" ] && [ -n "$rem" ] && [ "$rem" -ge 24 ]; } && rec PAM-15 5.3 L1 PAM PASS "Password history remembers 24 or more" "remember=$rem" || rec PAM-15 5.3 L1 PAM FAIL "Password history remembers 24 or more" "remember=${rem:-<unset>}"
nl=$(grep -lE '^\s*[^#].*pam_unix\.so.*\bnullok\b' /etc/pam.d/common-* 2>/dev/null | tr '\n' ' ')
[ -z "$nl" ] && rec PAM-16 5.3 L1 PAM PASS "pam_unix does not allow empty passwords (nullok)" "" || rec PAM-16 5.3 L1 PAM FAIL "pam_unix does not allow empty passwords (nullok)" "$nl"
grep -qE '^\s*password\s.*pam_unix\.so.*\b(yescrypt|sha512)\b' $CP && rec PAM-17 5.3 L1 PAM PASS "pam_unix uses a strong password hash" "$(grep -oE 'yescrypt|sha512' $CP | head -1)" || rec PAM-17 5.3 L1 PAM FAIL "pam_unix uses a strong password hash" ""
grep -qE '^\s*password\s.*pam_unix\.so.*\buse_authtok\b' $CP && rec PAM-18 5.3 L1 PAM PASS "pam_unix honours the quality-checked password (use_authtok)" "" || rec PAM-18 5.3 L1 PAM FAIL "pam_unix honours the quality-checked password (use_authtok)" "pam_unix line has no use_authtok"

# 5.4 user accounts and environment
ld() { awk -v k="$1" '$1==k{print $2}' /etc/login.defs | tail -1; }
v=$(ld PASS_MAX_DAYS); { [ -n "$v" ] && [ "$v" -ge 1 ] && [ "$v" -le 365 ]; } && rec ACCT-01 5.4 L1 ACCT PASS "Password expiration is 365 days or less (login.defs)" "PASS_MAX_DAYS=$v" || rec ACCT-01 5.4 L1 ACCT FAIL "Password expiration is 365 days or less (login.defs)" "PASS_MAX_DAYS=$v"
bad=$(awk -F: '$2 ~ /^\$/ && ($5=="" || $5>365 || $5<1){print $1"="$5}' /etc/shadow | tr '\n' ' ')
[ -z "$bad" ] && rec ACCT-02 5.4 L1 ACCT PASS "Existing password accounts expire within 365 days" "" || rec ACCT-02 5.4 L1 ACCT FAIL "Existing password accounts expire within 365 days" "max days: $bad"
v=$(ld PASS_MIN_DAYS); { [ -n "$v" ] && [ "$v" -ge 1 ]; } && rec ACCT-03 5.4 L2 ACCT PASS "Minimum password age is 1 day or more" "PASS_MIN_DAYS=$v" || rec ACCT-03 5.4 L2 ACCT FAIL "Minimum password age is 1 day or more" "PASS_MIN_DAYS=$v"
v=$(ld PASS_WARN_AGE); { [ -n "$v" ] && [ "$v" -ge 7 ]; } && rec ACCT-04 5.4 L1 ACCT PASS "Password expiry warning is 7 days or more" "PASS_WARN_AGE=$v" || rec ACCT-04 5.4 L1 ACCT FAIL "Password expiry warning is 7 days or more" "PASS_WARN_AGE=$v"
v=$(ld ENCRYPT_METHOD); [[ "${v^^}" =~ ^(YESCRYPT|SHA512)$ ]] && rec ACCT-05 5.4 L1 ACCT PASS "Strong password hashing algorithm is configured" "ENCRYPT_METHOD=$v" || rec ACCT-05 5.4 L1 ACCT FAIL "Strong password hashing algorithm is configured" "ENCRYPT_METHOD=$v"
v=$(useradd -D | awk -F= '/^INACTIVE/{print $2}'); { [ "$v" -ge 0 ] && [ "$v" -le 45 ]; } 2>/dev/null && rec ACCT-06 5.4 L1 ACCT PASS "Inactive password lock is 45 days or less" "INACTIVE=$v" || rec ACCT-06 5.4 L1 ACCT FAIL "Inactive password lock is 45 days or less" "INACTIVE=$v"
today=$(( $(date +%s) / 86400 )); bad=$(awk -F: -v t=$today '$2 ~ /^\$/ && $3>t{print $1}' /etc/shadow | tr '\n' ' ')
[ -z "$bad" ] && rec ACCT-07 5.4 L1 ACCT PASS "No user has a last password change date in the future" "" || rec ACCT-07 5.4 L1 ACCT FAIL "No user has a last password change date in the future" "$bad"
u0=$(awk -F: '$3==0{print $1}' /etc/passwd | tr '\n' ' '); [ "$u0" = "root " ] && rec ACCT-08 5.4 L1 ACCT PASS "root is the only UID 0 account" "" || rec ACCT-08 5.4 L1 ACCT FAIL "root is the only UID 0 account" "$u0"
g0=$(awk -F: '$4==0 && $1!~/^(root|sync|shutdown|halt|operator)$/{print $1}' /etc/passwd | tr '\n' ' '); [ -z "$g0" ] && rec ACCT-09 5.4 L1 ACCT PASS "root is the only GID 0 account" "" || rec ACCT-09 5.4 L1 ACCT FAIL "root is the only GID 0 account" "$g0"
rs=$(passwd -S root | awk '{print $2}'); [[ "$rs" =~ ^(P|L)$ ]] && rec ACCT-10 5.4 L1 ACCT PASS "root account access is controlled (password set or locked)" "status=$rs" || rec ACCT-10 5.4 L1 ACCT FAIL "root account access is controlled (password set or locked)" "status=$rs"
rp=$(sudo -Hiu root env 2>/dev/null | awk -F= '/^PATH=/{print $2}'); badp=""
IFS=: read -ra parts <<<"$rp"; for d in "${parts[@]}"; do { [ -z "$d" ] || [ "$d" = . ]; } && badp+="empty/dot "; [ -d "$d" ] && [ -n "$(find -L "$d" -maxdepth 0 \( -perm /022 -o ! -user root \) 2>/dev/null)" ] && badp+="$d "; done
[ -z "$badp" ] && rec ACCT-11 5.4 L1 ACCT PASS "root PATH integrity" "$rp" || rec ACCT-11 5.4 L1 ACCT FAIL "root PATH integrity" "$badp"
bad=$(awk -F: '($3<1000 || $3==65534) && $1!="root" && $7!~/(nologin|false)$/ && $1!~/^(sync|shutdown|halt)$/{print $1":"$7}' /etc/passwd | tr '\n' ' ')
[ -z "$bad" ] && rec ACCT-12 5.4 L1 ACCT PASS "System accounts have no login shell" "" || rec ACCT-12 5.4 L1 ACCT FAIL "System accounts have no login shell" "$bad"
um=$(grep -rhsE '^\s*umask\s+[0-9]+' /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null | awk '{print $2}' | tail -1); lu=$(ld UMASK)
if [[ "${um:-$lu}" =~ ^0?[0-7][2367]7$ ]]; then rec ACCT-13 5.4 L1 ACCT PASS "Default user umask is 027 or stricter" "profile=${um:-<unset>} login.defs=$lu"; else rec ACCT-13 5.4 L1 ACCT FAIL "Default user umask is 027 or stricter" "profile=${um:-<unset>} login.defs=${lu:-<unset>}"; fi
tm=$(grep -rhsE '^\s*(readonly\s+|export\s+|declare\s+-r?x?\s+)?TMOUT=[0-9]+' /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null | grep -oE '[0-9]+' | tail -1)
{ [ -n "$tm" ] && [ "$tm" -ge 1 ] && [ "$tm" -le 900 ]; } && rec ACCT-14 5.4 L1 ACCT PASS "Shell idle timeout (TMOUT) is 900s or less" "TMOUT=$tm" || rec ACCT-14 5.4 L1 ACCT FAIL "Shell idle timeout (TMOUT) is 900s or less" "TMOUT=${tm:-<unset>}"
grep -qsE '/nologin\b' /etc/shells && rec ACCT-15 5.4 L2 ACCT FAIL "nologin is not listed in /etc/shells" "" || rec ACCT-15 5.4 L2 ACCT PASS "nologin is not listed in /etc/shells" ""
# X: trivially guessable passwords (tiny dictionary; this is a sanity check, not a cracking run)
weakpw=""
if has perl; then
  while IFS=: read -r u h _; do
    [[ "$h" == \$* ]] || continue
    for cand in 1234 12345 123456 12345678 password Password1 'P@ssw0rd' admin root toor ubuntu changeme qwerty letmein welcome "$u" "${u}123"; do
      [ "$(CAND="$cand" HASH="$h" perl -e 'print crypt($ENV{CAND},$ENV{HASH})' 2>/dev/null)" = "$h" ] && { weakpw+="$u "; break; }
    done
  done < /etc/shadow
  [ -z "$weakpw" ] && rec ACCT-16 5.4 X ACCT PASS "No account uses a trivially guessable password" "17-word dictionary + username" || rec ACCT-16 5.4 X ACCT FAIL "No account uses a trivially guessable password" "accounts: $weakpw(password value not recorded)"
fi

# ================================================ 6 Logging and auditing ====
systemctl is-active --quiet systemd-journald && rec LOG-01 6.1 L1 LOG PASS "journald is active" "" || rec LOG-01 6.1 L1 LOG FAIL "journald is active" ""
JD=$(systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -vE '^\s*#')
jv() { grep -E "^\s*$1=" <<<"$JD" | tail -1 | cut -d= -f2; }
[ "$(jv Compress)" = yes ] && rec LOG-02 6.1 L1 LOG PASS "journald compresses large log files" "" || rec LOG-02 6.1 L1 LOG FAIL "journald compresses large log files" "Compress=$(jv Compress) (not explicitly set)"
[ "$(jv Storage)" = persistent ] && rec LOG-03 6.1 L1 LOG PASS "journald writes logs to persistent disk" "" || rec LOG-03 6.1 L1 LOG FAIL "journald writes logs to persistent disk" "Storage=$(jv Storage) (not explicitly set)"
if pkg_installed rsyslog && unit_on rsyslog.service; then rec LOG-04 6.1 L1 LOG PASS "rsyslog is installed and enabled" ""
  fcm=$(grep -rhsE '^\s*\$FileCreateMode\s+[0-9]+' /etc/rsyslog.conf /etc/rsyslog.d | awk '{print $2}' | tail -1)
  { [ -n "$fcm" ] && [ $(( 0$fcm & ~0640 )) -eq 0 ]; } && rec LOG-05 6.1 L1 LOG PASS "rsyslog creates log files 0640 or stricter" "\$FileCreateMode $fcm" || rec LOG-05 6.1 L1 LOG FAIL "rsyslog creates log files 0640 or stricter" "\$FileCreateMode ${fcm:-<unset>}"
  rh=$(grep -rhsE '^\s*[^#].*(@@?[A-Za-z0-9\[]|omfwd|omrelp)' /etc/rsyslog.conf /etc/rsyslog.d | head -1)
  [ -n "$rh" ] && rec LOG-06 6.1 L1 LOG PASS "Logs are forwarded to a remote log host" "$rh" || rec LOG-06 6.1 L1 LOG FAIL "Logs are forwarded to a remote log host" "no forwarding action configured (logs only exist on this host)"
else rec LOG-04 6.1 L1 LOG FAIL "rsyslog is installed and enabled" ""; fi
bad=$(find /var/log -xdev -type f -perm /0137 ! -name 'wtmp*' ! -name 'btmp*' ! -name 'lastlog*' ! -path '/var/log/journal/*' 2>/dev/null | head -8 | tr '\n' ' ')
nbad=$(find /var/log -xdev -type f -perm /0137 ! -name 'wtmp*' ! -name 'btmp*' ! -name 'lastlog*' ! -path '/var/log/journal/*' 2>/dev/null | wc -l)
[ "$nbad" -eq 0 ] && rec LOG-07 6.1 L1 LOG PASS "Log files are not readable by other users" "" || rec LOG-07 6.1 L1 LOG FAIL "Log files are not readable by other users" "$nbad files more permissive than 0640, e.g. $bad"

# 6.2 auditd (CIS Level 2)
if pkg_installed auditd; then rec AUD-01 6.2 L2 AUDIT PASS "auditd is installed" ""; else rec AUD-01 6.2 L2 AUDIT FAIL "auditd is installed" ""; fi
systemctl is-active --quiet auditd && systemctl is-enabled --quiet auditd 2>/dev/null && rec AUD-02 6.2 L2 AUDIT PASS "auditd is enabled and active" "" || rec AUD-02 6.2 L2 AUDIT FAIL "auditd is enabled and active" ""
grep -qw 'audit=1' /proc/cmdline && rec AUD-03 6.2 L2 AUDIT PASS "Auditing starts before auditd (audit=1 on kernel cmdline)" "" || rec AUD-03 6.2 L2 AUDIT FAIL "Auditing starts before auditd (audit=1 on kernel cmdline)" "$(cut -c1-80 /proc/cmdline)"
bl=$(grep -oE 'audit_backlog_limit=[0-9]+' /proc/cmdline | cut -d= -f2); { [ -n "$bl" ] && [ "$bl" -ge 8192 ]; } && rec AUD-04 6.2 L2 AUDIT PASS "audit_backlog_limit is 8192 or more" "$bl" || rec AUD-04 6.2 L2 AUDIT FAIL "audit_backlog_limit is 8192 or more" "${bl:-<unset>}"
av() { awk -F= -v k="$1" '{gsub(/ /,"")} tolower($1)==k{print tolower($2)}' /etc/audit/auditd.conf 2>/dev/null | tail -1; }
[ "$(av max_log_file_action)" = keep_logs ] && rec AUD-05 6.2 L2 AUDIT PASS "Audit logs are not automatically deleted" "max_log_file=$(av max_log_file)MB action=keep_logs" || rec AUD-05 6.2 L2 AUDIT FAIL "Audit logs are not automatically deleted" "max_log_file_action=$(av max_log_file_action)"
[[ "$(av space_left_action)" =~ ^(email|exec|single|halt)$ && "$(av admin_space_left_action)" =~ ^(single|halt)$ ]] && rec AUD-06 6.2 L2 AUDIT PASS "System warns/halts when audit logs are full" "" || rec AUD-06 6.2 L2 AUDIT FAIL "System warns/halts when audit logs are full" "space_left_action=$(av space_left_action) admin_space_left_action=$(av admin_space_left_action)"
AR=$(auditctl -l 2>/dev/null)
nrules=$(grep -c '^-' <<<"$AR")
i=10
while IFS='|' read -r name re; do
  if grep -qE -- "$re" <<<"$AR"; then rec "AUD-$i" 6.2 L2 AUDIT PASS "Audit rule: $name" ""
  elif [ "$name" = "sudo log file" ] && [ $SUDO_RS -eq 1 ]; then rec "AUD-$i" 6.2 L2 AUDIT NA "Audit rule: $name" "sudo-rs has no log file to watch"
  else rec "AUD-$i" 6.2 L2 AUDIT FAIL "Audit rule: $name" "no matching rule loaded ($nrules rules total)"; fi
  i=$((i+1))
done <<'EOF'
changes to sudoers (scope)|-w /etc/sudoers
actions as another user (execve with euid change)|-F arch=b64 -S execve.*(euid|-C euid)
sudo log file|-w /var/log/sudo\.log
date and time changes|adjtimex|clock_settime
network environment changes|sethostname
privileged command use|-F perm=x -F auid>=1000
unsuccessful file access attempts|-F exit=-EACCES
user/group identity changes|-w /etc/shadow
discretionary access control changes|-S .*chmod
successful mounts|-S mount
session initiation|/run/utmp|/var/log/wtmp|/var/log/btmp
login and logout events|/var/log/lastlog|/var/lib/lastlog|faillock
file deletion by users|-S .*unlink
mandatory access control changes|-w /etc/apparmor
kernel module loading and unloading|init_module
EOF
auditctl -s 2>/dev/null | grep -qE '^enabled 2' && rec AUD-30 6.2 L2 AUDIT PASS "Audit configuration is immutable (-e 2)" "" || rec AUD-30 6.2 L2 AUDIT FAIL "Audit configuration is immutable (-e 2)" "$(auditctl -s 2>/dev/null | grep '^enabled' || echo 'auditctl unavailable')"
if [ -d /var/log/audit ]; then
  bad=$(find /var/log/audit -type f \( -perm /0137 -o ! -user root \) | wc -l); dm=$(stat -c %a /var/log/audit)
  { [ "$bad" -eq 0 ] && [ $(( 0$dm & ~0750 )) -eq 0 ]; } && rec AUD-31 6.2 L2 AUDIT PASS "Audit log files and directory are access-restricted" "dir=$dm" || rec AUD-31 6.2 L2 AUDIT FAIL "Audit log files and directory are access-restricted" "dir=$dm, $bad loose files"
else rec AUD-31 6.2 L2 AUDIT FAIL "Audit log files and directory are access-restricted" "/var/log/audit missing"; fi

# 6.3 integrity
pkg_installed aide && rec AIDE-01 6.3 L1 AIDE PASS "AIDE is installed" "" || rec AIDE-01 6.3 L1 AIDE FAIL "AIDE is installed" ""
[ -s /var/lib/aide/aide.db ] && rec AIDE-02 6.3 L1 AIDE PASS "AIDE database is initialised" "$(stat -c '%y' /var/lib/aide/aide.db | cut -d. -f1)" || rec AIDE-02 6.3 L1 AIDE FAIL "AIDE database is initialised" "no /var/lib/aide/aide.db"
if systemctl is-enabled dailyaidecheck.timer >/dev/null 2>&1 || grep -rqs aide /etc/cron.d /etc/cron.daily /etc/crontab 2>/dev/null || systemctl is-enabled aide-check.timer >/dev/null 2>&1; then rec AIDE-03 6.3 L1 AIDE PASS "Filesystem integrity is checked on a schedule" ""
else rec AIDE-03 6.3 L1 AIDE FAIL "Filesystem integrity is checked on a schedule" "no timer/cron job"; fi

# ================================================== 7 System maintenance ====
chk_perm PERM-01 7.1 L1 PERM /etc/passwd 644 root root
chk_perm PERM-02 7.1 L1 PERM /etc/passwd- 644 root root
chk_perm PERM-03 7.1 L1 PERM /etc/group 644 root root
chk_perm PERM-04 7.1 L1 PERM /etc/group- 644 root root
chk_perm PERM-05 7.1 L1 PERM /etc/shadow 640 root 'root|shadow'
chk_perm PERM-06 7.1 L1 PERM /etc/shadow- 640 root 'root|shadow'
chk_perm PERM-07 7.1 L1 PERM /etc/gshadow 640 root 'root|shadow'
chk_perm PERM-08 7.1 L1 PERM /etc/gshadow- 640 root 'root|shadow'
chk_perm PERM-09 7.1 L1 PERM /etc/shells 644 root root
chk_perm PERM-10 7.1 L1 PERM /etc/security/opasswd 600 root root
ww=$(lfind -type f -perm -0002 | head -200); nww=$(grep -c . <<<"$ww")
wd=$(lfind -type d -perm -0002 ! -perm -1000 | head -50); nwd=$(grep -c . <<<"$wd")
{ [ "$nww" -eq 0 ] && [ "$nwd" -eq 0 ]; } && rec PERM-11 7.1 L1 PERM PASS "No world-writable files; world-writable dirs have the sticky bit" "" || rec PERM-11 7.1 L1 PERM FAIL "No world-writable files; world-writable dirs have the sticky bit" "$nww files, $nwd dirs e.g. $(head -3 <<<"$ww$wd" | tr '\n' ' ')"
uo=$(lfind \( -nouser -o -nogroup \) | head -200); nuo=$(grep -c . <<<"$uo")
[ "$nuo" -eq 0 ] && rec PERM-12 7.1 L1 PERM PASS "No files without a valid owner or group" "" || rec PERM-12 7.1 L1 PERM FAIL "No files without a valid owner or group" "$nuo e.g. $(head -3 <<<"$uo" | tr '\n' ' ')"
suid=$(lfind -type f \( -perm -4000 -o -perm -2000 \) | sort); rec PERM-13 7.1 L1 PERM MANUAL "SUID/SGID binaries are reviewed" "$(grep -c . <<<"$suid") files: $(tr '\n' ' ' <<<"$suid" | cut -c1-320)"

bad=$(awk -F: '$2!="x"{print $1}' /etc/passwd | tr '\n' ' '); [ -z "$bad" ] && rec USR-01 7.2 L1 USERS PASS "All accounts use shadowed passwords" "" || rec USR-01 7.2 L1 USERS FAIL "All accounts use shadowed passwords" "$bad"
bad=$(awk -F: '$2==""{print $1}' /etc/shadow | tr '\n' ' '); [ -z "$bad" ] && rec USR-02 7.2 L1 USERS PASS "No account has an empty password field" "" || rec USR-02 7.2 L1 USERS FAIL "No account has an empty password field" "$bad"
bad=$(for g in $(cut -d: -f4 /etc/passwd | sort -u); do getent group "$g" >/dev/null || echo "$g"; done | tr '\n' ' '); [ -z "$bad" ] && rec USR-03 7.2 L1 USERS PASS "All groups in /etc/passwd exist in /etc/group" "" || rec USR-03 7.2 L1 USERS FAIL "All groups in /etc/passwd exist in /etc/group" "$bad"
sm=$(getent group shadow | cut -d: -f4); [ -z "$sm" ] && rec USR-04 7.2 L1 USERS PASS "shadow group is empty" "" || rec USR-04 7.2 L1 USERS FAIL "shadow group is empty" "$sm"
d=$(cut -d: -f3 /etc/passwd | sort | uniq -d | tr '\n' ' '); [ -z "$d" ] && rec USR-05 7.2 L1 USERS PASS "No duplicate UIDs" "" || rec USR-05 7.2 L1 USERS FAIL "No duplicate UIDs" "$d"
d=$(cut -d: -f3 /etc/group | sort | uniq -d | tr '\n' ' '); [ -z "$d" ] && rec USR-06 7.2 L1 USERS PASS "No duplicate GIDs" "" || rec USR-06 7.2 L1 USERS FAIL "No duplicate GIDs" "$d"
d=$(cut -d: -f1 /etc/passwd | sort | uniq -d | tr '\n' ' '); [ -z "$d" ] && rec USR-07 7.2 L1 USERS PASS "No duplicate user names" "" || rec USR-07 7.2 L1 USERS FAIL "No duplicate user names" "$d"
d=$(cut -d: -f1 /etc/group | sort | uniq -d | tr '\n' ' '); [ -z "$d" ] && rec USR-08 7.2 L1 USERS PASS "No duplicate group names" "" || rec USR-08 7.2 L1 USERS FAIL "No duplicate group names" "$d"
bad=""; dot=""
while IFS=: read -r u _ uid _ _ h sh; do
  { [ "$uid" -ge 1000 ] && [ "$uid" -ne 65534 ]; } || [ "$u" = root ] || continue
  [[ "$sh" =~ (nologin|false)$ ]] && continue
  if [ ! -d "$h" ]; then bad+="$u:missing "; continue; fi
  read -r m o < <(stat -c '%a %U' "$h"); { [ $(( 0$m & ~0750 )) -ne 0 ] || [ "$o" != "$u" ]; } && bad+="$u:$m:$o "
  for f in .netrc .rhosts .forward; do [ -e "$h/$f" ] && dot+="$h/$f "; done
  dot+=$(find "$h" -xdev -maxdepth 1 -name '.*' -type f -perm /022 2>/dev/null | tr '\n' ' ')
done < /etc/passwd
[ -z "$bad" ] && rec USR-09 7.2 L1 USERS PASS "Interactive users' home directories exist, are owned, and are 0750 or stricter" "" || rec USR-09 7.2 L1 USERS FAIL "Interactive users' home directories exist, are owned, and are 0750 or stricter" "$bad"
[ -z "$dot" ] && rec USR-10 7.2 L1 USERS PASS "No risky dot files (.netrc/.rhosts/.forward, group/world-writable)" "" || rec USR-10 7.2 L1 USERS FAIL "No risky dot files (.netrc/.rhosts/.forward, group/world-writable)" "$dot"

# ================================================ X environment-specific ====
sf=$(findmnt -rn -t vboxsf,9p,virtiofs,fuse.vmhgfs-fuse -o TARGET,OPTIONS | tr '\n' ';')
[ -z "$sf" ] && rec ENV-01 - X ENV PASS "No hypervisor shared folders are mounted" "" || rec ENV-01 - X ENV FAIL "No hypervisor shared folders are mounted" "$sf (guest root can read/write host files)"
ci=$(pkg_installed cloud-init && echo installed); [ -z "$ci" ] && rec ENV-02 - X ENV PASS "cloud-init is absent or deliberately retained" "" || rec ENV-02 - X ENV MANUAL "cloud-init is absent or deliberately retained" "cloud-init installed; on a non-cloud VM it can re-apply ssh/user config from a datasource"
exit 0
