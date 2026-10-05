#!/bin/sh
# Restores the access-critical configuration captured before the hardening run.
# Started by the transient timer "hardening-rollback" when a run neither finishes nor
# proves that SSH + sudo still work. Can also be run by hand from the console.
B=/var/backups/hardening/latest
[ -f "$B/access-critical.tar.gz" ] || { logger -t hardening "rollback: no backup at $B"; exit 1; }
logger -t hardening "ROLLBACK: restoring access-critical configuration from $(readlink -f $B)"
command -v ufw >/dev/null 2>&1 && ufw --force disable
rm -f /etc/sudoers.d/90-hardening /usr/share/pam-configs/pwhistory \
      /usr/share/pam-configs/faillock /usr/share/pam-configs/faillock_authfail \
      /etc/security/pwquality.conf.d/50-hardening.conf
tar -xzpf "$B/access-critical.tar.gz" -C /
systemctl unmask ssh.socket 2>/dev/null
systemctl restart ssh.service 2>/dev/null || systemctl restart ssh.socket
logger -t hardening "ROLLBACK: done"
