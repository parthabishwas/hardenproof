#!/bin/sh
# Restores the access-critical configuration captured before the hardening run.
# Started by the transient timer "hardening-rollback" when a stage neither finishes nor
# proves that SSH + sudo still work. Can also be run by hand from the console.
#
# Restored from the backup of the most recent run ("latest"): PAM, sshd, sudoers, the
# account databases and the firewall configuration. Network kernel parameters go back to the
# values recorded before the run. Everything else the run changed stays; re-run the playbook
# or use playbooks/revert.yml for that.
B=/var/backups/hardening/latest
log() { logger -t hardening "$*"; echo "$*"; }

# Tell the playbook: a run that finds this marker must fail instead of reporting success.
touch /var/backups/hardening/.rollback-fired

[ -f "$B/access-critical.tar.gz" ] || { log "ROLLBACK FAILED: no backup at $B"; exit 1; }
log "ROLLBACK: restoring access-critical configuration from $(readlink -f "$B")"
rc=0

# Open the door first: whatever else fails below, a firewall must not keep the operator out.
command -v ufw >/dev/null 2>&1 && ufw --force disable >/dev/null 2>&1

# Files this tool adds; the archive only puts back what existed before.
rm -f /etc/sudoers.d/90-hardening /usr/share/pam-configs/pwhistory \
      /usr/share/pam-configs/faillock /usr/share/pam-configs/faillock_authfail \
      /etc/security/pwquality.conf.d/50-hardening.conf

tar -xzpf "$B/access-critical.tar.gz" -C / || { rc=1; log "ROLLBACK: restoring files failed"; }

# Network parameters are applied live by the run and can cut the management path on their
# own (reverse-path filtering, forwarding). Put the recorded values back.
rm -f /etc/sysctl.d/90-dev-sec.conf /etc/sysctl.d/91-hardening-interfaces.conf
if [ -f "$B/sysctl.before" ]; then
  grep -E '^net\.(ipv4|ipv6)\.(ip_forward|conf\.[^.]+\.(rp_filter|forwarding|accept_ra|accept_redirects|send_redirects)) ' "$B/sysctl.before" \
    | sed 's/ = /=/' | while IFS= read -r kv; do sysctl -q -w "$kv" 2>/dev/null || true; done
fi

systemctl unmask ssh.socket 2>/dev/null
systemctl restart ssh.service 2>/dev/null || systemctl restart ssh.socket || { rc=1; log "ROLLBACK: could not restart sshd"; }

# A firewall that was on before the run goes back on, with the rules it had then.
if [ "$(cat "$B/ufw.before" 2>/dev/null)" = active ] && command -v ufw >/dev/null 2>&1; then
  ufw --force enable >/dev/null 2>&1 || { rc=1; log "ROLLBACK: could not re-enable the firewall"; }
fi

if [ $rc -eq 0 ]; then log "ROLLBACK: done"; else log "ROLLBACK: finished WITH ERRORS - check this host from the console"; fi
exit $rc
