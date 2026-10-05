#!/usr/bin/env bash
# End-to-end test against a real, DISPOSABLE host. This changes the host, reverts it and
# hardens it again - never point it at a machine you care about.
#
#   HARDEN_BECOME_PASS=... tests/e2e.sh <inventory> <host> [output-dir]
#
# Sequence: full cycle (baseline, harden, audit) -> forced AIDE rebuild -> second apply
# (must change nothing) -> revert every family -> reboot -> drift audit (must exit 3) ->
# harden again -> final drift audit (must exit 0). A summary with the status and duration
# of every step is written to <output-dir>/summary.txt; the script exits non-zero if any
# step did not end as expected.
#
# Set E2E_SKIP_AIDE_REBUILD=1 to skip the forced rebuild on hosts where it takes long.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
[ $# -ge 2 ] || { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
INV=$1; H=$2; L=${3:-reports/_e2e/$H}
case $INV in /*) ;; *) INV=$PWD/$INV ;; esac
mkdir -p "$L"; OUT="$L/summary.txt"; : > "$OUT"; BAD=0
FAMILIES="firewall ssh pam sudo accounts sysctl modules mounts services cron banners logging auditd aide"

# step <expected status> <name> <command...>
step() { local want=$1 name=$2 s rc=0; shift 2; s=$(date +%s)
         "$@" > "$L/$name.log" 2>&1 || rc=$?
         local mark=ok; [ "$rc" -eq "$want" ] || { mark="UNEXPECTED (wanted $want)"; BAD=1; }
         printf '%-28s exit=%s %5ss  %s\n' "$name" "$rc" "$(( $(date +%s)-s ))" "$mark" | tee -a "$OUT"; }
score() { .venv/bin/python - "$H" <<'PY' | tee -a "$OUT"
import json, sys
d = json.load(open(f'reports/{sys.argv[1]}/latest/results.json')); c = {x['id']: x for x in d['checks']}
dr = d.get('drift') or {}
print('    L1=%s%% L2=%s%% lynis=%s checks=%d open=%d' % (d['scores']['L1']['pct'], d['scores']['L2']['pct'],
      (d.get('lynis') or {}).get('hardening_index'), len(c), d['scores']['all']['failed']))
print('    open: %s' % ' '.join(i for i in c if c[i]['status'] == 'FAIL'))
print('    regressed vs baseline: %s | since previous audit: %d regressed, %d fixed, %d missing' % (
      d['delta']['regressed'], len(dr.get('regressed', [])), len(dr.get('fixed', [])), len(dr.get('missing', []))))
PY
}
changed() { awk '/^(TASK|RUNNING HANDLER)/{t=$0} /^changed:/{print t}' "$1" | sed 's/ \*\*\**//' | sort -u \
            | grep -vE 'Arm the rollback guard|Back up /etc|Create backup directory|disarm the rollback guard' || true; }
W=(-y -i "$INV" -l "$H")

step 0 01-full-cycle ./harden.sh all "${W[@]}"; score
[ -n "${E2E_SKIP_AIDE_REBUILD:-}" ] || step 0 02-aide-rebuild .venv/bin/ansible-playbook -i "$INV" -l "$H" playbooks/harden.yml --tags post -e hardening_aide_reinit=always
step 0 03-second-apply ./harden.sh apply "${W[@]}"
c=$(changed "$L/03-second-apply.log"); printf '    changed on the second apply, beyond bookkeeping: %s\n' "${c:-nothing}" | tr '\n' ';' | sed 's/;$/\n/' | tee -a "$OUT"
# shellcheck disable=SC2086
step 0 04-revert-all ./harden.sh revert "${W[@]}" $FAMILIES
step 0 05-reboot .venv/bin/ansible-playbook -i "$INV" -l "$H" tests/e2e-reboot.yml
step 3 06-drift-audit ./harden.sh audit -i "$INV" -l "$H" --fail-on-regression; score
step 0 07-harden-again ./harden.sh all "${W[@]}"; score
step 0 08-final-audit ./harden.sh audit -i "$INV" -l "$H" --fail-on-regression; score
[ $BAD -eq 0 ] && echo "E2E PASSED" | tee -a "$OUT" || echo "E2E FAILED" | tee -a "$OUT"
exit $BAD
