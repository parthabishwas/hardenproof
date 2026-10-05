#!/usr/bin/env bash
# HardenProof - audit, harden, re-audit and report in one command.
#
#   ./harden.sh audit  -i <inventory>            read-only audit + report (first run = baseline)
#   ./harden.sh plan   -i <inventory>            dry run of the hardening (--check --diff)
#   ./harden.sh apply  -i <inventory>            harden only
#   ./harden.sh all    -i <inventory>            baseline (kept if present) -> harden -> audit -> report
#   ./harden.sh report -i <inventory>            rebuild HTML reports from saved audits
#   ./harden.sh revert -i <inventory> <family>.. undo one or more control families
#
# Options:
#   -i <inventory>         default: the one in ansible.cfg (inventory/example)
#   -l <host|group>        limit to some hosts
#   -y                     do not ask for confirmation before changing hosts
#   --rebaseline           replace an existing baseline audit
#   --fail-on-regression   (audit) exit 3 if a check that passed in the previous audit now fails
#
# Revert families: firewall ssh pam sudo accounts sysctl modules mounts services cron banners
#                  logging auditd aide
#
# Results: reports/<host>/baseline/, reports/<host>/<timestamp>/, reports/index.html
# Findings you decide to live with go in inventory/<env>/exceptions.yml.
#
# Credentials come from the environment, never from files:
#   HARDEN_BECOME_PASS  sudo password of the automation user (empty for passwordless sudo)
#   HARDEN_SSH_PASS     only needed for playbooks/bootstrap-access.yml
set -euo pipefail
cd "$(dirname "$0")"

PB=.venv/bin/ansible-playbook
PY=.venv/bin/python
REVERT_FAMILIES="firewall ssh pam sudo accounts sysctl modules mounts services cron banners logging auditd aide"

usage() { sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
say()   { printf '\n== %s\n' "$*"; }
die()   { printf 'error: %s\n' "$*" >&2; exit 1; }

[ $# -ge 1 ] || usage 1
CMD=$1; shift
case $CMD in -h|--help|help) usage 0 ;; esac
INV=(); LIMIT=(); YES=0; REBASE=0; FAILREG=0; DID_BASELINE=0; FAMILIES=()
while [ $# -gt 0 ]; do
  case $1 in
    -i) INV=(-i "$2"); shift 2 ;;
    -l) LIMIT=(-l "$2"); shift 2 ;;
    -y|--yes) YES=1; shift ;;
    --rebaseline) REBASE=1; shift ;;
    --fail-on-regression) FAILREG=1; shift ;;
    -h|--help) usage 0 ;;
    -*) die "unknown option: $1" ;;
    *) FAMILIES+=("$1"); shift ;;
  esac
done

[ -x "$PB" ] || die "no virtualenv. Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
[ -d collections/ansible_collections/devsec ] || die "collections missing. Run: .venv/bin/ansible-galaxy collection install -r requirements.yml -p ./collections"
if [ "$CMD" != report ] && [ -z "${HARDEN_BECOME_PASS+x}" ]; then
  die "HARDEN_BECOME_PASS is not set (export it; use an empty value only for passwordless sudo)"
fi
mkdir -p reports/_logs

# Accepted-risk register of the selected environment: inventory/<env>/exceptions.yml
INV_FILE=${INV[1]:-$(awk -F' *= *' '$1=="inventory"{print $2}' ansible.cfg)}
EXC=()
[ -f "$(dirname "$INV_FILE")/exceptions.yml" ] && EXC=(--exceptions "$(dirname "$INV_FILE")/exceptions.yml")

hosts() { .venv/bin/ansible all "${INV[@]}" "${LIMIT[@]}" --list-hosts 2>/dev/null | tail -n +2 | sed 's/^ *//'; }

audit() {  # label
  say "Audit ($1) - read-only"
  "$PB" "${INV[@]}" "${LIMIT[@]}" playbooks/audit.yml -e "label=$1"
}

# newest audit run of a host (a timestamped directory, or the baseline if there is nothing else)
latest_run() {
  local d
  d=$(find "reports/$1" -mindepth 1 -maxdepth 1 -type d ! -name baseline -exec test -f '{}/cis_audit.tsv' \; -print | sort | tail -1)
  [ -n "$d" ] || d="reports/$1/baseline"
  [ -f "$d/cis_audit.tsv" ] && printf '%s\n' "$d"
}

report() {
  local h run rc=0 made=0 args
  for h in $(hosts); do
    run=$(latest_run "$h") || continue
    [ -n "$run" ] || continue
    args=("${EXC[@]}" --host "$h" --current "$run" --out "$run" --history "reports/$h")
    [ -f "reports/$h/baseline/cis_audit.tsv" ] && [ "$run" != "reports/$h/baseline" ] && args+=(--baseline "reports/$h/baseline")
    [ $FAILREG -eq 1 ] && args+=(--fail-on-regression)
    "$PY" tools/report.py "${args[@]}" | grep -E 'REGRESSED|^error' || true
    [ "${PIPESTATUS[0]}" -eq 0 ] || rc=${PIPESTATUS[0]}
    ln -sfn "$(basename "$run")" "reports/$h/latest"
    made=1
  done
  [ $made -eq 1 ] || die "no audit results for these hosts under reports/ - run './harden.sh audit' first"
  "$PY" tools/report.py --fleet reports >/dev/null
  say "Reports"
  for h in $(hosts); do [ -f "reports/$h/latest/report.html" ] && printf '  reports/%s/latest/report.html\n' "$h"; done
  printf '  reports/index.html   (all hosts)\n'
  if [ $rc -eq 3 ]; then printf '\nRegression: a check that passed in the previous audit now fails.\n' >&2; fi
  return $rc
}

baseline() {
  local h missing=0
  for h in $(hosts); do [ -f "reports/$h/baseline/cis_audit.tsv" ] || missing=1; done
  if [ $REBASE -eq 1 ] || [ $missing -eq 1 ]; then
    audit baseline; DID_BASELINE=1
  else
    say "Baseline exists for every host - kept (use --rebaseline to replace it)"
  fi
}

confirm() {  # message
  [ $YES -eq 1 ] && return 0
  say "About to change these hosts"
  hosts | sed 's/^/  /'
  printf '\n%s\nType "yes" to continue: ' "$1"
  read -r answer
  [ "$answer" = yes ] || die "aborted - nothing was changed"
}

apply() {
  confirm 'This disables SSH password login, enables a default-deny firewall and may reboot.'
  local log
  log="reports/_logs/harden-$(date -u +%Y%m%dT%H%M%SZ).log"
  say "Hardening (log: $log)"
  "$PB" "${INV[@]}" "${LIMIT[@]}" playbooks/harden.yml --diff 2>&1 | tee "$log"
  return "${PIPESTATUS[0]}"
}

revert() {
  local f tags log
  [ ${#FAMILIES[@]} -ge 1 ] || die "name at least one family to revert: $REVERT_FAMILIES"
  for f in "${FAMILIES[@]}"; do
    [[ " $REVERT_FAMILIES " == *" $f "* ]] || die "unknown family '$f'. Choose from: $REVERT_FAMILIES"
  done
  tags=$(IFS=,; echo "${FAMILIES[*]}")
  confirm "This UNDOES the hardening of: ${FAMILIES[*]}. The hosts will be less protected afterwards."
  log="reports/_logs/revert-$(date -u +%Y%m%dT%H%M%SZ).log"
  say "Reverting $tags (log: $log)"
  "$PB" "${INV[@]}" "${LIMIT[@]}" playbooks/revert.yml --tags "$tags" --diff 2>&1 | tee "$log"
  return "${PIPESTATUS[0]}"
}

RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)
case $CMD in
  audit)  baseline; [ $DID_BASELINE -eq 1 ] || audit "$RUN_ID"; report ;;
  plan)   say "Dry run - nothing is changed"; "$PB" "${INV[@]}" "${LIMIT[@]}" playbooks/harden.yml --check --diff ;;
  apply)  apply ;;
  report) report ;;
  revert) revert ;;
  all)    baseline; apply; audit "$(date -u +%Y%m%dT%H%M%SZ)"; report ;;
  *) die "unknown command: $CMD (try --help)" ;;
esac
