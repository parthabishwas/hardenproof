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
#   -i <inventory>         hosts.yml or its directory (default: the one in ansible.cfg)
#   -l <host|group>        limit to some hosts
#   -y, --yes              do not ask for confirmation before changing hosts
#   --rebaseline           start over: archive this host's saved audits and take a new baseline
#   --fail-on-regression   exit 3 if a check that passed in the previous audit now fails
#   --version              print the version and exit
#
# Revert families: firewall ssh pam sudo accounts sysctl modules mounts services cron banners
#                  logging auditd aide
#
# Results: reports/<host>/baseline/, reports/<host>/<UTC timestamp>/, reports/<host>/latest,
#          reports/index.html. Findings you decide to live with go in exceptions.yml next to
#          the inventory.
#
# Exit status: 0 success; 3 regression found (--fail-on-regression); 1 usage or report error;
#              any other value is the status of the Ansible run (2 = a host failed,
#              4 = a host was unreachable). Reports are still built for the hosts that worked.
#
# Credentials come from the environment, never from files:
#   HARDEN_BECOME_PASS  sudo password of the automation user (empty for passwordless sudo)
#   HARDEN_SSH_PASS     only needed for playbooks/bootstrap-access.yml
set -euo pipefail
CALLER_PWD=$PWD
cd "$(dirname "$0")"

# Overridable so the wrapper can be tested without Ansible or a host (tests/test_wrapper.sh).
ANSIBLE=${HARDEN_ANSIBLE:-.venv/bin/ansible}
PB=${HARDEN_ANSIBLE_PLAYBOOK:-.venv/bin/ansible-playbook}
PY=${HARDEN_PYTHON:-.venv/bin/python}
REPORTS=${HARDEN_REPORTS_DIR:-reports}
REVERT_FAMILIES="firewall ssh pam sudo accounts sysctl modules mounts services cron banners logging auditd aide"

usage() { awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit "${1:-0}"; }
say()   { printf '\n== %s\n' "$*"; }
die()   { printf 'error: %s\n' "$*" >&2; exit 1; }

[ $# -ge 1 ] || usage 1
CMD=$1; shift
case $CMD in
  -h|--help|help) usage 0 ;;
  --version|version) cat VERSION; exit 0 ;;
  audit|plan|apply|all|report|revert) ;;
  *) die "unknown command: $CMD (try --help)" ;;
esac

INV_ARG=""; LIMIT=""; YES=0; REBASE=0; FAILREG=0; FAMILIES=()
while [ $# -gt 0 ]; do
  case $1 in
    -i|-l) [ $# -ge 2 ] || die "$1 needs a value"
           if [ "$1" = -i ]; then INV_ARG=$2; else LIMIT=$2; fi; shift 2 ;;
    -y|--yes) YES=1; shift ;;
    --rebaseline) REBASE=1; shift ;;
    --fail-on-regression) FAILREG=1; shift ;;
    -h|--help) usage 0 ;;
    -*) die "unknown option: $1" ;;
    *) [ "$CMD" = revert ] || die "unexpected argument: $1"
       FAMILIES+=("$1"); shift ;;
  esac
done

[ -x "$PY" ] || die "no virtualenv. Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
if [ "$CMD" != report ]; then
  [ -x "$PB" ] || die "ansible is not installed in the virtualenv. Run: .venv/bin/pip install -r requirements.txt"
  [ -n "${HARDEN_ANSIBLE_PLAYBOOK:-}" ] || [ -d collections/ansible_collections/devsec ] || \
    die "collections missing. Run: .venv/bin/ansible-galaxy collection install -r requirements.yml -p ./collections"
  [ -n "${HARDEN_BECOME_PASS+x}" ] || \
    die "HARDEN_BECOME_PASS is not set (export it; use an empty value only for passwordless sudo)"
fi

# The inventory: as given (relative to where the command was typed), else the ansible.cfg default.
if [ -n "$INV_ARG" ]; then
  case $INV_ARG in /*) INV_PATH=$INV_ARG ;; *) INV_PATH=$CALLER_PWD/$INV_ARG ;; esac
  [ -e "$INV_PATH" ] || die "inventory not found: $INV_ARG"
else
  INV_PATH=$(awk -F' *= *' '$1=="inventory"{print $2}' ansible.cfg)
fi
INV=(-i "$INV_PATH")
if [ -d "$INV_PATH" ]; then INV_DIR=$INV_PATH; else INV_DIR=$(dirname "$INV_PATH"); fi
# Accepted-risk register of the selected environment
EXC=()
[ -f "$INV_DIR/exceptions.yml" ] && EXC=(--exceptions "$INV_DIR/exceptions.yml")

mkdir -p "$REPORTS/_logs"
case $REPORTS in /*) REPORTS_ABS=$REPORTS ;; *) REPORTS_ABS=$PWD/$REPORTS ;; esac

# Hosts this invocation is about (inventory + optional -l).
HOSTS=()
if out=$("$ANSIBLE" all "${INV[@]}" ${LIMIT:+-l "$LIMIT"} --list-hosts 2>&1); then
  while IFS= read -r h; do [ -n "$h" ] && HOSTS+=("$h"); done < <(printf '%s\n' "$out" | sed -n '/hosts (/,$p' | tail -n +2 | sed 's/^ *//')
else
  printf '%s\n' "$out" >&2; die "could not read the inventory $INV_PATH"
fi
[ ${#HOSTS[@]} -ge 1 ] || die "no hosts match (inventory: $INV_PATH${LIMIT:+, limit: $LIMIT})"

join_hosts() { local IFS=,; echo "$*"; }
has_baseline() { [ -f "$REPORTS/$1/baseline/cis_audit.tsv" ]; }

# Run the audit playbook for some hosts. Never aborts the script: the status is returned so
# that reports are still built for the hosts that did answer.
audit() {  # label host...
  local label=$1; shift
  say "Audit ($label) - read-only: $*"
  "$PB" "${INV[@]}" -l "$(join_hosts "$@")" playbooks/audit.yml -e "label=$label" -e "reports_dir=$REPORTS_ABS"
}

# newest audit run of a host: the last timestamped directory, or the baseline
latest_run() {
  local d
  d=$(find "$REPORTS/$1" -mindepth 1 -maxdepth 1 -type d -name '[0-9]*' -exec test -f '{}/cis_audit.tsv' \; -print 2>/dev/null | sort | tail -1)
  [ -n "$d" ] || d="$REPORTS/$1/baseline"
  [ -f "$d/cis_audit.tsv" ] && printf '%s\n' "$d"
  return 0
}

render() {  # host run-dir [extra report.py args]  -> sets RENDER_ST
  local h=$1 run=$2 out; shift 2
  RENDER_ST=0
  out=$("$PY" tools/report.py ${EXC[@]+"${EXC[@]}"} --host "$h" --current "$run" --out "$run" --history "$REPORTS/$h" "$@" 2>&1) || RENDER_ST=$?
  case $RENDER_ST in
    0|3) printf '%s\n' "$out" | grep -E 'REGRESSED' || true ;;
    *)   printf 'report for %s failed:\n%s\n' "$h" "$out" >&2 ;;
  esac
}

report() {
  local h run made=0 failed=0 regressed=0 args
  for h in "${HOSTS[@]}"; do
    run=$(latest_run "$h")
    [ -n "$run" ] || { printf 'no audit results for %s\n' "$h" >&2; continue; }
    # the baseline gets its own report once, so that the history links lead somewhere
    if has_baseline "$h" && [ "$run" != "$REPORTS/$h/baseline" ] && [ ! -f "$REPORTS/$h/baseline/report.html" ]; then
      render "$h" "$REPORTS/$h/baseline"; [ "$RENDER_ST" -eq 0 ] || failed=1
    fi
    args=()
    has_baseline "$h" && [ "$run" != "$REPORTS/$h/baseline" ] && args+=(--baseline "$REPORTS/$h/baseline")
    [ $FAILREG -eq 1 ] && args+=(--fail-on-regression)
    render "$h" "$run" ${args[@]+"${args[@]}"}
    case $RENDER_ST in
      0) ;;
      3) regressed=1 ;;
      *) failed=1; continue ;;        # leave "latest" where it was
    esac
    if [ -e "$REPORTS/$h/latest" ] && [ ! -L "$REPORTS/$h/latest" ]; then
      printf 'reports/%s/latest exists and is not a symlink; leaving it alone\n' "$h" >&2
    else
      ln -sfn "$(basename "$run")" "$REPORTS/$h/latest"
    fi
    made=1
  done
  [ $made -eq 1 ] || { [ $failed -eq 1 ] && return 1; die "no audit results for these hosts under $REPORTS/ - run './harden.sh audit' first"; }
  "$PY" tools/report.py --fleet "$REPORTS" >/dev/null || failed=1
  say "Reports"
  for h in "${HOSTS[@]}"; do [ -f "$REPORTS/$h/latest/report.html" ] && printf '  %s/%s/latest/report.html\n' "$REPORTS" "$h"; done
  printf '  %s/index.html   (all hosts)\n' "$REPORTS"
  [ $failed -eq 0 ] || return 1
  if [ $regressed -eq 1 ]; then
    printf '\nRegression: a check that passed in the previous audit now fails.\n' >&2
    return 3
  fi
}

# --rebaseline starts a host's history over. The old audits are kept, out of the way.
archive_runs() {
  local h d stamp=$1
  for h in "${HOSTS[@]}"; do
    [ -d "$REPORTS/$h" ] || continue
    mkdir -p "$REPORTS/$h/_archive-$stamp"
    for d in "$REPORTS/$h"/*/; do
      case $(basename "$d") in _*) continue ;; esac
      [ -L "${d%/}" ] && continue
      mv "${d%/}" "$REPORTS/$h/_archive-$stamp/"
    done
    rm -f "$REPORTS/$h/latest"
  done
}

confirm() {  # message
  [ $YES -eq 1 ] && return 0
  say "About to change these hosts"
  printf '  %s\n' "${HOSTS[@]}"
  printf '\n%s\nType "yes" to continue: ' "$1"
  local answer=""; read -r answer || true
  [ "$answer" = yes ] || die "aborted - nothing was changed"
}

apply() {
  confirm 'This disables SSH password login, enables a default-deny firewall and may reboot.'
  local log st=0
  log="$REPORTS/_logs/harden-$(date -u +%Y%m%dT%H%M%SZ).log"
  say "Hardening (log: $log)"
  "$PB" "${INV[@]}" ${LIMIT:+-l "$LIMIT"} playbooks/harden.yml --diff 2>&1 | tee "$log" || st=${PIPESTATUS[0]}
  return "$st"
}

revert() {
  local f tags log st=0
  [ ${#FAMILIES[@]} -ge 1 ] || die "name at least one family to revert: $REVERT_FAMILIES"
  for f in "${FAMILIES[@]}"; do
    [[ " $REVERT_FAMILIES " == *" $f "* ]] || die "unknown family '$f'. Choose from: $REVERT_FAMILIES"
  done
  tags=$(join_hosts "${FAMILIES[@]}")
  confirm "This UNDOES the hardening of: ${FAMILIES[*]}. The hosts will be less protected afterwards."
  log="$REPORTS/_logs/revert-$(date -u +%Y%m%dT%H%M%SZ).log"
  say "Reverting $tags (log: $log)"
  "$PB" "${INV[@]}" ${LIMIT:+-l "$LIMIT"} playbooks/revert.yml --tags "$tags" --diff 2>&1 | tee "$log" || st=${PIPESTATUS[0]}
  return "$st"
}

# Baseline for the hosts that have none (all of them after --rebaseline). Hosts that already
# have one are never touched: their "before" picture is evidence.
NEED_BASELINE=(); HAVE_BASELINE=()
take_baselines() {
  local h
  [ $REBASE -eq 1 ] && archive_runs "$(date -u +%Y%m%dT%H%M%SZ)"
  for h in "${HOSTS[@]}"; do
    if has_baseline "$h"; then HAVE_BASELINE+=("$h"); else NEED_BASELINE+=("$h"); fi
  done
  if [ ${#NEED_BASELINE[@]} -ge 1 ]; then
    audit baseline "${NEED_BASELINE[@]}" || return $?
  else
    say "Baseline exists for every host - kept (use --rebaseline to start over)"
  fi
}

RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)
st=0; rst=0
case $CMD in
  audit)
    take_baselines || st=$?
    if [ ${#HAVE_BASELINE[@]} -ge 1 ]; then audit "$RUN_ID" "${HAVE_BASELINE[@]}" || st=$?; fi
    report || rst=$? ;;
  plan)
    say "Dry run - nothing is changed"
    "$PB" "${INV[@]}" ${LIMIT:+-l "$LIMIT"} playbooks/harden.yml --check --diff || st=$? ;;
  apply)  apply || st=$? ;;
  report) report || rst=$? ;;
  revert) revert || st=$? ;;
  all)
    take_baselines || st=$?
    apply || { ast=$?; [ $st -ne 0 ] || st=$ast; }
    audit "$(date -u +%Y%m%dT%H%M%SZ)" "${HOSTS[@]}" || { ust=$?; [ $st -ne 0 ] || st=$ust; }
    report || rst=$? ;;
esac
if [ $st -ne 0 ]; then
  printf '\nFinished with errors (status %s): at least one host failed or was unreachable.\n' "$st" >&2
  exit "$st"
fi
exit "$rst"
