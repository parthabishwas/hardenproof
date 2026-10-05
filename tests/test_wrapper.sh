#!/usr/bin/env bash
# Tests of harden.sh with stand-ins for ansible and ansible-playbook. No host is contacted:
# the fake "audit" copies a recorded result into the reports directory.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

mkdir -p "$tmp/bin" "$tmp/inv"
cat > "$tmp/bin/ansible" <<'STUB'
#!/usr/bin/env bash
# only "--list-hosts" is ever asked of it
limit=""; while [ $# -gt 0 ]; do [ "$1" = -l ] && { limit=$2; shift; }; shift; done
hosts=${limit:-$STUB_HOSTS}
echo "  hosts ($(tr ',' '\n' <<<"$hosts" | grep -c .)):"; tr ',' '\n' <<<"$hosts" | sed 's/^/    /'
STUB
cat > "$tmp/bin/ansible-playbook" <<'STUB'
#!/usr/bin/env bash
limit=""; label=""; rdir=""; pb=""; nolynis=""
while [ $# -gt 0 ]; do
  case $1 in
    -l) limit=$2; shift ;;
    -e) case $2 in label=*) label=${2#label=} ;; reports_dir=*) rdir=${2#reports_dir=} ;;
                   hardening_audit_lynis=false) nolynis=1 ;; esac; shift ;;
    *.yml) pb=$1 ;;
  esac; shift
done
echo "$pb ${limit:-all} $label${nolynis:+ nolynis}" >> "$STUB_LOG"
rc=0
case $pb in
  */audit.yml)
    for h in $(tr ',' ' ' <<<"${limit:-$STUB_HOSTS}"); do
      if [[ ",${STUB_UNREACHABLE:-}," == *",$h,"* ]]; then rc=4; continue; fi
      mkdir -p "$rdir/$h/$label"
      # every fake audit gets its own, later, timestamp
      n=$(( $(cat "$STUB_CLOCK" 2>/dev/null || echo 0) + 1 )); echo $n > "$STUB_CLOCK"
      sed "s/^#meta\tdate_utc\t.*/#meta\tdate_utc\t2026-02-01T00:$(printf %02d $n):00Z/" "${STUB_TSV}" > "$rdir/$h/$label/cis_audit.tsv"
    done ;;
  */harden.yml|*/revert.yml) rc=${STUB_CHANGE_RC:-0} ;;
esac
exit $rc
STUB
chmod +x "$tmp/bin/ansible" "$tmp/bin/ansible-playbook"
printf 'all:\n  hosts:\n    a:\n' > "$tmp/inv/hosts.yml"

PY=${PYTHON:-python3}
HARDEN_PYTHON=$(command -v "$PY")
export HARDEN_PYTHON HARDEN_ANSIBLE="$tmp/bin/ansible" HARDEN_ANSIBLE_PLAYBOOK="$tmp/bin/ansible-playbook"
export HARDEN_REPORTS_DIR="$tmp/reports" HARDEN_BECOME_PASS='' STUB_LOG="$tmp/calls" STUB_CLOCK="$tmp/clock"
GOOD=$ROOT/tests/fixtures/web01/20260102T000000Z/cis_audit.tsv
WORSE=$tmp/worse.tsv; sed $'s/^\\(SSH-20\t5.1\tL1\tSSH\t\\)PASS/\\1FAIL/' "$GOOD" > "$WORSE"
export STUB_HOSTS=a STUB_TSV=$GOOD
R=$tmp/reports
# run <expected status> <description> <harden.sh arguments...>
run() { local want=$1 what=$2 rc=0; shift 2; sleep 1; ./harden.sh "$@" -i "$tmp/inv/hosts.yml" >"$tmp/out" 2>"$tmp/err" || rc=$?
        [ "$rc" -eq "$want" ] || { cat "$tmp/out" "$tmp/err" >&2; fail "$what: expected exit $want, got $rc"; }; }
runs_of() { find "$R/$1" -mindepth 1 -maxdepth 1 -type d ! -name baseline ! -name '_*' | wc -l; }

# --- help is only help -----------------------------------------------------------------
./harden.sh --help > "$tmp/help"; if grep -q 'set -euo' "$tmp/help"; then fail "--help prints code"; fi
[ "$(./harden.sh --version)" = "$(cat VERSION)" ] || fail "--version"

# --- first audit is the baseline, the next one is a dated run -----------------------------
run 0 "first audit" audit
[ -f "$R/a/baseline/report.html" ] && [ "$(readlink "$R/a/latest")" = baseline ] || fail "first audit did not produce a baseline report"
sum_a=$(sha256sum < "$R/a/baseline/cis_audit.tsv")
run 0 "second audit" audit
[ "$(runs_of a)" -eq 1 ] || fail "second audit did not create a dated run"
[ "$(readlink "$R/a/latest")" != baseline ] || fail "latest still points at the baseline"

# --- adding a host must not touch the other host's baseline -------------------------------
export STUB_HOSTS=a,b
run 0 "audit after adding a host" audit
[ "$(sha256sum < "$R/a/baseline/cis_audit.tsv")" = "$sum_a" ] || fail "existing baseline was overwritten when a host was added"
[ -f "$R/b/baseline/cis_audit.tsv" ] || fail "new host got no baseline"
[ "$(runs_of a)" -eq 2 ] || fail "existing host was not audited again"
[ -f "$R/index.html" ] || fail "no fleet index"

# --- a regression on one host: exit 3 only when asked ------------------------------------
export STUB_TSV=$WORSE
run 3 "regression with --fail-on-regression" audit --fail-on-regression
grep -q 'Regression' "$tmp/err" || fail "regression not announced"
export STUB_TSV=$GOOD
run 0 "back to good" audit --fail-on-regression

# --- one unreachable host: non-zero exit, but the other host still gets its report ---------
before=$(readlink "$R/a/latest")
STUB_UNREACHABLE=b run 4 "one host unreachable" audit
[ "$(readlink "$R/a/latest")" != "$before" ] || fail "reachable host got no new report when another host was down"

# --- --rebaseline starts over and keeps the old audits ------------------------------------
run 0 "rebaseline" audit --rebaseline --fail-on-regression
[ "$(readlink "$R/a/latest")" = baseline ] && [ "$(runs_of a)" -eq 0 ] || fail "rebaseline left old runs in place"
ls -d "$R"/a/_archive-* >/dev/null 2>&1 || fail "rebaseline did not archive the old audits"
if grep -q regressed "$R/a/baseline/report.html" && grep -qE '[1-9][0-9]* regressed' "$R/a/baseline/report.html"; then fail "inverted report after rebaseline"; fi

# --- the exceptions file is found for a directory inventory too ---------------------------
printf 'exceptions:\n  - {id: BOOT-01, reason: "console access is restricted", accepted_by: CI, expires: 2999-01-01}\n' > "$tmp/inv/exceptions.yml"
sleep 1; ./harden.sh report -i "$tmp/inv" >/dev/null 2>&1 || fail "report with a directory inventory"
"$PY" -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['scores']['all']['accepted'] >= 1, 'exceptions.yml not applied'" "$R/a/latest/results.json"

# --- a malformed exceptions file is shown in full and fails the command -------------------
printf 'exceptions:\n  - {id: BOOT-01, reason: x}\n' > "$tmp/inv/exceptions.yml"
run 1 "malformed exceptions" report
grep -q 'missing accepted_by, expires' "$tmp/err" || fail "the detail of the exceptions error was hidden"
rm "$tmp/inv/exceptions.yml"

# --- changing hosts needs a yes; a failed apply is reported, the audit still runs ---------
: > "$STUB_LOG"
run 1 "apply without confirmation" apply < /dev/null
if grep -q harden.yml "$STUB_LOG"; then fail "apply ran without confirmation"; fi
STUB_CHANGE_RC=2 run 2 "failed apply inside all" all -y
grep -q 'audit.yml' "$STUB_LOG" || fail "no audit after a failed apply"

# --- --no-lynis reaches the audit playbook, and only when asked for --------------------------
: > "$STUB_LOG"
run 0 "audit" audit
if grep -q nolynis "$STUB_LOG"; then fail "Lynis skipped without --no-lynis"; fi
: > "$STUB_LOG"
run 0 "audit --no-lynis" audit --no-lynis
grep -q 'audit.yml .* nolynis' "$STUB_LOG" || fail "--no-lynis was not passed to the audit playbook"

# --- argument handling ------------------------------------------------------------------
./harden.sh revert -y -i "$tmp/inv/hosts.yml" nonsense >/dev/null 2>&1 && fail "unknown revert family accepted" || true
./harden.sh audit -i >/dev/null 2>&1 && fail "-i without a value accepted" || true
./harden.sh report -i "$tmp/does-not-exist" >/dev/null 2>&1 && fail "missing inventory accepted" || true

echo "wrapper tests passed"
