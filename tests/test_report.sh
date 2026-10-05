#!/usr/bin/env bash
# Tests of tools/report.py against recorded audit results. No host is contacted.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PYTHON:-python3}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cp -r tests/fixtures/web01 "$tmp/web01"
base="$tmp/web01/baseline"; run="$tmp/web01/20260102T000000Z"
fail() { echo "FAIL: $*" >&2; exit 1; }
report() { "$PY" tools/report.py "$@"; }
# expect <status> <description> <command...>
expect() { local want=$1 what=$2 rc=0; shift 2; "$@" >"$tmp/out" 2>"$tmp/err" || rc=$?
           [ "$rc" -eq "$want" ] || { cat "$tmp/err" >&2; fail "$what: expected exit $want, got $rc"; }; }

# --- the normal case: baseline diff, history, exceptions --------------------------------
expect 0 "normal report" report --current "$run" --baseline "$base" --history "$tmp/web01" \
       --exceptions tests/exceptions.yml --host web01 --out "$run" --fail-on-regression
[ -s "$run/report.html" ] || fail "no report.html"
"$PY" - "$run/results.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
c = {x["id"]: x for x in d["checks"]}
assert c["BOOT-01"]["status"] == "ACCEPTED" and c["BOOT-01"]["raw_status"] == "FAIL", "active exception not applied"
assert c["LOG-06"]["status"] == "FAIL" and c["LOG-06"]["exception"]["expired"], "expired exception must stay open"
assert [s["id"] for s in d["stale_exceptions"]] == ["SSH-23"], "stale exception not reported"
assert d["scores"]["L1"]["scored"] == d["scores"]["L1"]["passed"] + d["scores"]["L1"]["failed"] + 1, "accepted failure must count against the score"
assert len(d["delta"]["fixed"]) > 50 and not d["delta"]["regressed"], "baseline diff wrong"
assert d["drift"]["regressed"] == [] and d["drift"]["missing"] == [], "unexpected drift"
PY
grep -q 'id="history"' "$run/report.html" || fail "history section missing"

# --- drift: a regression, and a check that silently disappears, both exit 3 --------------
mkdir "$tmp/web01/20260103T000000Z" "$tmp/web01/20260104T000000Z"
sed $'s/^\\(SSH-20\t5.1\tL1\tSSH\t\\)PASS/\\1FAIL/' "$run/cis_audit.tsv" > "$tmp/web01/20260103T000000Z/cis_audit.tsv"
grep -q $'^SSH-20\t5.1\tL1\tSSH\tFAIL' "$tmp/web01/20260103T000000Z/cis_audit.tsv" || fail "fixture edit did not apply"
expect 3 "regression" report --current "$tmp/web01/20260103T000000Z" --history "$tmp/web01" --host web01 \
       --out "$tmp/web01/20260103T000000Z" --fail-on-regression
rm -rf "$tmp/web01/20260103T000000Z"
grep -v $'^SSH-22\t' "$run/cis_audit.tsv" > "$tmp/web01/20260104T000000Z/cis_audit.tsv"
expect 3 "a passing check that vanished" report --current "$tmp/web01/20260104T000000Z" --history "$tmp/web01" \
       --host web01 --out "$tmp/web01/20260104T000000Z" --fail-on-regression
rm -rf "$tmp/web01/20260104T000000Z"

# --- an accepted regression is not a surprise --------------------------------------------
mkdir "$tmp/web01/20260105T000000Z"
sed $'s/^\\(SSH-20\t5.1\tL1\tSSH\t\\)PASS/\\1FAIL/' "$run/cis_audit.tsv" > "$tmp/web01/20260105T000000Z/cis_audit.tsv"
printf 'exceptions:\n  - {id: SSH-20, reason: "bastion", accepted_by: CI, expires: 2999-01-01}\n' > "$tmp/acc.yml"
expect 0 "accepted regression" report --current "$tmp/web01/20260105T000000Z" --history "$tmp/web01" --host web01 \
       --exceptions "$tmp/acc.yml" --out "$tmp/web01/20260105T000000Z" --fail-on-regression
rm -rf "$tmp/web01/20260105T000000Z"

# --- host-supplied text never reaches the page unescaped ---------------------------------
mkdir -p "$tmp/evil/r1"
evil='<script>alert(1)</script>"><img src=x onerror=1>'
{ printf '#meta\thostname\t%s\n#meta\tdate_utc\t2026-01-01T00:00:00Z\n' "$evil"
  printf 'X-01\t%s\t%s\t%s\tFAIL\t%s\t%s\n' "$evil" "$evil" "SSH" "$evil" "$evil"
  printf 'X-02\t1\t%s\tSSH\tMANUAL\tt\te\n' "$evil"; } > "$tmp/evil/r1/cis_audit.tsv"
expect 0 "hostile strings" report --current "$tmp/evil/r1" --out "$tmp/evil/r1" --md
for f in report.html summary.md; do
  if grep -qE '<script>alert|<img src=x' "$tmp/evil/r1/$f"; then fail "unescaped host text in $f"; fi
done

# --- malformed input is refused with a clear message, never a traceback ------------------
bad() { mkdir -p "$tmp/bad"; printf '%b' "$2" > "$tmp/bad/cis_audit.tsv"
        expect 1 "$1" report --current "$tmp/bad" --out "$tmp/bad"
        grep -q '^error:' "$tmp/err" || fail "$1: no 'error:' line"
        if grep -q Traceback "$tmp/err"; then fail "$1: traceback"; fi; }
bad "empty audit"        ''
bad "unknown status"     'A-1\t1\tL1\tSSH\tWARN\tt\te\n'
bad "truncated row"      'A-1\t1\tL1\n'
# bytes that are not UTF-8, a bare #meta line and a carriage return must not crash it
printf '#meta\nA-1\t1\tL1\tSSH\tPASS\tt\tcaf\xe9 \xff\r\n' > "$tmp/bad/cis_audit.tsv"
expect 0 "odd bytes" report --current "$tmp/bad" --out "$tmp/bad"

# --- the exceptions register ------------------------------------------------------------
exc() { printf '%b' "$2" > "$tmp/e.yml"; expect "$3" "$1" report --current "$run" --exceptions "$tmp/e.yml" --host web01 --out "$tmp/out-exc"; }
exc "missing fields"      'exceptions:\n  - {id: BOOT-01, reason: x}\n' 1
exc "duplicate entries"   'exceptions:\n  - {id: BOOT-01, reason: x, accepted_by: a, expires: 2999-01-01}\n  - {id: BOOT-01, reason: y, accepted_by: a, expires: 2000-01-01}\n' 1
exc "not a mapping"       'exceptions:\n  - BOOT-01\n' 1
exc "datetime expiry"     'exceptions:\n  - {id: BOOT-01, reason: x, accepted_by: a, expires: 2999-01-01 00:00:00}\n' 0
exc "host given as text"  'exceptions:\n  - {id: BOOT-01, reason: x, accepted_by: a, expires: 2999-01-01, hosts: web01-prod}\n' 0
"$PY" -c "import json,sys; c={x['id']:x for x in json.load(open(sys.argv[1]))['checks']}; assert c['BOOT-01']['status']=='FAIL', 'exception for web01-prod applied to web01'" "$tmp/out-exc/results.json"
expect 1 "missing exceptions file" report --current "$run" --exceptions "$tmp/nope.yml" --out "$tmp/out-exc"

# --- fleet index: several hosts, one of them unreadable -----------------------------------
cp -r "$tmp/web01" "$tmp/web02"; mkdir -p "$tmp/web03/r1"; cp "$run/cis_audit.tsv" "$tmp/web03/r1/"
echo '{broken' > "$tmp/web03/r1/results.json"
report --current "$tmp/web02/20260102T000000Z" --baseline "$tmp/web02/baseline" --out "$tmp/web02/20260102T000000Z" >/dev/null
rm -rf "$tmp/evil" "$tmp/bad" "$tmp/out-exc"
expect 0 "fleet index" report --fleet "$tmp"
grep -q 'web01' "$tmp/index.html" && grep -q 'web02' "$tmp/index.html" || fail "fleet index missing a host"
grep -q 'skipping web03' "$tmp/err" || fail "unreadable host not reported"

# --- every check row carries its CIS section ---------------------------------------------
"$PY" - "$run/report.html" "$run/cis_audit.tsv" <<'PY'
import re, sys
html = open(sys.argv[1]).read()
rows = [l.rstrip("\n").split("\t") for l in open(sys.argv[2]) if l.strip() and not l.startswith("#")]
for cid, cis in [(r[0], r[1]) for r in rows]:
    m = re.search(r'<tr id="chk-%s"[^>]*>.*?</tr>' % re.escape(cid), html, re.S)
    assert m, f"{cid}: no row in the family tables"
    assert f'<td class="lv">{cis}</td>' in m.group(0) or (cis == "-" and 'Not a CIS Benchmark item' in m.group(0)), f"{cid}: CIS section {cis} missing"
for sec in ("open", "manual"):
    body = re.search(r'<section id="%s">.*?</section>' % sec, html, re.S).group(0)
    assert body.count("<th") == 0 or ">CIS</th>" in body, f"{sec}: no CIS column"
    for tr in re.findall(r"<tr><td.*?</tr>", body, re.S):
        assert tr.count("<td") == 6, f"{sec}: a row does not have six cells"
PY

# --- an audit without Lynis (--no-lynis) -------------------------------------------------
mkdir -p "$tmp/nl/run"; cp "$run/cis_audit.tsv" "$tmp/nl/run/"
expect 0 "report without Lynis" report --current "$tmp/nl/run" --baseline "$base" --host web01 --out "$tmp/nl/run"
grep -q 'Lynis was skipped for this audit' "$tmp/nl/run/report.html" || fail "skipped Lynis not stated beside the baseline index"
if grep -q 'id="lynis"' "$tmp/nl/run/report.html"; then fail "Lynis section shown without Lynis data"; fi
if grep -q 'and lynis-report.dat' "$tmp/nl/run/report.html"; then fail "footer cites a Lynis report that does not exist"; fi
mkdir -p "$tmp/nl/base"; cp "$base/cis_audit.tsv" "$tmp/nl/base/"
expect 0 "report with no Lynis at all" report --current "$tmp/nl/run" --baseline "$tmp/nl/base" --host web01 --out "$tmp/nl/run"
if grep -qi 'lynis hardening index' "$tmp/nl/run/report.html"; then fail "Lynis row shown when Lynis never ran"; fi

echo "report tests passed"
