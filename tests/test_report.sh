#!/usr/bin/env bash
# Smoke test of tools/report.py against recorded audit results. No host is contacted.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PYTHON:-python3}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cp -r tests/fixtures/web01 "$tmp/web01"
run="$tmp/web01/20260102T000000Z"
fail() { echo "FAIL: $*" >&2; exit 1; }

"$PY" tools/report.py --current "$run" --baseline "$tmp/web01/baseline" --history "$tmp/web01" \
      --exceptions tests/exceptions.yml --host web01 --out "$run" --fail-on-regression >/dev/null
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
assert d["drift"]["regressed"] == [], "unexpected drift"
PY
grep -q 'id="history"' "$run/report.html" || fail "history section missing"

# a regression against the previous audit must exit 3
mkdir "$tmp/web01/20260103T000000Z"
sed 's/^\(SSH-20\tL1\t\|SSH-20\t[^\t]*\tL1\tSSH\t\)PASS/\1FAIL/; s/^\(SSH-20\t5.1\tL1\tSSH\t\)PASS/\1FAIL/' "$run/cis_audit.tsv" > "$tmp/web01/20260103T000000Z/cis_audit.tsv"
grep -q $'^SSH-20\t5.1\tL1\tSSH\tFAIL' "$tmp/web01/20260103T000000Z/cis_audit.tsv" || fail "fixture edit did not apply"
rc=0
"$PY" tools/report.py --current "$tmp/web01/20260103T000000Z" --history "$tmp/web01" --host web01 \
      --out "$tmp/web01/20260103T000000Z" --fail-on-regression >/dev/null || rc=$?
[ "$rc" -eq 3 ] || fail "expected exit 3 on regression, got $rc"

# a malformed exception must stop the report
printf 'exceptions:\n  - {id: BOOT-01, reason: x}\n' > "$tmp/bad.yml"
if "$PY" tools/report.py --current "$run" --exceptions "$tmp/bad.yml" --out "$tmp/out" >/dev/null 2>&1; then
  fail "malformed exception was accepted"
fi

"$PY" tools/report.py --fleet "$tmp" >/dev/null
grep -q 'web01' "$tmp/index.html" || fail "fleet index missing host"
echo "report tests passed"
