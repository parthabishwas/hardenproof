#!/usr/bin/env python3
"""Turn audit output into a reviewable report.

    tools/report.py --current reports/<host>/<run> --baseline reports/<host>/baseline \
                    --history reports/<host> --out reports/<host>/<run>
    tools/report.py --fleet reports            # index page across all hosts

Reads cis_audit.tsv and lynis-report.dat from each directory, joins the checks with
controls/catalogue.yml and writes report.html (self-contained, works offline, prints) and
results.json (machine-readable). --md additionally writes summary.md.
Everything in the output is derived from the audit files - no hand-entered numbers.
"""
import argparse
import datetime
import json
import sys
from collections import Counter, OrderedDict
from html import escape
from pathlib import Path

import yaml

LEVELS = OrderedDict([("L1", "CIS Level 1"), ("L2", "CIS Level 2"), ("X", "Additional checks")])
STATUS_WORD = {"PASS": "Pass", "FAIL": "Fail", "ACCEPTED": "Accepted", "MANUAL": "Manual", "NA": "N/A"}
STATUS_CLASS = {"PASS": "pass", "FAIL": "fail", "ACCEPTED": "acc", "MANUAL": "manual", "NA": "na"}
LEVEL_WORD = {"L1": "Level 1", "L2": "Level 2", "X": "Additional"}


# ------------------------------------------------------------------ input ---
class InputError(Exception):
    """Audit input that cannot be turned into a trustworthy report."""


_CTRL = {c: " " for c in range(32) if c != 9}     # control characters other than TAB


def load_tsv(path, require_checks=True):
    """Read cis_audit.tsv. The file is whatever the audited host printed, so it is treated
    as untrusted: undecodable bytes are replaced, stray control characters removed, and
    anything that is not a well-formed row stops the report instead of being guessed at."""
    meta, rows = {}, OrderedDict()
    text = Path(path).read_bytes().decode("utf-8", errors="replace")
    for n, line in enumerate(text.split("\n"), 1):
        line = line.rstrip("\r").translate(_CTRL)
        if not line.strip():
            continue
        parts = line.split("\t")
        if parts[0] == "#meta":
            if len(parts) >= 2:
                meta[parts[1]] = parts[2] if len(parts) > 2 else ""
            continue
        if line.startswith("#"):
            continue
        if len(parts) < 6 or not parts[0] or parts[4] not in STATUS_WORD or parts[4] == "ACCEPTED":
            raise InputError(f"{path}: line {n} is not an audit row (expected ID, CIS, LEVEL, GROUP, "
                             f"STATUS, TITLE, EVIDENCE with STATUS one of PASS/FAIL/MANUAL/NA): {line[:80]!r}")
        parts += [""] * (7 - len(parts))
        cid, cis, level, group, status, title, evidence = parts[:7]
        rows[cid] = dict(id=cid, cis=cis, level=level, group=group, status=status, title=title, evidence=evidence)
    if require_checks and not rows:
        raise InputError(f"{path}: no audit rows. An empty audit must not be reported as 'no findings'.")
    return meta, rows


def load_lynis(path):
    p = Path(path)
    if not p.exists():
        return None
    out = {"warnings": [], "suggestions": []}
    for line in p.read_text(errors="replace").splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k == "hardening_index":
            if v.strip().isdigit():
                out["hardening_index"] = int(v)
        elif k == "lynis_version":
            out["version"] = v
        elif k == "warning[]":
            out["warnings"].append(v.split("|")[:2])
        elif k == "suggestion[]":
            out["suggestions"].append(v.split("|")[:2])
    return out


def score(rows, level=None, group=None):
    c = Counter(r["status"] for r in rows.values()
                if (level is None or r["level"] == level) and (group is None or r["group"] == group))
    sel = [r for r in rows.values()
           if (level is None or r["level"] == level) and (group is None or r["group"] == group)]
    acc_fail = sum(1 for r in sel if r["status"] == "ACCEPTED" and r.get("raw_status") == "FAIL")
    scored = c["PASS"] + c["FAIL"] + acc_fail
    pct = round(100 * c["PASS"] / scored, 1) if scored else None
    return dict(passed=c["PASS"], failed=c["FAIL"], accepted=c["ACCEPTED"], manual=c["MANUAL"], na=c["NA"],
                scored=scored, pct=pct)


def load_exceptions(path, host, today):
    """Accepted-risk register: inventory/<env>/exceptions.yml.

    Each entry needs id, reason, accepted_by and expires (YYYY-MM-DD). An optional hosts
    list limits it to some inventory hosts. A malformed entry stops the report: an
    acceptance nobody can attribute or that never expires is not an acceptance.
    """
    if not path:
        return {}
    if not Path(path).exists():
        raise InputError(f"{path}: exceptions file not found")
    data = yaml.safe_load(Path(path).read_text()) or {}
    entries = data.get("exceptions") if isinstance(data, dict) else None
    if entries is None:
        entries = []
    if not isinstance(entries, list):
        raise InputError(f"{path}: 'exceptions' must be a list")
    out, errors, seen = {}, [], set()
    for n, e in enumerate(entries, 1):
        if not isinstance(e, dict):
            errors.append(f"entry {n}: must be a mapping with id, reason, accepted_by and expires")
            continue
        cid = str(e.get("id", "")).strip()
        missing = [k for k in ("id", "reason", "accepted_by", "expires") if not str(e.get(k, "") or "").strip()]
        if missing:
            errors.append(f"entry {n} ({cid or 'no id'}): missing {', '.join(missing)}")
            continue
        exp = e["expires"]
        if isinstance(exp, datetime.datetime):
            exp = exp.date()
        if not isinstance(exp, datetime.date):
            try:
                exp = datetime.date.fromisoformat(str(exp).strip())
            except ValueError:
                errors.append(f"entry {n} ({cid}): expires must be YYYY-MM-DD")
                continue
        hosts = e.get("hosts")
        if isinstance(hosts, str):
            hosts = [hosts]               # "hosts: web01" means that one host, not a substring test
        if hosts is not None and not isinstance(hosts, list):
            errors.append(f"entry {n} ({cid}): hosts must be a list of inventory host names")
            continue
        if hosts and host not in [str(h) for h in hosts]:
            continue
        if cid in seen:
            errors.append(f"entry {n} ({cid}): a second entry for the same check and host; keep one")
            continue
        seen.add(cid)
        out[cid] = dict(id=cid, reason=str(e["reason"]).strip(), accepted_by=str(e["accepted_by"]).strip(),
                        expires=exp.isoformat(), expired=exp < today)
    if errors:
        raise InputError(f"{path}:\n  " + "\n  ".join(errors))
    return out


def fmt_pct(s):
    return "n/a" if s is None or s["pct"] is None else f'{s["pct"]}%'


def run_dirs(host_dir):
    """Audit runs of one host, oldest first: 'baseline' then timestamped directories."""
    host_dir = Path(host_dir)

    def when(p):       # the time the audit ran, as recorded by the audit itself
        try:
            for line in (p / "cis_audit.tsv").read_bytes().decode("utf-8", "replace").split("\n")[:12]:
                f = line.split("\t")
                if f[:2] == ["#meta", "date_utc"] and len(f) > 2:
                    return (f[2], p.name)
        except OSError:
            pass
        return ("", p.name)

    runs = sorted((p for p in host_dir.iterdir() if p.is_dir() and not p.is_symlink()
                   and p.name != "baseline" and not p.name.startswith("_")
                   and (p / "cis_audit.tsv").exists()), key=when)
    base = host_dir / "baseline"
    return ([base] if (base / "cis_audit.tsv").exists() else []) + runs


def load_history(host_dir):
    out = []
    for p in run_dirs(host_dir):
        try:
            meta, rows = load_tsv(p / "cis_audit.tsv")
        except InputError:
            continue                      # an unreadable old run does not block today's report
        out.append(dict(name=p.name, has_report=(p / "report.html").exists(), date=meta.get("date_utc", ""), l1=score(rows, level="L1"),
                        l2=score(rows, level="L2"), all=score(rows)))
    return out


def build(current, baseline, catalogue, exceptions=None, host=None, today=None, history=None, previous=None):
    cat = yaml.safe_load(Path(catalogue).read_text())
    meta, cur = load_tsv(Path(current) / "cis_audit.tsv")
    lyn = load_lynis(Path(current) / "lynis-report.dat")
    bmeta, base, blyn = {}, None, None
    if baseline:
        bmeta, base = load_tsv(Path(baseline) / "cis_audit.tsv", require_checks=False)
        blyn = load_lynis(Path(baseline) / "lynis-report.dat")
    # Acceptance is applied here, on top of the audit evidence; cis_audit.tsv is never altered.
    host = host or Path(current).resolve().parent.name      # reports/<host>/<run>
    exc = load_exceptions(exceptions, host, today or datetime.date.today())
    stale = []
    for cid, x in exc.items():
        r = cur.get(cid)
        if r is None:
            stale.append(dict(x, why="no check with this ID"))
        elif r["status"] not in ("FAIL", "MANUAL"):
            stale.append(dict(x, why=f"the check now reports {STATUS_WORD[r['status']].lower()}"))
        else:
            r["exception"] = x
            if not x["expired"]:
                r["raw_status"], r["status"] = r["status"], "ACCEPTED"
    scores = OrderedDict((lv or "all", score(cur, level=lv)) for lv in list(LEVELS) + [None])
    bscores = OrderedDict((lv or "all", score(base, level=lv)) for lv in list(LEVELS) + [None]) if base is not None else None
    delta = dict(fixed=[], regressed=[], reclassified=[], new=[], missing=[])
    if base is not None:
        # a check the baseline had and this audit does not print at all
        delta["missing"] = [cid for cid in base if cid not in cur]
        for cid, r in cur.items():
            b = base.get(cid)
            now = r.get("raw_status", r["status"])     # compare audit results, not risk decisions
            if b is None:
                delta["new"].append(cid)
            elif b["status"] == "FAIL" and now == "PASS":
                delta["fixed"].append(cid)
            elif b["status"] == "PASS" and now == "FAIL":
                delta["regressed"].append(cid)
            elif b["status"] != now:
                delta["reclassified"].append(cid)
    # Drift: what changed since the audit before this one (not since the baseline).
    drift = None
    if previous and Path(previous).resolve() != Path(current).resolve():
        pmeta, prev = load_tsv(Path(previous) / "cis_audit.tsv", require_checks=False)
        drift = dict(date=pmeta.get("date_utc", ""), regressed=[], fixed=[])
        # A check that passed last time and is simply absent now is not "no change": the
        # control is no longer being verified. Count it as a regression.
        drift["missing"] = [cid for cid, pr in prev.items() if cid not in cur and pr["status"] == "PASS"]
        for cid, r in cur.items():
            now, was = r.get("raw_status", r["status"]), prev.get(cid, {}).get("status")
            if was == "PASS" and now == "FAIL":
                drift["regressed"].append(cid)
            elif was == "FAIL" and now == "PASS":
                drift["fixed"].append(cid)
        # a regression someone has formally accepted is not a surprise
        drift["unaccepted"] = [c for c in drift["regressed"] if cur[c]["status"] != "ACCEPTED"] + drift["missing"]
    hist = load_history(history) if history else []
    groups = list(OrderedDict.fromkeys(r["group"] for r in cur.values()))
    return dict(drift=drift, history=hist, run=Path(current).name, inv_host=host, cat=cat, meta=meta, cur=cur, lyn=lyn, bmeta=bmeta, base=base, blyn=blyn,
                scores=scores, bscores=bscores, delta=delta, groups=groups, stale=stale)


# --------------------------------------------------------------- markdown ---
def render_md(d):
    cur, base, cat, meta = d["cur"], d["base"], d["cat"], d["meta"]

    def esc(t):        # every value from the audited host: no raw HTML, no table breakage
        return escape(str(t), quote=False).replace("|", "\\|").replace("`", "'")

    L = [f"# Audit summary - {esc(meta.get('hostname', '?'))}", "",
         f"- Host: {esc(meta.get('hostname', '?'))} - {esc(meta.get('os', ''))} - kernel {esc(meta.get('kernel', ''))}",
         f"- Audit time (UTC): {esc(meta.get('date_utc', ''))} - audit script v{esc(meta.get('script_version', ''))}", ""]
    L += ["## Scores", "", "| Profile | Baseline | Current | Pass | Fail | Accepted | Manual | N/A |", "|---|---|---|---|---|---|---|---|"]
    for lv, name in list(LEVELS.items()) + [("all", "All checks")]:
        s = d["scores"][lv]
        b = fmt_pct(d["bscores"][lv]) if d["bscores"] else "-"
        L.append(f"| {name} | {b} | {fmt_pct(s)} | {s['passed']} | {s['failed']} | {s['accepted']} | {s['manual']} | {s['na']} |")
    L.append("")
    if base is not None:
        L += [f"Fixed: {len(d['delta']['fixed'])}, regressed: {len(d['delta']['regressed'])}, "
              f"other status changes: {len(d['delta']['reclassified'])}.", ""]
    for status, title in (("FAIL", "Open findings"), ("ACCEPTED", "Accepted risks"), ("MANUAL", "Manual review items")):
        items = [r for r in cur.values() if r["status"] == status]
        L += [f"## {title} ({len(items)})", "", "| ID | Lvl | Family | Check | Evidence |", "|---|---|---|---|---|"]
        L += [f"| {esc(r['id'])} | {esc(r['level'])} | {esc(r['group'])} | {esc(r['title'])} | {esc(r['evidence'])} |" for r in items]
        L.append("")
    L += ["## All checks", "", "| ID | CIS | Lvl | Family | Status | Baseline | Check | Evidence |", "|---|---|---|---|---|---|---|---|"]
    for r in cur.values():
        b = base[r["id"]]["status"] if base is not None and r["id"] in base else "-"
        L.append(f"| {esc(r['id'])} | {esc(r['cis'])} | {esc(r['level'])} | {esc(r['group'])} ({esc(cat.get(r['group'], {}).get('title', ''))}) | "
                 f"{r['status']} | {b} | {esc(r['title'])} | {esc(r['evidence'])} |")
    return "\n".join(L) + "\n"


# ------------------------------------------------------------------- html ---
CSS = """
:root{
  --bg:#ffffff;--panel:#f2f5f8;--ink:#12202e;--ink2:#4d5b69;--rule:#d5dde5;--link:#0b5d8a;
  --good:#0ca30c;--crit:#d03b3b;--warn:#fab219;--na:#a7b1bb;--warn-ink:#8a5a00;
  --sans:Ubuntu,Seravek,"Gill Sans Nova",Calibri,"DejaVu Sans","Segoe UI",sans-serif;
  --mono:"Ubuntu Mono",ui-monospace,"DejaVu Sans Mono",Menlo,Consolas,monospace;
  color-scheme:light;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#141b22;--panel:#1c252e;--ink:#eef2f5;--ink2:#a9b6c2;--rule:#2e3a46;--link:#74bde6;
  --na:#5d6b78;--warn-ink:#fab219;color-scheme:dark}}
:root[data-theme="dark"]{
  --bg:#141b22;--panel:#1c252e;--ink:#eef2f5;--ink2:#a9b6c2;--rule:#2e3a46;--link:#74bde6;
  --na:#5d6b78;--warn-ink:#fab219;color-scheme:dark}
*{box-sizing:border-box}
html{scroll-behavior:smooth;scroll-padding-top:4rem}
@media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
body{margin:0;background:var(--bg);color:var(--ink);font:1rem/1.55 var(--sans)}
a{color:var(--link);text-underline-offset:.15em}
a:focus-visible,button:focus-visible,input:focus-visible,summary:focus-visible{outline:2px solid var(--link);outline-offset:2px}
.wrap{max-width:70rem;margin:0 auto;padding:0 1.25rem}
nav.top{position:sticky;top:0;z-index:5;background:var(--bg);border-bottom:1px solid var(--rule)}
nav.top .wrap{display:flex;gap:1.25rem;align-items:center;min-height:3rem;overflow-x:auto;white-space:nowrap;scrollbar-width:none}
nav.top a{color:var(--ink2);text-decoration:none;font-size:.9rem}
nav.top a:hover{color:var(--ink);text-decoration:underline}
nav.top button{margin-left:auto;font:inherit;font-size:.85rem;color:var(--ink2);background:none;border:1px solid var(--rule);border-radius:.35rem;padding:.2rem .6rem;cursor:pointer}
header.hero{padding:3rem 0 1.5rem}
header.hero p.kind{margin:0;color:var(--ink2)}
h1{font-size:clamp(2.3rem,6vw,3.6rem);line-height:1.05;letter-spacing:-.02em;margin:.2rem 0 .8rem;font-weight:700;overflow-wrap:anywhere}
p.verdict{font-size:1.3rem;line-height:1.4;max-width:46rem;margin:0 0 1rem}
dl.meta{display:flex;flex-wrap:wrap;gap:.3rem 2rem;margin:0;color:var(--ink2);font-size:.92rem}
dl.meta div{display:flex;gap:.4rem}
dl.meta dt{color:var(--ink2)}dl.meta dd{margin:0;color:var(--ink)}
section{padding:2rem 0;border-top:1px solid var(--rule)}
h2{font-size:1.45rem;margin:0 0 .3rem;letter-spacing:-.01em}
p.note{color:var(--ink2);margin:.2rem 0 1rem;max-width:46rem}
/* check map */
.legend{display:flex;flex-wrap:wrap;gap:.4rem 1.2rem;margin:.6rem 0 1rem;font-size:.9rem;color:var(--ink2)}
.legend span{display:inline-flex;align-items:center;gap:.4rem}
.map{display:grid;grid-template-columns:minmax(11rem,17rem) 1fr 1fr max-content;gap:.45rem 1.25rem;align-items:start}
.map.single{grid-template-columns:minmax(11rem,17rem) 1fr max-content}
.map .h{font-size:.85rem;color:var(--ink2);padding-bottom:.2rem;border-bottom:1px solid var(--rule)}
.map .fam{font-size:.92rem}
.map .fam a{color:var(--ink);text-decoration:none}.map .fam a:hover{text-decoration:underline}
.map .num{font-size:.85rem;color:var(--ink2);font-variant-numeric:tabular-nums;text-align:right;white-space:nowrap}
.cells{display:flex;flex-wrap:wrap;gap:2px;padding-top:.3rem}
.c{display:block;width:12px;height:12px;border-radius:2px;position:relative;flex:none}
.c.pass{background:var(--good)}
.c.fail{background:var(--crit)}
.c.fail::after{content:"";position:absolute;inset:2px;background:
  linear-gradient(45deg,transparent 42%,#fff 42% 58%,transparent 58%),
  linear-gradient(-45deg,transparent 42%,#fff 42% 58%,transparent 58%)}
.c.manual{border:2.5px solid var(--warn);background:transparent}
.c.na{background:var(--na);transform:scale(.5);border-radius:50%}
.c.acc{border:2px solid var(--ink2);background:linear-gradient(45deg,transparent 40%,var(--ink2) 40% 60%,transparent 60%)}
.acc-note{color:var(--ink2);font-size:.85rem;margin-top:.2rem;max-width:34rem}
.expired{color:var(--crit);font-weight:600}
:root{--series:#2a78d6}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--series:#3987e5}}
:root[data-theme="dark"]{--series:#3987e5}
.trend{width:100%;max-width:44rem;height:auto;display:block;margin:.5rem 0 1rem}
.trend .grid{stroke:var(--rule);stroke-width:1}
.trend .line{fill:none;stroke:var(--series);stroke-width:2;stroke-linejoin:round}
.trend .dot{fill:var(--series);stroke:var(--bg);stroke-width:2}
.trend .hit{fill:transparent}
.trend text{fill:var(--ink2);font-size:11px;font-family:var(--sans)}
.trend text.val{fill:var(--ink);font-weight:600}
tr.cur td{background:var(--panel)}
a.c:hover,a.c:focus-visible{outline:2px solid var(--ink);outline-offset:1px}
#tip{position:fixed;z-index:20;pointer-events:none;max-width:22rem;background:var(--ink);color:var(--bg);
  font-size:.82rem;line-height:1.35;padding:.4rem .55rem;border-radius:.3rem;display:none}
/* tables */
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.92rem}
th{text-align:left;font-weight:600;color:var(--ink2);font-size:.85rem;border-bottom:1px solid var(--rule);padding:.4rem .7rem .4rem 0;white-space:nowrap}
td{vertical-align:top;border-bottom:1px solid var(--rule);padding:.5rem .7rem .5rem 0}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
td.id{white-space:nowrap;font-weight:600}td.lv{white-space:nowrap}
td.ev{font-family:var(--mono);font-size:.84rem;color:var(--ink2);overflow-wrap:anywhere;min-width:14rem}
table.scores td.big{font-size:1.15rem;font-weight:700}
.st{display:inline-flex;align-items:center;gap:.4rem;white-space:nowrap}
.was{color:var(--ink2);font-size:.85rem}
tr:target td{background:var(--panel)}
/* families */
details{border-bottom:1px solid var(--rule)}
details>summary{cursor:pointer;list-style:none;display:grid;grid-template-columns:1fr max-content;gap:.5rem 1rem;padding:.75rem 0;align-items:baseline}
details>summary::-webkit-details-marker{display:none}
details>summary .t{font-weight:600;font-size:1.05rem}
details>summary .t::before{content:"+";display:inline-block;width:1.1rem;color:var(--ink2);font-weight:400}
details[open]>summary .t::before{content:"\\2212"}
details>summary .s{color:var(--ink2);font-size:.88rem;font-variant-numeric:tabular-nums}
.why{display:grid;grid-template-columns:8rem 1fr;gap:.45rem 1rem;margin:.2rem 0 1.2rem 1.1rem;max-width:58rem;font-size:.95rem}
.why dt{color:var(--ink2)}.why dd{margin:0}
.why dd.cmd{font-family:var(--mono);font-size:.86rem;overflow-wrap:anywhere}
details .scroll{margin:0 0 1.2rem 1.1rem}
.filter{display:flex;flex-wrap:wrap;gap:.6rem 1.2rem;align-items:center;margin:.8rem 0 .4rem}
.filter input[type=search]{font:inherit;padding:.4rem .6rem;border:1px solid var(--rule);border-radius:.35rem;background:var(--bg);color:var(--ink);min-width:min(22rem,100%)}
.filter label{display:inline-flex;align-items:center;gap:.35rem;font-size:.92rem}
#count{color:var(--ink2);font-size:.88rem}
footer{padding:2rem 0 3rem;border-top:1px solid var(--rule);color:var(--ink2);font-size:.88rem}
footer p{max-width:52rem;margin:.3rem 0}
@media (max-width:720px){
  .map,.map.single{grid-template-columns:1fr max-content}
  .map .h{display:none}
  .map .fam{grid-column:1/-1;font-weight:600;padding-top:.4rem}.map .num{display:none}
  .map .cells{grid-column:1/-1;padding-top:0}
  .map .cells.b::before{content:"Baseline";font-size:.78rem;color:var(--ink2);width:100%}
  .map .cells.n::before{content:"Now";font-size:.78rem;color:var(--ink2);width:100%}
  .why{grid-template-columns:1fr;gap:.1rem}.why dd{margin-bottom:.5rem}
}
@media print{
  nav.top,.filter,#tip{display:none}
  body{font-size:10pt}section{break-inside:auto;padding:1rem 0}
  tr,details>summary{break-inside:avoid}a{color:inherit;text-decoration:none}
  .c,.c::after{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
"""

JS = """
(function(){
  var root=document.documentElement,btn=document.getElementById('theme');
  try{var t=localStorage.getItem('harden-theme');if(t)root.dataset.theme=t}catch(e){}
  btn.addEventListener('click',function(){
    var dark=root.dataset.theme?root.dataset.theme==='dark':matchMedia('(prefers-color-scheme:dark)').matches;
    root.dataset.theme=dark?'light':'dark';try{localStorage.setItem('harden-theme',root.dataset.theme)}catch(e){}
  });
  var tip=document.getElementById('tip');
  function show(e){var el=e.target.closest('[data-tip]');if(!el){tip.style.display='none';return}
    tip.textContent=el.dataset.tip;tip.style.display='block';
    var r=el.getBoundingClientRect(),w=tip.offsetWidth,h=tip.offsetHeight;
    var x=Math.min(Math.max(8,r.left+r.width/2-w/2),innerWidth-w-8),y=r.top-h-8;if(y<8)y=r.bottom+8;
    tip.style.left=x+'px';tip.style.top=y+'px'}
  document.addEventListener('mouseover',show);document.addEventListener('focusin',show);
  document.addEventListener('mouseout',function(e){if(e.target.closest('[data-tip]'))tip.style.display='none'});
  document.addEventListener('focusout',function(){tip.style.display='none'});
  function openTarget(){var id=decodeURIComponent(location.hash.slice(1));if(!id)return;
    var el=document.getElementById(id);if(!el)return;var d=el.closest('details');
    if(d&&!d.open){d.open=true;el.scrollIntoView()}}
  addEventListener('hashchange',openTarget);openTarget();
  var q=document.getElementById('q'),boxes=[].slice.call(document.querySelectorAll('.filter input[type=checkbox]')),
      count=document.getElementById('count'),fams=[].slice.call(document.querySelectorAll('#families details'));
  function apply(){
    var text=q.value.trim().toLowerCase(),on={};boxes.forEach(function(b){on[b.value]=b.checked});
    var active=text!==''||boxes.some(function(b){return !b.checked}),shown=0,total=0;
    fams.forEach(function(d){var any=false;
      [].forEach.call(d.querySelectorAll('tbody tr'),function(tr){total++;
        var ok=on[tr.dataset.status]&&(text===''||tr.textContent.toLowerCase().indexOf(text)>=0);
        tr.hidden=!ok;if(ok){any=true;shown++}});
      d.hidden=!any;if(active)d.open=any;});
    count.textContent=active?('Showing '+shown+' of '+total+' checks'):(total+' checks');
  }
  q.addEventListener('input',apply);boxes.forEach(function(b){b.addEventListener('change',apply)});apply();
  addEventListener('beforeprint',function(){fams.forEach(function(d){d.open=true})});
})();
"""


def cell(r, link=True):
    cls = STATUS_CLASS[r["status"]]
    tip = escape(f'{r["id"]} {STATUS_WORD[r["status"]]}: {r["title"]}', quote=True)
    if link:
        return f'<a class="c {cls}" href="#chk-{escape(r["id"])}" data-tip="{tip}" aria-label="{tip}"></a>'
    return f'<span class="c {cls}" data-tip="{tip}"></span>'


def status_html(status):
    cls = STATUS_CLASS[status]
    return f'<span class="st"><span class="c {cls}"></span>{STATUS_WORD[status]}</span>'


def counts_text(s):
    parts = [f'{s["passed"]} pass', f'{s["failed"]} fail']
    if s["accepted"]:
        parts.append(f'{s["accepted"]} accepted')
    if s["manual"]:
        parts.append(f'{s["manual"]} manual')
    if s["na"]:
        parts.append(f'{s["na"]} n/a')
    return ", ".join(parts)


def render_html(d):
    cur, base, cat, meta, delta = d["cur"], d["base"], d["cat"], d["meta"], d["delta"]
    e = escape
    host = meta.get("hostname", "unknown host")
    l1 = d["scores"]["L1"]
    n_open = d["scores"]["all"]["failed"]
    n_manual = d["scores"]["all"]["manual"]
    n_acc = d["scores"]["all"]["accepted"]
    verdict = [f'{l1["passed"]} of {l1["scored"]} CIS Level 1 checks pass.']
    verdict.append("No findings are open." if not n_open else
                   f'{n_open} finding{"s are" if n_open != 1 else " is"} open'
                   + (f' and {n_manual} need{"s" if n_manual == 1 else ""} a manual decision.' if n_manual else "."))
    if n_acc:
        verdict.append(f'{n_acc} {"are" if n_acc != 1 else "is"} accepted with a recorded reason.')
    if base is not None:
        nr = len(delta["regressed"])
        verdict.append(f'{len(delta["fixed"])} checks were fixed since the baseline and '
                       + ("none regressed." if not nr else f'{nr} regressed.'))
    if d["drift"] and (d["drift"]["regressed"] or d["drift"]["missing"]):
        n = len(d["drift"]["regressed"]) + len(d["drift"]["missing"])
        verdict.append(f'{n} check{"s have" if n != 1 else " has"} regressed since the previous audit.')
    H = []
    w = H.append
    w(f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
      f'<meta name="viewport" content="width=device-width,initial-scale=1">'
      f'<title>Hardening audit: {e(host)}</title><style>{CSS}</style></head><body>')
    w('<nav class="top" aria-label="Sections"><div class="wrap">'
      '<a href="#map">Check map</a><a href="#scores">Scores</a><a href="#open">Open findings</a><a href="#accepted">Accepted</a>'
      '<a href="#manual">Manual review</a><a href="#families">Control families</a>'
      + ('<a href="#history">History</a>' if len(d["history"]) > 1 else '')
      + ('<a href="#lynis">Lynis</a>' if d["lyn"] else '')
      + '<button id="theme" type="button">Switch theme</button></div></nav>')
    w('<div class="wrap">')
    w(f'<header class="hero"><p class="kind">Hardening audit</p><h1>{e(host)}</h1>'
      f'<p class="verdict">{e(" ".join(verdict))}</p><dl class="meta">')
    facts = [("System", meta.get("os", "")), ("Kernel", meta.get("kernel", "")),
             ("Audited", meta.get("date_utc", "").replace("T", " ").replace("Z", " UTC"))]
    if base is not None:
        facts.append(("Baseline", d["bmeta"].get("date_utc", "").replace("T", " ").replace("Z", " UTC")))
    for k, v in facts:
        w(f'<div><dt>{k}</dt><dd>{e(v)}</dd></div>')
    w('</dl></header>')

    # ---- check map
    w('<section id="map"><h2>Check map</h2>'
      '<p class="note">One cell per check, grouped by control family. Select a cell to see its evidence.</p>'
      '<div class="legend">'
      + "".join(f'<span><span class="c {c}"></span>{t}</span>' for c, t in
                (("pass", "Pass"), ("fail", "Fail"), ("acc", "Accepted risk"), ("manual", "Manual decision"), ("na", "Not applicable")))
      + '</div>')
    w(f'<div class="map{"" if base is not None else " single"}">')
    w('<div class="h">Control family</div>' + ('<div class="h">Baseline</div>' if base is not None else '')
      + '<div class="h">Now</div><div class="h">Pass / fail</div>')
    for g in d["groups"]:
        s = score(cur, group=g)
        title = cat.get(g, {}).get("title", g)
        w(f'<div class="fam"><a href="#fam-{e(g)}">{e(title)}</a></div>')
        if base is not None:
            w('<div class="cells b">' + "".join(cell(base[cid]) for cid, r in cur.items() if r["group"] == g and cid in base) + '</div>')
        w('<div class="cells n">' + "".join(cell(r) for r in cur.values() if r["group"] == g) + '</div>')
        w(f'<div class="num">{s["passed"]} / {s["failed"]}</div>')
    w('</div></section>')

    # ---- scores
    w('<section id="scores"><h2>Scores</h2>'
      '<p class="note">Share of checks passing out of those that pass or fail. An accepted failure still counts against the score: '
      'accepting a risk does not make the benchmark pass. Manual and not-applicable checks are excluded. '
      'A score is a regression signal; the open findings are the result.</p><div class="scroll"><table class="scores"><thead><tr>'
      '<th>Profile</th>' + ('<th class="n">Baseline</th>' if base is not None else '')
      + '<th class="n">Now</th><th class="n">Pass</th><th class="n">Fail</th><th class="n">Accepted</th><th class="n">Manual</th><th class="n">N/A</th></tr></thead><tbody>')
    for lv, name in list(LEVELS.items()) + [("all", "All checks")]:
        s = d["scores"][lv]
        b = f'<td class="n">{fmt_pct(d["bscores"][lv])}</td>' if base is not None else ''
        w(f'<tr><td>{name}</td>{b}<td class="n big">{fmt_pct(s)}</td><td class="n">{s["passed"]}</td>'
          f'<td class="n">{s["failed"]}</td><td class="n">{s["accepted"]}</td><td class="n">{s["manual"]}</td><td class="n">{s["na"]}</td></tr>')
    if d["lyn"]:
        b = f'<td class="n">{d["blyn"].get("hardening_index", "n/a")}</td>' if d["blyn"] else ('<td class="n"></td>' if base is not None else '')
        w(f'<tr><td>Lynis hardening index (0 to 100)</td>{b}<td class="n big">{d["lyn"].get("hardening_index", "n/a")}</td>'
          f'<td class="n" colspan="5">{len(d["lyn"]["warnings"])} warnings, {len(d["lyn"]["suggestions"])} suggestions</td></tr>')
    w('</tbody></table></div>')
    if base is not None and (delta["regressed"] or delta["reclassified"]):
        w('<h2 style="margin-top:1.6rem;font-size:1.15rem">Status changes other than fixes</h2>'
          '<div class="scroll"><table><thead><tr><th>ID</th><th>Check</th><th>Was</th><th>Now</th><th>Evidence</th></tr></thead><tbody>')
        for cid in delta["regressed"] + delta["reclassified"]:
            r = cur[cid]
            w(f'<tr><td class="id"><a href="#chk-{e(cid)}">{e(cid)}</a></td><td>{e(r["title"])}</td>'
              f'<td>{status_html(base[cid]["status"])}</td><td>{status_html(r.get("raw_status", r["status"]))}</td><td class="ev">{e(r["evidence"])}</td></tr>')
        w('</tbody></table></div>')
    w('</section>')

    # ---- open + manual
    def exc_note(r):
        x = r.get("exception")
        if not x:
            return ""
        if x["expired"]:
            return (f'<div class="acc-note"><span class="expired">Acceptance expired {e(x["expires"])}.</span> '
                    f'Was accepted by {e(x["accepted_by"])}: {e(x["reason"])}</div>')
        return f'<div class="acc-note">Accepted by {e(x["accepted_by"])} until {e(x["expires"])}: {e(x["reason"])}</div>'

    def findings(anchor, title, status, note, empty):
        items = [r for r in cur.values() if r["status"] == status]
        w(f'<section id="{anchor}"><h2>{title} ({len(items)})</h2><p class="note">{note}</p>')
        if not items:
            w(f'<p>{empty}</p></section>')
            return
        w('<div class="scroll"><table><thead><tr><th>ID</th><th>Level</th><th>Family</th><th>Check</th><th>Evidence</th></tr></thead><tbody>')
        for r in items:
            fam = cat.get(r["group"], {}).get("title", r["group"])
            lvl = e(LEVEL_WORD.get(r["level"], r["level"]))
            w(f'<tr><td class="id"><a href="#chk-{e(r["id"])}">{e(r["id"])}</a></td><td>{lvl}</td>'
              f'<td><a href="#fam-{e(r["group"])}">{e(fam)}</a></td><td>{e(r["title"])}{exc_note(r)}</td><td class="ev">{e(r["evidence"])}</td></tr>')
        w('</tbody></table></div></section>')

    findings("open", "Open findings", "FAIL",
             "Each one needs a decision: fix it, or accept it with a written reason. The family link explains the control and its impact.",
             "Nothing is failing.")
    acc = [r for r in cur.values() if r["status"] == "ACCEPTED"]
    w(f'<section id="accepted"><h2>Accepted risks ({len(acc)})</h2>'
      '<p class="note">Findings someone has decided to live with, from the environment\'s exceptions file. '
      'Each has an owner and an expiry date; when it expires the finding returns to the open list.</p>')
    if acc:
        w('<div class="scroll"><table><thead><tr><th>ID</th><th>Check</th><th>Reason</th><th>Accepted by</th><th>Expires</th><th>Evidence</th></tr></thead><tbody>')
        for r in acc:
            x = r["exception"]
            w(f'<tr><td class="id"><a href="#chk-{e(r["id"])}">{e(r["id"])}</a></td><td>{e(r["title"])}</td><td>{e(x["reason"])}</td>'
              f'<td>{e(x["accepted_by"])}</td><td class="lv">{e(x["expires"])}</td><td class="ev">{e(r["evidence"])}</td></tr>')
        w('</tbody></table></div>')
    else:
        w('<p>No risks are accepted. To accept one, add it to <code>exceptions.yml</code> in the inventory folder.</p>')
    if d["stale"]:
        w('<p class="note" style="margin-top:1rem">Entries in the exceptions file that no longer apply and should be removed: '
          + "; ".join(f'{e(x["id"])} ({e(x["why"])})' for x in d["stale"]) + '.</p>')
    w('</section>')
    findings("manual", "Manual review", "MANUAL",
             "A script cannot decide these. The evidence is the input for the reviewer.",
             "Nothing needs manual review.")

    # ---- families
    w('<section id="families"><h2>Control families</h2>'
      '<p class="note">Every check, with what the control changes, why, what it can break, and how to verify and undo it.</p>'
      '<div class="filter"><input id="q" type="search" placeholder="Filter checks by ID, text or evidence" aria-label="Filter checks">'
      + "".join(f'<label><input type="checkbox" value="{k}" checked>{v}</label>' for k, v in STATUS_WORD.items())
      + '<span id="count"></span></div>')
    for g in d["groups"]:
        c = cat.get(g, {})
        s = score(cur, group=g)
        w(f'<details id="fam-{e(g)}"><summary><span class="t">{e(c.get("title", g))}</span>'
          f'<span class="s">CIS {e(str(c.get("cis", "-")))}, {counts_text(s)}</span></summary>')
        if c:
            w('<dl class="why">')
            for label, key, cls in (("What changes", "change", ""), ("Why", "why", ""), ("Impact", "impact", ""),
                                    ("Verify", "validate", "cmd"), ("Undo", "rollback", "cmd"), ("Done by", "source", "")):
                if c.get(key):
                    w(f'<dt>{label}</dt><dd class="{cls}">{e(str(c[key]).strip())}</dd>')
            maps = []
            if c.get("iso"):
                maps.append("ISO 27001 " + ", ".join(c["iso"]))
            if c.get("pci"):
                maps.append("PCI DSS " + ", ".join(c["pci"]))
            if maps:
                w(f'<dt>Maps to</dt><dd>{e("; ".join(maps))}</dd>')
            w('</dl>')
        w('<div class="scroll"><table><thead><tr><th>Status</th><th>ID</th><th>Level</th><th>Check</th><th>Evidence</th></tr></thead><tbody>')
        for r in cur.values():
            if r["group"] != g:
                continue
            was = ""
            if base is not None and r["id"] in base and base[r["id"]]["status"] != r.get("raw_status", r["status"]):
                was = f'<div class="was">was {STATUS_WORD[base[r["id"]]["status"]].lower()}</div>'
            w(f'<tr id="chk-{e(r["id"])}" data-status="{r["status"]}"><td>{status_html(r["status"])}{was}</td>'
              f'<td class="id">{e(r["id"])}</td><td>{e(LEVEL_WORD.get(r["level"], r["level"]))}</td><td>{e(r["title"])}{exc_note(r)}</td><td class="ev">{e(r["evidence"])}</td></tr>')
        w('</tbody></table></div></details>')
    w('</section>')

    # ---- history and drift
    hist = d["history"]
    if len(hist) > 1 or d["drift"]:
        w('<section id="history"><h2>History</h2>')
        if d["drift"]:
            dr = d["drift"]
            when = dr["date"].replace("T", " ").replace("Z", " UTC")
            if dr["missing"]:
                w(f'<p class="note"><span class="expired">No longer checked:</span> {e(", ".join(dr["missing"]))}. '
                  'These passed in the previous audit and are absent from this one, so they count as regressions.</p>')
            if dr["regressed"] or dr["fixed"]:
                w(f'<p class="note">Since the previous audit ({e(when)}): {len(dr["regressed"])} regressed, {len(dr["fixed"])} fixed.</p>')
                w('<div class="scroll"><table><thead><tr><th>Change</th><th>ID</th><th>Check</th><th>Evidence</th></tr></thead><tbody>')
                for kind, ids in (("Regressed", dr["regressed"]), ("Fixed", dr["fixed"])):
                    for cid in ids:
                        r = cur[cid]
                        w(f'<tr><td>{status_html("FAIL" if kind == "Regressed" else "PASS")} {kind.lower()}</td>'
                          f'<td class="id"><a href="#chk-{e(cid)}">{e(cid)}</a></td><td>{e(r["title"])}{exc_note(r)}</td><td class="ev">{e(r["evidence"])}</td></tr>')
                w('</tbody></table></div>')
            else:
                w(f'<p class="note">Nothing passed or failed differently since the previous audit ({e(when)}).</p>')
        if len(hist) > 1:
            pts = [h for h in hist if h["l1"]["pct"] is not None]
            if len(pts) > 1:
                W, Hh, L, R, T, B = 640, 170, 34, 46, 14, 26
                xs = [L + i * (W - L - R) / (len(pts) - 1) for i in range(len(pts))]
                ys = [T + (100 - h["l1"]["pct"]) * (Hh - T - B) / 100 for h in pts]
                w(f'<svg class="trend" viewBox="0 0 {W} {Hh}" role="img" aria-label="CIS Level 1 score per audit">')
                for v in (0, 50, 100):
                    y = T + (100 - v) * (Hh - T - B) / 100
                    w(f'<line class="grid" x1="{L}" x2="{W - R}" y1="{y:.1f}" y2="{y:.1f}"/><text x="{L - 6}" y="{y + 4:.1f}" text-anchor="end">{v}%</text>')
                w('<polyline class="line" points="' + " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys)) + '"/>')
                for h, x, y in zip(pts, xs, ys):
                    tip = e(f'{h["date"][:10]} ({h["name"]}): Level 1 {h["l1"]["pct"]}%, {h["all"]["failed"]} failing', quote=True)
                    w(f'<circle class="dot" cx="{x:.1f}" cy="{y:.1f}" r="4.5"/><circle class="hit" cx="{x:.1f}" cy="{y:.1f}" r="12" data-tip="{tip}"/>')
                w(f'<text class="val" x="{xs[-1] + 9:.1f}" y="{ys[-1] + 4:.1f}">{pts[-1]["l1"]["pct"]}%</text>')
                w(f'<text x="{xs[0]:.1f}" y="{Hh - 6}" text-anchor="start">{e(pts[0]["date"][:10])}</text>'
                  f'<text x="{xs[-1]:.1f}" y="{Hh - 6}" text-anchor="end">{e(pts[-1]["date"][:10])}</text></svg>')
            w('<p class="note">CIS Level 1 score at each audit of this host. Scores here are the audit result before any accepted risks.</p>'
              '<div class="scroll"><table><thead><tr><th>Audit</th><th>Date (UTC)</th><th class="n">Level 1</th><th class="n">Level 2</th>'
              '<th class="n">Failing</th><th class="n">Manual</th><th>Report</th></tr></thead><tbody>')
            for h in reversed(hist):
                me = h["name"] == d["run"]
                link = "this report" if me else (f'<a href="../{e(h["name"])}/report.html">open</a>' if h["has_report"] else "not rendered")
                w(f'<tr{" class=cur" if me else ""}><td class="id">{e(h["name"])}</td><td>{e(h["date"].replace("T", " ").replace("Z", ""))}</td>'
                  f'<td class="n">{fmt_pct(h["l1"])}</td><td class="n">{fmt_pct(h["l2"])}</td><td class="n">{h["all"]["failed"]}</td>'
                  f'<td class="n">{h["all"]["manual"]}</td><td>{link}</td></tr>')
            w('</tbody></table></div>')
        w('</section>')

    # ---- lynis
    if d["lyn"]:
        lyn = d["lyn"]
        w(f'<section id="lynis"><h2>Lynis</h2><p class="note">Independent second opinion from Lynis {e(lyn.get("version", ""))}. '
          'Its test IDs are its own and do not map to CIS.</p>')
        if lyn["warnings"] or lyn["suggestions"]:
            w('<div class="scroll"><table><thead><tr><th>Kind</th><th>Test</th><th>Text</th></tr></thead><tbody>')
            for kind, items in (("Warning", lyn["warnings"]), ("Suggestion", lyn["suggestions"])):
                for it in items:
                    w(f'<tr><td>{kind}</td><td class="id">{e(it[0])}</td><td>{e(it[1] if len(it) > 1 else "")}</td></tr>')
            w('</tbody></table></div>')
        else:
            w('<p>No warnings or suggestions.</p>')
        w('</section>')

    w(f'<footer><p>Generated by HardenProof (tools/report.py) from cis_audit.tsv (audit script v{e(meta.get("script_version", "?"))}) '
      'and lynis-report.dat. No number on this page was entered by hand.</p>'
      '<p>CIS references are section numbers of the CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0, the nearest published '
      'benchmark. Confirm exact recommendation numbers against the licensed document before quoting them.</p></footer>')
    w(f'</div><div id="tip" role="tooltip"></div><script>{JS}</script></body></html>')
    return "".join(H)


def render_fleet(reports_dir):
    """Index across hosts, built from each host's latest results.json."""
    e = escape
    rows = []
    for hd in sorted(p for p in Path(reports_dir).iterdir() if p.is_dir() and not p.name.startswith("_")):
        runs = [p for p in run_dirs(hd) if (p / "results.json").exists()]
        if not runs:
            continue
        try:
            r = json.loads((runs[-1] / "results.json").read_text())
            sc = r["scores"]
            for k in ("L1", "L2", "all"):
                for f in ("failed", "accepted", "manual", "pct"):
                    sc[k].setdefault(f, 0 if f != "pct" else None)
            r.setdefault("meta", {})
        except (ValueError, KeyError, TypeError, OSError) as err:
            print(f"warning: skipping {hd.name}: unreadable results.json ({err.__class__.__name__})", file=sys.stderr)
            continue
        rows.append((hd.name, runs[-1].name, r))
    H = []
    w = H.append
    w(f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
      f'<title>Hardening audit: all hosts</title><style>{CSS}</style></head><body><nav class="top"><div class="wrap">'
      '<a href="#hosts">Hosts</a><button id="theme" type="button">Switch theme</button></div></nav><div class="wrap">')
    n_open = sum(r["scores"]["all"]["failed"] for _, _, r in rows)
    n_reg = sum(len((r.get("drift") or {}).get("unaccepted", [])) for _, _, r in rows)
    verdict = f'{len(rows)} host{"s" if len(rows) != 1 else ""} audited. {n_open} finding{"s" if n_open != 1 else ""} open in total'
    verdict += f', and {n_reg} check{"s have" if n_reg != 1 else " has"} regressed since the previous audit.' if n_reg else '.'
    w(f'<header class="hero"><p class="kind">Hardening audit</p><h1>All hosts</h1><p class="verdict">{e(verdict)}</p></header>')
    w('<section id="hosts"><h2>Hosts</h2><p class="note">Latest audit of each host. Sorted with regressions and the most open findings first.</p>'
      '<div class="filter"><input id="q" type="search" placeholder="Filter hosts" aria-label="Filter hosts"><span id="count"></span></div>'
      '<div id="families"><details open><summary style="display:none"></summary><div class="scroll"><table><thead><tr><th>Host</th><th>System</th>'
      '<th>Audited (UTC)</th><th class="n">Level 1</th><th class="n">Level 2</th><th class="n">Open</th><th class="n">Accepted</th>'
      '<th class="n">Manual</th><th class="n">Regressed</th><th>Report</th></tr></thead><tbody>')
    rows.sort(key=lambda x: (-len((x[2].get("drift") or {}).get("unaccepted", [])), -x[2]["scores"]["all"]["failed"], x[0]))
    for host, run, r in rows:
        sc, reg = r["scores"], len((r.get("drift") or {}).get("unaccepted", []))
        regcell = f'{status_html("FAIL")} {reg}' if reg else "0"
        w(f'<tr data-status="PASS"><td class="id">{e(host)}</td><td>{e(r["meta"].get("os", ""))}</td>'
          f'<td class="lv">{e(r["meta"].get("date_utc", "").replace("T", " ").replace("Z", ""))}</td>'
          f'<td class="n big">{fmt_pct(sc["L1"])}</td><td class="n">{fmt_pct(sc["L2"])}</td><td class="n">{sc["all"]["failed"]}</td>'
          f'<td class="n">{sc["all"]["accepted"]}</td><td class="n">{sc["all"]["manual"]}</td><td class="n">{regcell}</td>'
          f'<td><a href="{e(host)}/{e(run)}/report.html">open</a></td></tr>')
    w('</tbody></table></div></details></div></section>'
      '<footer><p>Generated by HardenProof (tools/report.py --fleet) from each host\'s latest results.json.</p></footer>'
      f'</div><div id="tip" role="tooltip"></div><script>{JS}</script></body></html>')
    return "".join(H), len(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fleet", metavar="REPORTS_DIR", help="write REPORTS_DIR/index.html across all hosts and exit")
    ap.add_argument("--current")
    ap.add_argument("--baseline")
    ap.add_argument("--catalogue", default=str(Path(__file__).resolve().parent.parent / "controls" / "catalogue.yml"))
    ap.add_argument("--out")
    ap.add_argument("--history", metavar="HOST_DIR", help="reports/<host>: adds the trend of all audits of this host")
    ap.add_argument("--previous", help="audit run to diff against for drift (default with --history: the run before --current)")
    ap.add_argument("--fail-on-regression", action="store_true",
                    help="exit 3 if a check that passed in the previous audit now fails and is not an accepted risk")
    ap.add_argument("--exceptions", help="accepted-risk register (inventory/<env>/exceptions.yml)")
    ap.add_argument("--host", help="inventory host name used to match host-scoped exceptions (default: directory name)")
    ap.add_argument("--md", action="store_true", help="also write summary.md")
    a = ap.parse_args()

    if a.fleet:
        html, n = render_fleet(a.fleet)
        (Path(a.fleet) / "index.html").write_text(html)
        print(f"wrote {Path(a.fleet) / 'index.html'} ({n} hosts)")
        return
    if not a.current or not a.out:
        ap.error("--current and --out are required (or use --fleet)")
    previous = a.previous
    if not previous and a.history:
        runs = run_dirs(a.history)
        names = [p.name for p in runs]
        cur_name = Path(a.current).resolve().name       # also when given as .../latest
        if cur_name in names and names.index(cur_name) > 0:
            previous = str(runs[names.index(cur_name) - 1])

    current = str(Path(a.current).resolve()) if Path(a.current).is_symlink() else a.current
    try:
        d = build(current, a.baseline, a.catalogue, a.exceptions, a.host, history=a.history, previous=previous)
    except InputError as err:
        sys.exit(f"error: {err}")
    except FileNotFoundError as err:
        sys.exit(f"error: {err.filename}: not found")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.html").write_text(render_html(d))
    (out / "results.json").write_text(json.dumps(
        dict(meta=d["meta"], scores=d["scores"], baseline_scores=d["bscores"], lynis=d["lyn"],
             delta=d["delta"], drift=d["drift"], stale_exceptions=d["stale"], checks=list(d["cur"].values())), indent=2))
    if a.md:
        (out / "summary.md").write_text(render_md(d))
    print(f"wrote {out / 'report.html'}")
    for k, s in d["scores"].items():
        print(f"  {k:4} pass={s['passed']:3} fail={s['failed']:3} accepted={s['accepted']:2} manual={s['manual']:2} na={s['na']:2} score={fmt_pct(s)}")
    if d["lyn"]:
        print(f"  lynis index={d['lyn'].get('hardening_index')} warnings={len(d['lyn']['warnings'])} suggestions={len(d['lyn']['suggestions'])}")
    if d["drift"] and d["drift"]["unaccepted"]:
        print(f"  REGRESSED since previous audit: {', '.join(d['drift']['unaccepted'])}")
        if a.fail_on_regression:
            sys.exit(3)


if __name__ == "__main__":
    main()
