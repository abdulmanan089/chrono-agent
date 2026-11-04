"""Local dashboard: render the audit trail, savepoints and branches of one
project as a self-contained HTML report (no server, no network, no tracking).

This is a single-project report, NOT the multi-team company dashboard from the
roadmap — that product needs a central server and accounts.
"""
import html
import json
import time
from collections import Counter


def _esc(value):
    return html.escape("" if value is None else str(value))


def render(store):
    st = store.state()
    snaps = store.list()
    recs = store.audit.read()
    actions = Counter(str(r.get("action", "?")) for r in recs)
    outcomes = Counter(str(r.get("outcome", "?")) for r in recs)
    risk = Counter(str(r.get("risk_level", "")) for r in recs if r.get("risk_level"))
    verify = store.audit.verify()
    anchors = store.verify_audit() if verify["ok"] else []

    rows = []
    for r in reversed(recs[-200:]):
        rows.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            % (_esc(r.get("seq")), _esc(r.get("ts")), _esc(r.get("actor")),
               _esc(r.get("agent") or r.get("model") or ""),
               _esc(r.get("action")), _esc(r.get("outcome")),
               _esc(r.get("detail") or r.get("command") or "")))
    snap_rows = []
    for m in reversed(snaps[-50:]):
        snap_rows.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td></tr>"
            % (_esc(m["id"]), _esc(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(m["time"]))),
               _esc(m["branch"]), _esc(m["message"]), len(m["files"])))
    branch_rows = "".join(
        "<tr><td>%s%s</td><td>%s</td></tr>"
        % (_esc(b), " (current)" if b == st["branch"] else "", _esc(h))
        for b, h in sorted(st["branches"].items()))

    def chips(counter):
        return " ".join("<span class=chip>%s: %d</span>" % (_esc(k), v)
                        for k, v in counter.most_common()) or "<span class=dim>none</span>"

    status = "CHAIN INTACT" if verify["ok"] and not anchors else "CHAIN BROKEN"
    status_cls = "ok" if verify["ok"] and not anchors else "bad"
    return """<!doctype html><html><head><meta charset=utf-8>
<title>ChronoAgent report</title><style>
body{{font-family:ui-monospace,Menlo,Consolas,monospace;background:#0d1117;color:#c9d1d9;margin:2em}}
h1{{color:#58a6ff}} h2{{color:#8b949e;border-bottom:1px solid #21262d;padding-bottom:.3em}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
td,th{{border:1px solid #21262d;padding:4px 8px;text-align:left}}
th{{color:#8b949e}} .chip{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:2px 10px;margin:2px;display:inline-block}}
.ok{{color:#3fb950}} .bad{{color:#f85149}} .dim{{color:#6e7681}}
</style></head><body>
<h1>ChronoAgent — project report</h1>
<p class=dim>Generated {gen} · root {root} · {nrec} audit records · {nsnap} savepoints</p>
<h2>Audit chain: <span class={status_cls}>{status}</span></h2>
<p>{reason} ({nrec} records){anchor_note}</p>
<h2>Actions</h2><p>{actions}</p>
<h2>Outcomes</h2><p>{outcomes}</p>
<h2>Risk levels seen</h2><p>{risk}</p>
<h2>Branches</h2><table><tr><th>branch</th><th>head savepoint</th></tr>{branches}</table>
<h2>Savepoints (newest {nsnap_shown})</h2><table><tr><th>id</th><th>time (UTC)</th><th>branch</th><th>message</th><th>files</th></tr>{snaps}</table>
<h2>Audit records (newest {nrec_shown})</h2><table><tr><th>#</th><th>time (UTC)</th><th>actor</th><th>agent/model</th><th>action</th><th>outcome</th><th>detail</th></tr>{rows}</table>
</body></html>""".format(
        gen=_esc(time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())),
        root=_esc(store.root), nrec=len(recs), nsnap=len(snaps),
        status_cls=status_cls, status=status,
        reason=_esc(verify["reason"]),
        anchor_note="" if not anchors else _esc(" — %d snapshot anchor(s) broken" % len(anchors)),
        actions=chips(actions), outcomes=chips(outcomes), risk=chips(risk),
        branches=branch_rows, snaps="".join(snap_rows), rows="".join(rows),
        nsnap_shown=min(len(snaps), 50), nrec_shown=min(len(recs), 200))


def write_report(store, out_path):
    from .snapshot import _atomic
    from pathlib import Path
    out = Path(out_path)
    _atomic(out, render(store).encode("utf-8"))
    return out
