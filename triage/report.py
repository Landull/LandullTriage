"""Self-contained HTML summary of a case (opens in any browser, prints cleanly)."""

import html
import os

from .core import human_size
from .modules import BY_ID

SEV_ORDER = {"high": 0, "medium": 1, "low": 2}
STATUS_LABEL = {"ok": "Collected", "partial": "Partial", "failed": "Failed", "skipped": "Skipped"}

CSS = """
:root{--bg:#141414;--panel:#1a1a1a;--line:#2a2a2a;--text:#e6e3dd;--muted:#9a968f;--dim:#6b6862;
--red:#e06a6a;--amber:#e0b25a;--green:#86c98a;--blue:#7fa7d9}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:32px 20px 60px}
header{display:flex;gap:18px;align-items:center;border-bottom:1px solid var(--line);padding-bottom:20px}
header .mark{font-weight:800;letter-spacing:5px;font-size:13px;color:var(--muted)}
h1{margin:2px 0 0;font-size:26px;letter-spacing:.5px}
h2{font-size:12px;letter-spacing:2.5px;text-transform:uppercase;color:var(--muted);margin:36px 0 12px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px 24px;margin-top:18px}
.meta div{font-size:13px}.meta b{display:block;color:var(--dim);font-weight:600;font-size:11px;letter-spacing:1px;text-transform:uppercase}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .n{font-size:26px;font-weight:800;font-variant-numeric:tabular-nums}.card .l{color:var(--muted);font-size:12px}
.card.high .n{color:var(--red)}.card.medium .n{color:var(--amber)}.card.low .n{color:var(--blue)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--dim);font-weight:700;background:#171717}
tr:last-child td{border-bottom:none}td.mono,.mono{font-family:Menlo,Consolas,"DejaVu Sans Mono",monospace;font-size:12px;word-break:break-all}
.sev{display:inline-block;border-radius:9px;padding:1px 9px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px}
.sev.high{background:rgba(224,106,106,.14);color:var(--red);border:1px solid rgba(224,106,106,.4)}
.sev.medium{background:rgba(224,178,90,.12);color:var(--amber);border:1px solid rgba(224,178,90,.4)}
.sev.low{background:rgba(127,167,217,.12);color:var(--blue);border:1px solid rgba(127,167,217,.4)}
.st{font-weight:700}.st.ok{color:var(--green)}.st.partial{color:var(--amber)}.st.failed{color:var(--red)}.st.skipped{color:var(--dim)}
.notes{color:var(--muted);font-size:12px;margin:4px 0 0;padding-left:16px}
.muted{color:var(--muted)}.empty{padding:16px;color:var(--muted);background:var(--panel);border:1px dashed var(--line);border-radius:10px}
a{color:var(--text)}details{margin-top:6px}summary{cursor:pointer;color:var(--muted)}
footer{margin-top:40px;color:var(--dim);font-size:12px;border-top:1px solid var(--line);padding-top:14px}
@media print{:root{--bg:#fff;--panel:#fff;--line:#ccc;--text:#111;--muted:#444;--dim:#666}th{background:#f2f2f2}
details{display:block}details>*{display:block}}
"""


def _e(x):
    return html.escape("" if x is None else str(x))


def _files(case_dir, mid):
    root = os.path.join(case_dir, mid)
    out = []
    for dp, _, fn in os.walk(root):
        for f in fn:
            p = os.path.join(dp, f)
            try:
                out.append((os.path.relpath(p, case_dir).replace("\\", "/"), os.path.getsize(p)))
            except OSError:
                pass
    return sorted(out)


def _result_line(res):
    if not isinstance(res, dict):
        return ""
    bits = []
    for k, v in res.items():
        if k in ("command", "tool_sha256", "image_sha256", "profiles", "error", "reason", "stopped", "format",
                 "start_utc", "end_utc", "exit_code", "physical_ram_bytes", "image", "tool"):
            continue
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            label = k.replace("_", " ")
            bits.append(f"{human_size(v) if 'bytes' in k else v} {label.replace(' bytes', '')}")
    if res.get("image_sha256"):
        bits.append(f"SHA-256 {res['image_sha256'][:16]}…")
    if res.get("error"):
        bits.append(res["error"])
    return ", ".join(bits)


def write_report(case_dir, case):
    host = case.get("host", {})
    flags = case.get("flags") or []
    counts = {s: sum(1 for f in flags if f["severity"] == s) for s in ("high", "medium", "low")}
    mods = case.get("modules", {})
    total_bytes = 0
    file_count = 0
    for dp, _, fn in os.walk(case_dir):
        for f in fn:
            try:
                total_bytes += os.path.getsize(os.path.join(dp, f))
                file_count += 1
            except OSError:
                pass
    title = case.get("case_id") or host.get("hostname") or "Triage"
    h = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
         f"<title>LandullTriage – {_e(title)}</title><style>{CSS}</style></head><body><div class='wrap'>"]
    h.append("<header><div><div class='mark'>LANDULL TRIAGE</div>"
             f"<h1>{_e(host.get('hostname'))}{(' · ' + _e(case.get('case_id'))) if case.get('case_id') else ''}</h1></div></header>")
    meta = [("Case", case.get("case_id") or "—"), ("Examiner", case.get("examiner") or "—"),
            ("Started (UTC)", case.get("started_utc")), ("Finished (UTC)", case.get("finished_utc")),
            ("Operating system", host.get("os")), ("Local time at start", host.get("local_time")),
            ("RAM", human_size(host.get("ram_bytes"))), ("Collected as", ("administrator/root" if host.get("admin") else "standard user")),
            ("Tool", f"LandullTriage {case.get('version')}"), ("FQDN", host.get("fqdn") or "—")]
    h.append("<div class='meta'>" + "".join(f"<div><b>{_e(k)}</b>{_e(v)}</div>" for k, v in meta) + "</div>")
    if case.get("notes"):
        h.append(f"<p class='muted' style='margin-top:14px'><b>Notes:</b> {_e(case['notes'])}</p>")
    if case.get("stopped"):
        h.append("<p class='sev medium' style='margin-top:14px;padding:6px 12px'>Collection was stopped early by the examiner.</p>")

    h.append("<h2>Summary</h2><div class='cards'>")
    h.append(f"<div class='card high'><div class='n'>{counts['high']}</div><div class='l'>High findings</div></div>")
    h.append(f"<div class='card medium'><div class='n'>{counts['medium']}</div><div class='l'>Medium findings</div></div>")
    h.append(f"<div class='card low'><div class='n'>{counts['low']}</div><div class='l'>Low findings</div></div>")
    okc = sum(1 for m in mods.values() if m.get("status") == "ok")
    h.append(f"<div class='card'><div class='n'>{okc}/{len(mods)}</div><div class='l'>Modules fully collected</div></div>")
    h.append(f"<div class='card'><div class='n'>{file_count}</div><div class='l'>Files · {human_size(total_bytes)}</div></div></div>")

    h.append("<h2>Findings to review</h2>")
    if flags:
        h.append("<p class='muted'>Automatic leads, not verdicts: each one is a reason to look closer. "
                 "Details are in the module folders.</p>")
        h.append("<table><tr><th style='width:90px'>Severity</th><th style='width:110px'>Module</th><th>Finding</th></tr>")
        for f in flags:
            detail = f"<div class='mono muted'>{_e(f['detail'])}</div>" if f.get("detail") else ""
            h.append(f"<tr><td><span class='sev {f['severity']}'>{_e(f['severity'])}</span></td>"
                     f"<td>{_e(BY_ID.get(f['module'], {}).get('title', f['module']))}</td>"
                     f"<td>{_e(f['what'])}{detail}</td></tr>")
        h.append("</table>")
    else:
        h.append("<div class='empty'>No automatic findings. That isn't proof the system is clean; review the collected data.</div>")

    h.append("<h2>Modules</h2><table><tr><th>Module</th><th style='width:100px'>Status</th><th style='width:80px'>Time</th><th>Collected</th></tr>")
    for mid, m in mods.items():
        st = m.get("status", "")
        notes = m.get("notes") or []
        res = m.get("result") or {}
        files = _files(case_dir, mid)
        note_html = ("<ul class='notes'>" + "".join(f"<li>{_e(n)}</li>" for n in notes) + "</ul>") if notes else ""
        if m.get("reason") and not notes:
            note_html = f"<ul class='notes'><li>{_e(m['reason'])}</li></ul>"
        file_html = ""
        if files:
            rows = "".join(f"<div class='mono'><a href='{_e(r)}'>{_e(r)}</a> <span class='muted'>{human_size(s)}</span></div>"
                           for r, s in files[:400])
            more = f"<div class='muted'>…and {len(files) - 400} more</div>" if len(files) > 400 else ""
            file_html = f"<details><summary>{len(files)} file(s)</summary>{rows}{more}</details>"
        h.append(f"<tr><td><b>{_e(BY_ID.get(mid, {}).get('title', mid))}</b>{note_html}</td>"
                 f"<td><span class='st {st}'>{_e(STATUS_LABEL.get(st, st))}</span></td>"
                 f"<td>{_e(m.get('seconds', ''))}s</td><td>{_e(_result_line(res))}{file_html}</td></tr>")
    h.append("</table>")

    h.append("<h2>Integrity</h2><table>")
    h.append("<tr><td style='width:220px'><a href='manifest.sha256'>manifest.sha256</a></td><td>SHA-256 of every file in this case. "
             "Verify later with <span class='mono'>sha256sum -c manifest.sha256</span> (Linux) or "
             "<span class='mono'>shasum -a 256 -c manifest.sha256</span> (macOS).</td></tr>")
    h.append("<tr><td><a href='footprint.jsonl'>footprint.jsonl</a></td><td>Every command LandullTriage ran and every file it copied, "
             "with timestamps, so its own activity can be told apart from anything else on the system.</td></tr>")
    h.append("<tr><td><a href='copied_files.csv'>copied_files.csv</a></td><td>Original path, timestamps, copy method (normal, raw NTFS, "
             "shadow copy) and SHA-256 of each copied file.</td></tr>")
    h.append("<tr><td><a href='case.json'>case.json</a></td><td>Machine-readable case details and module results.</td></tr></table>")
    collector = case.get("collector", {})
    h.append(f"<footer>Collected by {_e(collector.get('user'))} with LandullTriage {_e(case.get('version'))} "
             f"(pid {_e(collector.get('pid'))}, {_e(collector.get('executable'))}"
             f"{', SHA-256 ' + _e(collector.get('executable_sha256', '')[:16]) + '…' if collector.get('executable_sha256') else ''}). "
             "Times are UTC unless marked local.</footer></div></body></html>")
    with open(os.path.join(case_dir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write("".join(h))
