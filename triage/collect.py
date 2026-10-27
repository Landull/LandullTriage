"""
Run a collection: python -m triage.collect --out <dir> [options], or through the app (--collect ...).

The GUI starts this in a separate (possibly elevated) process and follows progress.jsonl.
"""

import argparse
import json
import os
import sys
import traceback
import zipfile

from . import VERSION
from .core import (DEFAULT_CONFIG, Run, case_folder_name, host_info, human_size, iso, self_footprint,
                   utc_now, write_manifest)
from .modules import BY_ID, MODULES, available, collectors


def run_collection(config, case_dir=None):
    cfg = dict(DEFAULT_CONFIG)
    cfg.update(config or {})
    host = host_info()
    if not case_dir:
        out = cfg.get("output_dir") or os.getcwd()
        case_dir = os.path.join(out, case_folder_name(cfg.get("case_id"), host["hostname"]))
    os.makedirs(case_dir, exist_ok=True)
    run = Run(case_dir, cfg)
    wanted = [m["id"] for m in MODULES if m["id"] in (cfg.get("modules") or []) and available(m)]
    run.event("start", case_dir=case_dir, modules=wanted, version=VERSION, admin=host["admin"])
    run.module = "core"
    run.footprint("start", **self_footprint())
    case = {"tool": "LandullTriage", "version": VERSION, "case_id": cfg.get("case_id", ""),
            "examiner": cfg.get("examiner", ""), "notes": cfg.get("notes", ""), "host": host,
            "started_utc": iso(run.started), "finished_utc": None, "collector": self_footprint(), "modules": {}}
    _save_case(case_dir, case)

    funcs = collectors()
    for mid in wanted:
        if run.stopped():
            case["modules"][mid] = {"status": "skipped", "reason": "stopped by examiner"}
            continue
        run.module = mid
        m = BY_ID[mid]
        run.event("module_start", module=mid, title=m["title"])
        t0 = utc_now()
        try:
            res = funcs[mid](run) or {}
            status = res.pop("status", None) or ("partial" if run.notes.get(mid) else "ok")
        except Exception as e:  # one module failing never stops the rest
            res = {"error": f"{type(e).__name__}: {e}"}
            run.say(traceback.format_exc(limit=5), "error")
            run.notes.setdefault(mid, []).append(f"Module error: {type(e).__name__}: {e}")
            status = "failed"
        if run.stopped() and status == "ok":
            status = "partial"
        secs = (utc_now() - t0).total_seconds()
        case["modules"][mid] = {"status": status, "seconds": round(secs, 1), "result": res,
                                "notes": run.notes.get(mid, [])}
        run.event("module_end", module=mid, status=status, seconds=round(secs, 1))
        _save_case(case_dir, case)

    run.module = "core"
    case["finished_utc"] = iso()
    case["flags"] = sorted(run.flags, key=lambda f: {"high": 0, "medium": 1, "low": 2}.get(f["severity"], 3))
    case["stopped"] = run.stopped()
    _save_case(case_dir, case)
    run.event("stage", msg="Writing report")
    from .report import write_report
    try:
        write_report(case_dir, case)
    except Exception:
        run.say("Report failed: " + traceback.format_exc(limit=4), "error")
    run.event("stage", msg="Hashing every file into manifest.sha256")
    run.footprint("finish")
    run.close()  # closes progress.jsonl too; the remaining events go through a fresh handle

    def big(rel, size):
        _event(case_dir, "log", level="info", module="core", msg=f"hashing {rel} ({human_size(size)})")
    n = write_manifest(case_dir, run.hash_cache, big)
    zip_path = None
    if cfg.get("zip"):
        _event(case_dir, "stage", msg="Zipping the case folder")
        zip_path = _zip(case_dir)
    stop = os.path.join(case_dir, ".stop")
    if os.path.exists(stop):
        try:
            os.remove(stop)
        except OSError:
            pass
    _event(case_dir, "done", case_dir=case_dir, report=os.path.join(case_dir, "report.html"), files=n,
           flags=len(case["flags"]), zip=zip_path, stopped=case["stopped"])
    return case_dir


def _event(_dir, kind, **kw):
    kw.update({"t": kind, "ts": iso()})
    with open(os.path.join(_dir, "progress.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(kw, default=str) + "\n")


def _save_case(case_dir, case):
    tmp = os.path.join(case_dir, "case.json.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(case, fh, indent=2, default=str, ensure_ascii=False)
    os.replace(tmp, os.path.join(case_dir, "case.json"))


def _zip(case_dir):
    dest = case_dir.rstrip("/\\") + ".zip"
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as z:
        for dp, _, files in os.walk(case_dir):
            for f in files:
                p = os.path.join(dp, f)
                arc = os.path.join(os.path.basename(case_dir), os.path.relpath(p, case_dir))
                big = os.path.getsize(p) > 512 * 1024 * 1024 or f.endswith((".raw", ".lime", ".sys", ".zip", ".gz"))
                z.write(p, arc, compress_type=zipfile.ZIP_STORED if big else zipfile.ZIP_DEFLATED)
    return dest


def main(argv=None):
    ap = argparse.ArgumentParser(prog="LandullTriage --collect", description="Collect live-response evidence into a case folder.")
    ap.add_argument("--config", help="JSON config written by the app")
    ap.add_argument("--case-dir", help="exact case folder to write (the app creates it)")
    ap.add_argument("--out", help="parent folder for a new case folder")
    ap.add_argument("--modules", default="", help="comma list, or 'default' / 'all'. Available: " +
                    ", ".join(m["id"] for m in MODULES if available(m)))
    ap.add_argument("--case", default="", help="case number or name")
    ap.add_argument("--examiner", default="")
    ap.add_argument("--notes", default="")
    ap.add_argument("--log-days", type=int, default=7)
    ap.add_argument("--zip", action="store_true")
    a = ap.parse_args(argv)
    if a.config:
        with open(a.config, encoding="utf-8") as fh:
            cfg = json.load(fh)
    else:
        if a.modules in ("", "default"):
            mods = [m["id"] for m in MODULES if m["default"] and available(m)]
        elif a.modules == "all":
            mods = [m["id"] for m in MODULES if available(m)]
        else:
            mods = [x.strip() for x in a.modules.split(",") if x.strip()]
            bad = [x for x in mods if x not in BY_ID]
            if bad:
                ap.error("unknown module(s): " + ", ".join(bad))
        cfg = {"case_id": a.case, "examiner": a.examiner, "notes": a.notes, "output_dir": a.out or os.getcwd(),
               "modules": mods, "log_days": a.log_days, "zip": a.zip, "echo": True}
    case_dir = run_collection(cfg, a.case_dir)
    print(case_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
