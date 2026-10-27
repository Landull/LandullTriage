"""
Memory analysis with Volatility 3: run a set of core plugins against an image and save each as CSV.

    LandullTriage --analyze <image> --out <folder> [--os windows|linux|mac] [--plugins a,b] [--symbols DIR] [--offline]

Every plugin runs in its own process (the app re-launched with --vol ...), so one plugin crashing
or running out of memory never takes the rest down. Progress is printed as JSON lines.
"""

import argparse
import json
import os
import subprocess
import sys
import time

from .core import iso, no_window_flags, sha256_file

PLUGINS = {
    "windows": [
        ("windows.info", "Image and OS details", True),
        ("windows.pslist", "Process list (active list)", True),
        ("windows.pstree", "Process tree", True),
        ("windows.psscan", "Process scan (finds hidden and exited processes)", True),
        ("windows.cmdline", "Process command lines", True),
        ("windows.netscan", "Network connections and listeners", True),
        ("windows.malware.malfind|windows.malfind", "Injected code (malfind)", True),
        ("windows.svcscan", "Services", True),
        ("windows.malware.psxview|windows.psxview", "Cross-view hidden process check", False),
        ("windows.dlllist", "Loaded DLLs (large)", False),
        ("windows.registry.hivelist", "Registry hives in memory", False),
        ("windows.filescan", "File objects (large)", False),
        ("windows.handles", "Open handles (very large)", False),
    ],
    "linux": [
        ("linux.pslist", "Process list", True),
        ("linux.pstree", "Process tree", True),
        ("linux.psaux", "Process arguments", True),
        ("linux.bash", "Bash history in memory", True),
        ("linux.sockstat", "Network sockets", True),
        ("linux.lsmod", "Kernel modules", True),
        ("linux.malware.malfind|linux.malfind", "Injected code (malfind)", True),
        ("linux.malware.check_syscall|linux.check_syscall", "Syscall table hooks", False),
    ],
    "mac": [
        ("mac.pslist", "Process list", True),
        ("mac.pstree", "Process tree", True),
        ("mac.psaux", "Process arguments", True),
        ("mac.bash", "Bash history in memory", True),
        ("mac.netstat", "Network connections", True),
        ("mac.lsmod", "Kernel extensions", True),
        ("mac.malfind", "Injected code (malfind)", True),
    ],
}

SYMBOL_NOTE = {
    "windows": "Windows symbols are downloaded automatically from Microsoft the first time (internet needed), then cached.",
    "linux": "Linux images need a symbol table (ISF) built for that exact kernel; put it in a folder and choose it under Symbols.",
    "mac": "macOS images need a symbol table (ISF) built for that exact kernel; put it in a folder and choose it under Symbols.",
}


def guess_os(path):
    name = os.path.basename(path).lower()
    if name.endswith((".lime", ".lime.compressed")):
        return "linux"
    if name.endswith((".raw", ".mem", ".dmp", ".vmem", ".aff4", ".sys", ".bin")):
        return "windows"
    return "windows"


def available_plugins():
    """Names of the plugins in this Volatility build (used to pick between renamed plugins)."""
    try:
        from volatility3 import framework
        import volatility3.plugins
        framework.import_files(volatility3.plugins, True)
        keys = set(framework.list_plugins().keys())
        return keys | {k.rsplit(".", 1)[0] for k in keys}
    except Exception:
        return set()


def resolve(names, have):
    opts = names.split("|")
    if not have:
        return opts[0]
    for o in opts:
        if o in have:
            return o
    return None


def vol_command(args):
    if getattr(sys, "frozen", False):
        return [sys.executable, "--vol"] + args
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return [sys.executable, os.path.join(root, "landull_triage.py"), "--vol"] + args


def emit(**kw):
    kw["ts"] = iso()
    print(json.dumps(kw, default=str), flush=True)


def run_analysis(image, out, os_name=None, plugins=None, symbols=None, offline=False, hash_image=True):
    os_name = os_name or guess_os(image)
    os.makedirs(out, exist_ok=True)
    have = available_plugins()
    chosen = plugins or [p for p, _, d in PLUGINS[os_name] if d]
    emit(t="start", image=image, out=out, os=os_name, plugins=chosen, volatility=_vol_version())
    summary = {"image": image, "os": os_name, "started_utc": iso(), "plugins": {}}
    if hash_image:
        emit(t="log", msg="Hashing the image (so the analysis can be tied to the exact file)")
        try:
            summary["image_sha256"] = sha256_file(image)
        except OSError as e:
            summary["image_sha256"] = f"error: {e}"
    stop_file = os.path.join(out, ".stop")
    for i, spec in enumerate(chosen):
        if os.path.exists(stop_file):
            emit(t="plugin_end", plugin=spec.split("|")[0], status="skipped", index=i, total=len(chosen))
            continue
        name = resolve(spec, have)
        if not name:
            emit(t="plugin_end", plugin=spec, status="missing", index=i, total=len(chosen))
            continue
        dest = os.path.join(out, name + ".csv")
        errf = os.path.join(out, name + ".log")
        args = ["-q", "-r", "csv", "-f", image]
        if symbols:
            args += ["-s", symbols]
        if offline:
            args += ["--offline"]
        args.append(name)
        emit(t="plugin_start", plugin=name, index=i, total=len(chosen))
        t0 = time.time()
        stopped = False
        with open(dest, "wb") as so, open(errf, "wb") as se:
            p = subprocess.Popen(vol_command(args), stdout=so, stderr=se, stdin=subprocess.DEVNULL,
                                 creationflags=no_window_flags())
            while p.poll() is None:
                if os.path.exists(stop_file):
                    p.terminate()
                    try:
                        p.wait(10)
                    except subprocess.TimeoutExpired:
                        p.kill()
                    stopped = True
                    break
                time.sleep(0.3)
            rc = p.wait()
        secs = round(time.time() - t0, 1)
        rows = 0
        try:
            with open(dest, "rb") as fh:
                rows = max(0, sum(1 for _ in fh) - 1)
        except OSError:
            pass
        err_tail = ""
        try:
            with open(errf, "rb") as fh:
                err_tail = fh.read()[-1500:].decode("utf-8", "replace").strip()
        except OSError:
            pass
        status = "ok" if rc == 0 else "failed"
        friendly = ""
        if rc != 0:   # on failure Volatility writes its diagnostics to stdout: keep them in the .log, not a .csv
            try:
                with open(dest, "rb") as fh, open(errf, "ab") as lf:
                    extra = fh.read()
                    lf.write(b"\n" + extra)
                os.remove(dest)
                err_tail = (err_tail + "\n" + extra[-1500:].decode("utf-8", "replace")).strip()
            except OSError:
                pass
            rows = 0
            if "Unable to validate the plugin requirements" in err_tail:
                hint = {"windows": "Volatility couldn't find a Windows kernel in this image. Check the System choice, that the "
                                   "image isn't compressed (hiberfil/AVML-compressed), and that symbols can download (not offline).",
                        "linux": "No symbol table matches this Linux kernel. Build one with dwarf2json for this exact kernel "
                                 "and choose its folder under Symbols.",
                        "mac": "No symbol table matches this macOS kernel. Build one with dwarf2json and choose its folder "
                               "under Symbols."}[os_name]
                friendly = hint
        if stopped:
            status = "failed"
            friendly = "stopped by examiner"
        summary["plugins"][name] = {"status": status, "rows": rows, "seconds": secs, "exit_code": rc,
                                    "error": (friendly + "\n" if friendly else "") + (err_tail[-500:] if rc else "")}
        emit(t="plugin_end", plugin=name, status=status, rows=rows, seconds=secs, index=i, total=len(chosen),
             error=friendly or (err_tail[-400:] if rc else ""))
        if rc == 0 and os.path.exists(errf) and os.path.getsize(errf) == 0:
            os.remove(errf)
    summary["finished_utc"] = iso()
    summary["stopped"] = os.path.exists(stop_file)
    if summary["stopped"]:
        os.remove(stop_file)
    with open(os.path.join(out, "analysis.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    emit(t="done", out=out)
    return summary


def _vol_version():
    try:
        from volatility3.framework import constants
        return constants.PACKAGE_VERSION
    except Exception:
        return None


def vol_main(argv):
    """Entry for --vol: hand the arguments to Volatility 3's own command line."""
    from volatility3 import cli
    sys.argv = ["vol"] + list(argv)
    try:
        cli.main()
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="LandullTriage --analyze", description="Run core Volatility 3 plugins on a memory image.")
    ap.add_argument("image")
    ap.add_argument("--out", required=True)
    ap.add_argument("--os", choices=["windows", "linux", "mac"])
    ap.add_argument("--plugins", default="", help="comma list of plugin names (default: the core set)")
    ap.add_argument("--symbols", help="folder with symbol tables (ISF)")
    ap.add_argument("--offline", action="store_true", help="don't download symbols")
    ap.add_argument("--no-hash", action="store_true")
    a = ap.parse_args(argv)
    plugins = [x.strip() for x in a.plugins.split(",") if x.strip()] or None
    run_analysis(a.image, a.out, a.os, plugins, a.symbols, a.offline, not a.no_hash)
    return 0
