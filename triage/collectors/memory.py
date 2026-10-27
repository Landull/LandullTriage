"""RAM capture: WinPmem on Windows, AVML on Linux. macOS can't be captured by a free tool."""

import os
import platform
import shutil
import socket
import subprocess
import sys
import time

from ..core import PLATFORM, human_size, is_admin, iso, no_window_flags, safe_name, sha256_file, total_ram, utc_now

MAC_EXPLAIN = ("Full RAM capture isn't available on modern macOS: Apple's kernel protections block the access "
               "it needs. LandullTriage collects the live state instead (processes, network, persistence, logs).")


def base_dir():
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def find_tool(name):
    """Bundled acquisition tool in assets/bin, or one next to the app, or on PATH."""
    names = {"winpmem": ["winpmem.exe", "winpmem_mini_x64.exe"], "avml": ["avml"]}[name]
    dirs = [os.path.join(base_dir(), "assets", "bin"), os.path.dirname(sys.executable), os.getcwd()]
    for d in dirs:
        for n in names:
            p = os.path.join(d, n)
            if os.path.isfile(p):
                return p
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def availability():
    """(available, reason) for the GUI."""
    if PLATFORM == "macos":
        return False, MAC_EXPLAIN
    if PLATFORM == "windows":
        if platform.machine().lower() in ("arm64", "aarch64"):
            return False, "WinPmem doesn't support Windows on ARM."
        if not find_tool("winpmem"):
            return False, "WinPmem isn't bundled with this build (assets/bin/winpmem.exe)."
    if PLATFORM == "linux":
        if platform.machine().lower() not in ("x86_64", "amd64"):
            return False, "The bundled AVML build is x86-64 only."
        if not find_tool("avml"):
            return False, "AVML isn't bundled with this build (assets/bin/avml)."
    return True, ""


def collect(run):
    ok, why = availability()
    if not ok:
        run.note(why)
        return {"status": "skipped", "reason": why}
    if not is_admin():
        msg = "RAM capture needs administrator (Windows) or root (Linux) rights. Run elevated to capture memory."
        run.note(msg)
        return {"status": "skipped", "reason": msg}

    ram = total_ram()
    free = shutil.disk_usage(run.case_dir).free
    need = int(ram * 1.05) + 256 * 1024 * 1024
    if ram and free < need:
        msg = (f"Not enough free space for a RAM image: {human_size(ram)} of RAM needs about {human_size(need)}, "
               f"but the output drive has {human_size(free)} free.")
        run.note(msg)
        return {"status": "failed", "reason": msg}

    host = safe_name(socket.gethostname(), 40)
    if PLATFORM == "windows":
        tool = find_tool("winpmem")
        dest = run.path("memory", f"{host}_memory.raw")
        cmd = [tool, dest]
        fmt = "raw"
    else:
        tool = find_tool("avml")
        dest = run.path("memory", f"{host}_memory.lime")
        try:
            helptext = subprocess.run([tool, "--help"], capture_output=True, text=True, timeout=20).stdout
        except Exception:
            helptext = ""
        cmd = [tool, "acquire", dest] if "acquire" in helptext else [tool, dest]
        fmt = "lime"

    try:
        tool_hash = sha256_file(tool)
    except OSError:
        tool_hash = ""
    log_path = run.path("memory", "acquisition_log.txt")
    run.say(f"Capturing {human_size(ram)} of RAM with {os.path.basename(tool)} to {run.rel(dest)}")
    t0 = utc_now()
    with open(log_path, "wb") as logfh:
        proc = subprocess.Popen(cmd, stdout=logfh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                creationflags=no_window_flags())
        last = -1
        while proc.poll() is None:
            if run.stopped():
                proc.terminate()
                try:
                    proc.wait(10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                run.note("RAM capture was stopped before it finished; the partial image was kept and marked.")
                break
            try:
                size = os.path.getsize(dest)
            except OSError:
                size = 0
            if size != last:
                run.event("progress", module="memory", done=size, total=ram)
                last = size
            time.sleep(0.5)
        rc = proc.wait()
    t1 = utc_now()
    run.footprint("exec", cmd=" ".join(cmd), start=iso(t0), end=iso(t1), rc=rc, tool_sha256=tool_hash,
                  output=run.rel(dest))
    size = os.path.getsize(dest) if os.path.exists(dest) else 0
    run.event("progress", module="memory", done=size, total=size or ram)
    info = {"tool": os.path.basename(tool), "tool_sha256": tool_hash, "command": cmd, "format": fmt,
            "start_utc": iso(t0), "end_utc": iso(t1), "exit_code": rc, "image": run.rel(dest) if size else None,
            "image_bytes": size, "physical_ram_bytes": ram, "stopped": run.stopped()}
    if size:
        run.say("Hashing the memory image...")
        info["image_sha256"] = sha256_file(dest)
        run.hash_cache[os.path.abspath(dest)] = (size, os.path.getmtime(dest), info["image_sha256"])
    run.write_json("memory_info.json", info)
    if rc != 0 or not size:
        tail = ""
        try:
            with open(log_path, "rb") as fh:
                lines = fh.read()[-4000:].decode("utf-8", "replace").strip().splitlines()
                tail = " | ".join(x.strip() for x in lines[-6:] if x.strip())
        except OSError:
            pass
        hint = ""
        if PLATFORM == "windows":
            hint = (" If Memory Integrity (HVCI) or an EDR blocked WinPmem's driver, try again with an exclusion "
                    "or capture with another tool.")
        else:
            hint = " Kernel lockdown (Secure Boot) can block /proc/kcore and /dev/crash."
        run.note(f"RAM capture failed (exit code {rc}).{hint} Tool output: {tail[-400:]}")
        return {"status": "failed" if not size else "partial", **info}
    run.say(f"RAM image complete: {human_size(size)}")
    return {"status": "partial" if run.stopped() else "ok", **info}
