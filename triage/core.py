"""
Core of a triage run: the case folder, progress events, the command runner that
records LandullTriage's own footprint, file copying with hashing, and the final
SHA-256 manifest.

A run is driven by a config dict (see DEFAULT_CONFIG) and writes everything into
one case folder:

    <case>/
      case.json              case details, host, examiner, times, module results
      progress.jsonl         live progress events (the GUI tails this file)
      footprint.jsonl        every command LandullTriage ran, with times and exit codes
      copied_files.csv       source path, timestamps and hash of every file copied
      <module>/...           collected data
      report.html            human readable summary
      manifest.sha256        SHA-256 of every file in the case (sha256sum -c compatible)
"""

import csv
import datetime as _dt
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import traceback

from . import VERSION

PLATFORM = "windows" if sys.platform.startswith("win") else "macos" if sys.platform == "darwin" else "linux"
STOP_FILE = ".stop"


# ------------------------------------------------------------------ small helpers
def utc_now():
    return _dt.datetime.now(_dt.timezone.utc)


def iso(ts=None):
    """ISO-8601 UTC string for a datetime or a POSIX timestamp."""
    if ts is None:
        d = utc_now()
    elif isinstance(ts, (int, float)):
        try:
            d = _dt.datetime.fromtimestamp(ts, _dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return ""
    else:
        d = ts
    return d.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def sha256_file(path, chunk=4 * 1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def safe_name(text, maxlen=80):
    keep = "".join(c if c.isalnum() or c in "-_.@" else "_" for c in str(text))
    keep = keep.strip("._") or "item"
    return keep[:maxlen]


def is_admin():
    if PLATFORM == "windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def human_size(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def total_ram():
    """Physical memory in bytes (0 if unknown)."""
    try:
        if PLATFORM == "windows":
            import ctypes

            class MEMSTAT(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            st = MEMSTAT()
            st.dwLength = ctypes.sizeof(MEMSTAT)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st))
            return int(st.ullTotalPhys)
        if PLATFORM == "linux":
            with open("/proc/meminfo") as fh:
                for line in fh:
                    if line.startswith("MemTotal:"):
                        return int(line.split()[1]) * 1024
        if PLATFORM == "macos":
            out = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, timeout=10)
            return int(out.stdout.strip())
    except Exception:
        pass
    return 0


def system_drive():
    if PLATFORM == "windows":
        return os.environ.get("SystemDrive", "C:") + "\\"
    return "/"


def same_volume(a, b):
    """True when two paths live on the same volume (used to warn about writing evidence to the system disk)."""
    try:
        if PLATFORM == "windows":
            return os.path.splitdrive(os.path.abspath(a))[0].upper() == os.path.splitdrive(os.path.abspath(b))[0].upper()
        return os.stat(a).st_dev == os.stat(b).st_dev
    except OSError:
        return False


def no_window_flags():
    return 0x08000000 if PLATFORM == "windows" else 0  # CREATE_NO_WINDOW


def host_info():
    info = {
        "hostname": socket.gethostname(),
        "fqdn": "",
        "os": platform.platform(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "platform": PLATFORM,
        "python": platform.python_version(),
        "local_time": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "utc_time": iso(),
        "timezone": time.strftime("%Z"),
        "utc_offset": _dt.datetime.now().astimezone().strftime("%z"),
        "ram_bytes": total_ram(),
        "admin": is_admin(),
    }
    try:
        info["fqdn"] = socket.getfqdn()
    except Exception:
        pass
    return info


DEFAULT_CONFIG = {
    "case_id": "",
    "examiner": "",
    "notes": "",
    "output_dir": "",
    "modules": [],          # module ids, run in the order of triage.modules.MODULES
    "log_days": 7,          # how far back to export logs where the OS supports a range
    "zip": False,
}


# ------------------------------------------------------------------ the run context
class Run:
    """Everything a collector needs: where to write, how to run commands, how to report progress."""

    def __init__(self, case_dir, config):
        self.case_dir = os.path.abspath(case_dir)
        self.config = config
        self.module = "core"
        self.started = utc_now()
        os.makedirs(self.case_dir, exist_ok=True)
        self._progress = open(os.path.join(self.case_dir, "progress.jsonl"), "a", encoding="utf-8")
        self._footprint = open(os.path.join(self.case_dir, "footprint.jsonl"), "a", encoding="utf-8")
        self._copied_path = os.path.join(self.case_dir, "copied_files.csv")
        new = not os.path.exists(self._copied_path)
        self._copied_fh = open(self._copied_path, "a", newline="", encoding="utf-8")
        self._copied = csv.writer(self._copied_fh)
        if new:
            self._copied.writerow(["module", "source", "destination", "size", "modified_utc", "accessed_utc",
                                   "changed_or_created_utc", "method", "sha256"])
        self.notes = {}      # module id -> list of notes for the report
        self.flags = []      # findings worth a look: dicts with module, severity, what, detail
        self._vss_failures = 0
        self.hash_cache = {} # abs path -> (size, mtime, sha256) so big files are hashed once

    # --- progress -------------------------------------------------------
    def event(self, kind, **kw):
        kw.update({"t": kind, "ts": iso()})
        try:
            self._progress.write(json.dumps(kw, default=str) + "\n")
            self._progress.flush()
        except Exception:
            pass
        if self.config.get("echo"):
            if kind == "log":
                print(f"[{kw.get('module')}] {kw.get('msg')}", flush=True)
            elif kind == "module_start":
                print(f"== {kw.get('title')}", flush=True)
            elif kind == "module_end":
                print(f"   {kw.get('module')}: {kw.get('status')} ({kw.get('seconds')}s)", flush=True)

    def say(self, msg, level="info"):
        self.event("log", level=level, module=self.module, msg=str(msg))

    def note(self, msg):
        """A note that ends up in the report under this module (limitations, skipped items)."""
        self.notes.setdefault(self.module, []).append(str(msg))
        self.say(msg, "warn")

    def flag(self, what, detail="", severity="medium"):
        self.flags.append({"module": self.module, "severity": severity, "what": what, "detail": detail})

    def stopped(self):
        return os.path.exists(os.path.join(self.case_dir, STOP_FILE))

    # --- paths ----------------------------------------------------------
    def path(self, *parts):
        p = os.path.join(self.case_dir, *parts)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    def rel(self, p):
        return os.path.relpath(p, self.case_dir).replace("\\", "/")

    # --- footprint ------------------------------------------------------
    def footprint(self, action, **kw):
        kw.update({"ts": iso(), "module": self.module, "action": action})
        try:
            self._footprint.write(json.dumps(kw, default=str) + "\n")
            self._footprint.flush()
        except Exception:
            pass

    # --- running commands ----------------------------------------------
    def run(self, cmd, out=None, timeout=300, shell=False, text=True, env=None, quiet=False, input_data=None):
        """
        Run a command and record it in footprint.jsonl. When `out` is a relative path, stdout
        (and stderr, if any) is saved there inside the case. Returns (rc, stdout, stderr).
        rc is None when the program is missing or timed out.
        """
        shown = cmd if isinstance(cmd, str) else " ".join(str(c) for c in cmd)
        if not quiet:
            self.say(f"$ {shown}")
        t0 = utc_now()
        rc, so, se, err = None, "" if text else b"", "" if text else b"", ""
        try:
            rc, so, se, err = _run_bounded(cmd, timeout, shell, env, input_data, self.stopped)
            if text:
                so = _decode(so)
                se = _decode(se)
        except FileNotFoundError:
            err = "program not found"
        except Exception as e:  # noqa
            err = f"{type(e).__name__}: {e}"
        t1 = utc_now()
        saved = None
        if out and (so or se):
            dest = self.path(self.module_dir(), out)
            mode = "w" if text else "wb"
            with open(dest, mode, **({"encoding": "utf-8", "errors": "replace"} if text else {})) as fh:
                fh.write(so)
                if se and se.strip():
                    if text:
                        fh.write("\n\n----- stderr -----\n" + se)
            saved = self.rel(dest)
        self.footprint("exec", cmd=shown, start=iso(t0), end=iso(t1), rc=rc, error=err or None, output=saved)
        if err and not quiet:
            self.say(f"  {err}", "warn")
        return rc, so, se

    def ps(self, script, out=None, timeout=300, quiet=False):
        """Run a PowerShell script block (Windows)."""
        cmd = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
               "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; " + script]
        return self.run(cmd, out=out, timeout=timeout, quiet=quiet)

    def module_dir(self):
        return self.module

    # --- writing files --------------------------------------------------
    def write_text(self, name, text):
        dest = self.path(self.module_dir(), name)
        with open(dest, "w", encoding="utf-8", errors="replace", newline="") as fh:
            fh.write(text)
        return dest

    def write_json(self, name, obj):
        dest = self.path(self.module_dir(), name)
        with open(dest, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, default=str, ensure_ascii=False)
        return dest

    def write_csv(self, name, rows, fields=None):
        rows = list(rows)
        if fields is None:
            fields = []
            for r in rows:
                for k in r:
                    if k not in fields:
                        fields.append(k)
        dest = self.path(self.module_dir(), name)
        with open(dest, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.DictWriter(fh, fieldnames=fields or ["empty"], extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow({k: _cell(v) for k, v in r.items()})
        return dest

    # --- copying files --------------------------------------------------
    def copy(self, src, dest_rel=None, raw_ok=True):
        """
        Copy one file into the case, keeping a record of its original timestamps and hash.
        On Windows, locked files fall back to reading straight off the NTFS volume, then to
        a shadow-copy read with esentutl. Returns the destination path or None.
        """
        try:
            st = os.stat(src)
        except OSError as e:
            self.say(f"  can't read {src}: {e.strerror or e}", "warn")
            return None
        if dest_rel is None:
            dest_rel = _mirror_path(src)
        dest = self.path(self.module_dir(), dest_rel)
        method = "copy"
        ok = False
        try:
            shutil.copyfile(src, dest)
            ok = True
        except (PermissionError, OSError) as e:
            if PLATFORM == "windows" and raw_ok:
                ok, method = self._copy_locked(src, dest)
            if not ok:
                self.say(f"  can't copy {src}: {getattr(e, 'strerror', None) or e}", "warn")
        if not ok:
            try:
                if os.path.exists(dest) and os.path.getsize(dest) == 0:
                    os.remove(dest)
            except OSError:
                pass
            return None
        digest = sha256_file(dest)
        try:
            self.hash_cache[os.path.abspath(dest)] = (os.path.getsize(dest), os.path.getmtime(dest), digest)
        except OSError:
            pass
        btime = getattr(st, "st_birthtime", None)
        self._copied.writerow([self.module, src, self.rel(dest), st.st_size, iso(st.st_mtime), iso(st.st_atime),
                               iso(btime if btime else st.st_ctime), method, digest])
        self._copied_fh.flush()
        self.footprint("copy", source=src, dest=self.rel(dest), method=method)
        return dest

    def _copy_locked(self, src, dest):
        try:
            from .ntfsraw import raw_copy
            n = raw_copy(src, dest, stop=self.stopped)
            if n is not None:
                return True, "raw-ntfs"
        except Exception as e:
            self.say(f"  raw NTFS read failed for {src}: {e}", "warn")
        # shadow-copy fallback: each attempt creates a snapshot, so stop trying after it fails twice
        if is_admin() and self._vss_failures < 2:
            rc, _, _ = self.run(["esentutl.exe", "/y", src, "/vss", "/d", dest], timeout=300, quiet=True)
            if rc == 0 and os.path.exists(dest):
                return True, "vss-esentutl"
            self._vss_failures += 1
        return False, "failed"

    def copy_tree(self, root, dest_rel, patterns=None, max_files=5000, max_bytes=None):
        """Copy files under root (optionally matching fnmatch patterns). Returns count copied."""
        import fnmatch
        n = 0
        if not os.path.isdir(root):
            return 0
        for dirpath, dirnames, files in os.walk(root):
            if self.stopped():
                break
            for f in files:
                if patterns and not any(fnmatch.fnmatch(f.lower(), p.lower()) for p in patterns):
                    continue
                src = os.path.join(dirpath, f)
                try:
                    if max_bytes and os.path.getsize(src) > max_bytes:
                        continue
                except OSError:
                    continue
                rel = os.path.join(dest_rel, os.path.relpath(src, root))
                if self.copy(src, rel):
                    n += 1
                if n >= max_files:
                    self.note(f"Stopped copying {root} after {max_files} files")
                    return n
        return n

    def close(self):
        for fh in (self._progress, self._footprint, self._copied_fh):
            try:
                fh.close()
            except Exception:
                pass


# ------------------------------------------------------------------ internals
def _kill_tree(p):
    """Kill a process and everything it started (a hung grandchild must not outlive the timeout)."""
    try:
        if PLATFORM == "windows":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True, timeout=30,
                           creationflags=no_window_flags())
        else:
            import signal
            os.killpg(p.pid, signal.SIGKILL)
    except Exception:
        pass
    try:
        p.kill()
    except Exception:
        pass


def _run_bounded(cmd, timeout, shell, env, input_data, stopped=None):
    """
    Run a command with output going to temporary files rather than pipes, so a grandchild that
    inherits the handles can't keep us waiting, and kill the whole process tree on timeout or stop.
    Returns (rc, stdout_bytes, stderr_bytes, error_text).
    """
    import tempfile
    with tempfile.TemporaryFile() as fo, tempfile.TemporaryFile() as fe:
        kw = {"creationflags": no_window_flags() | (0x00000200 if PLATFORM == "windows" else 0)}  # NEW_PROCESS_GROUP
        if PLATFORM != "windows":
            kw["start_new_session"] = True
        stdin = subprocess.PIPE if input_data is not None else subprocess.DEVNULL
        p = subprocess.Popen(cmd, stdout=fo, stderr=fe, stdin=stdin, shell=shell, env=env, **kw)
        if input_data is not None:
            try:
                p.stdin.write(input_data if isinstance(input_data, bytes) else input_data.encode())
                p.stdin.close()
            except OSError:
                pass
        deadline = time.time() + timeout
        err = ""
        while p.poll() is None:
            if time.time() > deadline:
                _kill_tree(p)
                err = f"timed out after {timeout}s"
                break
            if stopped and stopped():
                _kill_tree(p)
                err = "stopped by examiner"
                break
            time.sleep(0.1)
        try:
            rc = p.wait(15)
        except subprocess.TimeoutExpired:
            rc = None
        if err:
            rc = None
        fo.seek(0)
        fe.seek(0)
        return rc, fo.read(), fe.read(), err


def _decode(b):
    if b is None:
        return ""
    if isinstance(b, str):
        return b
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return b.decode("utf-16", "replace")
    if len(b) > 4 and b[1:2] == b"\x00" and b[3:4] == b"\x00":
        try:
            return b.decode("utf-16-le")
        except UnicodeDecodeError:
            pass
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        enc = "mbcs" if PLATFORM == "windows" else "latin-1"
        try:
            return b.decode(enc, "replace")
        except LookupError:
            return b.decode("latin-1", "replace")


def _cell(v):
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return " ".join(str(x) for x in v)
    if isinstance(v, dict):
        return json.dumps(v, default=str)
    return v


def _mirror_path(src):
    """C:\\Users\\bob\\x.db -> C/Users/bob/x.db ; /home/bob/x -> home/bob/x"""
    p = os.path.abspath(src)
    drive, rest = os.path.splitdrive(p)
    parts = [drive.rstrip(":").replace("\\", "") if drive else ""] + [x for x in rest.replace("\\", "/").split("/") if x]
    return os.path.join(*[safe_name(x, 120) for x in parts if x])


def write_manifest(case_dir, cache=None, on_file=None):
    """sha256sum-compatible manifest of every file in the case (except the manifest itself)."""
    cache = cache or {}
    lines = []
    for dirpath, _, files in os.walk(case_dir):
        for f in sorted(files):
            p = os.path.join(dirpath, f)
            rel = os.path.relpath(p, case_dir).replace("\\", "/")
            if rel in ("manifest.sha256", "progress.jsonl", STOP_FILE):
                continue
            try:
                st = os.stat(p)
                hit = cache.get(os.path.abspath(p))
                if hit and hit[0] == st.st_size and hit[1] == st.st_mtime:
                    digest = hit[2]
                else:
                    if on_file and st.st_size > 64 * 1024 * 1024:
                        on_file(rel, st.st_size)
                    digest = sha256_file(p)
                lines.append(f"{digest}  {rel}")
            except OSError as e:
                lines.append(f"# unreadable {rel}: {e}")
    lines.sort(key=lambda s: s.split("  ", 1)[-1])
    with open(os.path.join(case_dir, "manifest.sha256"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    return len(lines)


def case_folder_name(case_id, hostname):
    stamp = utc_now().strftime("%Y%m%d-%H%M%SZ")
    parts = ["LandullTriage", safe_name(hostname, 40)]
    if case_id:
        parts.insert(1, safe_name(case_id, 40))
    return "_".join(parts + [stamp])


def self_footprint():
    """Who/what is doing the collecting: our own process, executable and its hash."""
    exe = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(sys.argv[0] or __file__)
    fp = {"tool": "LandullTriage", "version": VERSION, "pid": os.getpid(), "executable": exe,
          "frozen": bool(getattr(sys, "frozen", False)), "argv": sys.argv, "cwd": os.getcwd(),
          "user": _whoami(), "admin": is_admin()}
    try:
        fp["executable_sha256"] = sha256_file(exe)
    except OSError:
        pass
    return fp


def _whoami():
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return os.environ.get("USERNAME") or os.environ.get("USER") or ""


def format_exc():
    return traceback.format_exc(limit=6)
