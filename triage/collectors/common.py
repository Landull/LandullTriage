"""Pieces shared by every platform: user homes, suspicious-path checks, browser history, flag helpers."""

import glob
import os
import re
import shutil
import sqlite3
import tempfile
import time

from ..core import PLATFORM, iso, sha256_file

DAY = 86400

# ------------------------------------------------------------------ users and homes
def user_homes():
    """[(username, home_dir)] for real user profiles on this machine."""
    homes = []
    if PLATFORM == "windows":
        root = os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "Users")
        skip = {"public", "default", "default user", "all users", "defaultapppool", "wdagutilityaccount"}
        for d in sorted(glob.glob(os.path.join(root, "*"))):
            if os.path.isdir(d) and os.path.basename(d).lower() not in skip and not os.path.islink(d):
                homes.append((os.path.basename(d), d))
    elif PLATFORM == "macos":
        for d in sorted(glob.glob("/Users/*")):
            if os.path.isdir(d) and os.path.basename(d) not in ("Shared", "Guest") and not os.path.basename(d).startswith("."):
                homes.append((os.path.basename(d), d))
        if os.path.isdir("/var/root"):
            homes.append(("root", "/var/root"))
    else:
        seen = set()
        try:
            with open("/etc/passwd", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    f = line.rstrip("\n").split(":")
                    if len(f) >= 7 and os.path.isdir(f[5]) and f[5] not in seen and f[5] not in ("/", "/nonexistent"):
                        uid = int(f[2]) if f[2].isdigit() else -1
                        if uid == 0 or uid >= 1000 or f[5].startswith("/home/"):
                            seen.add(f[5])
                            homes.append((f[0], f[5]))
        except OSError:
            pass
        for d in sorted(glob.glob("/home/*")):
            if os.path.isdir(d) and d not in seen:
                homes.append((os.path.basename(d), d))
    return homes


# ------------------------------------------------------------------ suspicious locations
_SUSP_WIN = [
    (r"\\appdata\\local\\temp\\", "runs from a Temp folder"),
    (r"\\windows\\temp\\", "runs from Windows\\Temp"),
    (r"\\users\\public\\", "runs from C:\\Users\\Public"),
    (r"\\downloads\\", "runs from a Downloads folder"),
    (r"\\\$recycle\.bin\\", "runs from the Recycle Bin"),
    (r"\\programdata\\[^\\]+\.(exe|dll|scr|bat|ps1|vbs|js)$", "loose executable in the root of ProgramData"),
    (r"\\appdata\\roaming\\[^\\]+\.(exe|dll|scr)$", "loose executable in the root of AppData\\Roaming"),
    (r"\\perflogs\\", "runs from PerfLogs"),
    (r"\\windows\\tasks\\", "runs from Windows\\Tasks"),
    (r"\\windows\\debug\\", "runs from Windows\\debug"),
    (r"\\fonts\\.*\.(exe|dll)$", "executable in a Fonts folder"),
]
_SUSP_NIX = [
    (r"^/tmp/", "runs from /tmp"),
    (r"^/var/tmp/", "runs from /var/tmp"),
    (r"^/dev/shm/", "runs from /dev/shm (memory-backed)"),
    (r"^/private/tmp/", "runs from /tmp"),
    (r"^/private/var/tmp/", "runs from /var/tmp"),
    (r"^/users/shared/", "runs from /Users/Shared"),
    (r"/downloads/", "runs from a Downloads folder"),
    (r"/\.[^/]+/[^/]+$", "runs from a hidden folder"),
    (r"^/run/user/", "runs from /run/user"),
]

_SUSP_CMD = [
    (r"(?i)(powershell|pwsh)(\.exe)?\b.*\s[-/]e(c|nc|ncodedcommand)?\s+[a-z0-9+/=]{40,}", "encoded PowerShell command"),
    (r"(?i)\b(iex|invoke-expression)\b", "PowerShell Invoke-Expression"),
    (r"(?i)downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer", "downloads from the internet"),
    (r"(?i)frombase64string", "decodes base64"),
    (r"(?i)-w(indowstyle)?\s+hidden", "hidden window"),
    (r"(?i)\bmshta(\.exe)?\b.*(http|javascript|vbscript)", "mshta running remote or inline script"),
    (r"(?i)\bregsvr32(\.exe)?\b.*/i:\s*http", "regsvr32 loading a remote scriptlet"),
    (r"(?i)\brundll32(\.exe)?\b.*(javascript|http|\\appdata\\|\\temp\\)", "rundll32 with script or user-folder DLL"),
    (r"(?i)\bcertutil(\.exe)?\b.*(-urlcache|-decode)", "certutil download or decode"),
    (r"(?i)\bbitsadmin\b.*/transfer", "bitsadmin download"),
    (r"(?i)\b(wscript|cscript)(\.exe)?\b.*\.(js|jse|vbs|vbe|wsf)\b.*(\\temp\\|\\appdata\\|\\users\\public\\)", "script host running a script from a user folder"),
    (r"/dev/tcp/|/dev/udp/", "bash network redirection (reverse shell pattern)"),
    (r"\b(nc|ncat|netcat)\b.*\s-(e|c)\s", "netcat executing a program"),
    (r"\bsocat\b.*exec", "socat exec"),
    (r"python[0-9.]*\s+-c\s+.*socket", "inline Python with sockets"),
    (r"perl\s+-e\s+.*socket", "inline Perl with sockets"),
    (r"(curl|wget)\s[^|;]*\|\s*(ba|z|da)?sh\b", "downloads and pipes straight into a shell"),
    (r"base64\s+(-d|--decode)", "decodes base64"),
    (r"(?i)osascript\s+-e", "inline AppleScript"),
    (r"\bchmod\s+\+?[0-7]*x?\s+/(tmp|var/tmp|dev/shm)/", "makes a temp file executable"),
]


def suspicious_path(path):
    """Reason string if an executable path is in a place malware likes, else ''."""
    if not path:
        return ""
    p = path.replace("/", "\\").lower() if PLATFORM == "windows" else path.lower()
    for rx, why in (_SUSP_WIN if PLATFORM == "windows" else _SUSP_NIX):
        if re.search(rx, p):
            return why
    return ""


def suspicious_cmd(cmd):
    if not cmd:
        return ""
    reasons = [why for rx, why in _SUSP_CMD if re.search(rx, cmd)]
    return "; ".join(dict.fromkeys(reasons))


def recent(ts, days=30):
    try:
        return ts and (time.time() - float(ts)) < days * DAY and float(ts) <= time.time() + DAY
    except (TypeError, ValueError):
        return False


def file_times(path):
    try:
        st = os.stat(path)
    except OSError:
        return {}
    b = getattr(st, "st_birthtime", None)
    return {"size": st.st_size, "modified_utc": iso(st.st_mtime),
            "created_utc": iso(b) if b else (iso(st.st_ctime) if PLATFORM == "windows" else ""),
            "changed_utc": "" if PLATFORM == "windows" else iso(st.st_ctime), "_mtime": st.st_mtime,
            "_ctime": b or st.st_ctime}


class HashCache:
    """Hash each executable once per run."""

    def __init__(self):
        self.cache = {}

    def get(self, path, limit=512 * 1024 * 1024):
        if not path:
            return ""
        if path in self.cache:
            return self.cache[path]
        h = ""
        try:
            if os.path.isfile(path) and os.path.getsize(path) <= limit:
                h = sha256_file(path)
        except OSError:
            h = ""
        self.cache[path] = h
        return h


def first_exe(cmd):
    """Best-effort executable path from a command line (handles quotes, %VARS% and rundll32 targets)."""
    if not cmd:
        return ""
    c = os.path.expandvars(cmd.strip())
    if PLATFORM == "windows":
        c = re.sub(r"%([^%]+)%", lambda m: os.environ.get(m.group(1), m.group(0)), c)
        c = re.sub(r"(?i)^\\\?\?\\", "", c)
        c = re.sub(r"(?i)^\\systemroot\\", os.environ.get("SystemRoot", r"C:\Windows").replace("\\", "\\\\") + r"\\", c)
        c = re.sub(r"(?i)^system32\\", os.environ.get("SystemRoot", r"C:\Windows").replace("\\", "\\\\") + r"\\System32\\", c)
    if c.startswith('"'):
        exe = c[1:].split('"', 1)[0]
        rest = c[len(exe) + 2:]
    else:
        exe = c
        rest = ""
        if PLATFORM == "windows":
            m = re.match(r"(?i)^(.+?\.(exe|com|bat|cmd|dll|ps1|vbs|js|scr|cpl|msc))(\s|$|,)", c)
            if m:
                exe, rest = m.group(1), c[len(m.group(1)):]
            else:
                exe, _, rest = c.partition(" ")
        else:
            exe, _, rest = c.partition(" ")
    base = os.path.basename(exe).lower()
    if PLATFORM == "windows" and base in ("rundll32.exe", "rundll32", "regsvr32.exe", "regsvr32"):
        m = re.search(r'"?([a-z]:\\[^",]+?\.(dll|ocx|cpl|exe))', rest, re.I)
        if m:
            return m.group(1)
    if PLATFORM == "windows" and not os.path.isabs(exe):
        found = shutil.which(exe)
        if found:
            return found
    return exe


# ------------------------------------------------------------------ browser history
def _browser_roots(home):
    if PLATFORM == "windows":
        la = os.path.join(home, "AppData", "Local")
        ra = os.path.join(home, "AppData", "Roaming")
        chromium = {"Chrome": os.path.join(la, "Google", "Chrome", "User Data"),
                    "Edge": os.path.join(la, "Microsoft", "Edge", "User Data"),
                    "Brave": os.path.join(la, "BraveSoftware", "Brave-Browser", "User Data"),
                    "Vivaldi": os.path.join(la, "Vivaldi", "User Data"),
                    "Opera": os.path.join(ra, "Opera Software", "Opera Stable"),
                    "Opera GX": os.path.join(ra, "Opera Software", "Opera GX Stable"),
                    "Chromium": os.path.join(la, "Chromium", "User Data")}
        firefox = [os.path.join(ra, "Mozilla", "Firefox", "Profiles")]
        safari = None
    elif PLATFORM == "macos":
        a = os.path.join(home, "Library", "Application Support")
        chromium = {"Chrome": os.path.join(a, "Google", "Chrome"),
                    "Edge": os.path.join(a, "Microsoft Edge"),
                    "Brave": os.path.join(a, "BraveSoftware", "Brave-Browser"),
                    "Vivaldi": os.path.join(a, "Vivaldi"),
                    "Arc": os.path.join(a, "Arc", "User Data"),
                    "Opera": os.path.join(a, "com.operasoftware.Opera"),
                    "Chromium": os.path.join(a, "Chromium")}
        firefox = [os.path.join(a, "Firefox", "Profiles")]
        safari = os.path.join(home, "Library", "Safari")
    else:
        c = os.path.join(home, ".config")
        chromium = {"Chrome": os.path.join(c, "google-chrome"),
                    "Chromium": os.path.join(c, "chromium"),
                    "Chromium (snap)": os.path.join(home, "snap", "chromium", "common", "chromium"),
                    "Edge": os.path.join(c, "microsoft-edge"),
                    "Brave": os.path.join(c, "BraveSoftware", "Brave-Browser"),
                    "Vivaldi": os.path.join(c, "vivaldi"),
                    "Opera": os.path.join(c, "opera")}
        firefox = [os.path.join(home, ".mozilla", "firefox"),
                   os.path.join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
                   os.path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox")]
        safari = None
    return chromium, firefox, safari


def _chromium_profiles(root):
    out = []
    if not os.path.isdir(root):
        return out
    if os.path.isfile(os.path.join(root, "History")):       # Opera keeps History in the root
        out.append(("Default", root))
    for d in sorted(glob.glob(os.path.join(root, "*"))):
        if os.path.isfile(os.path.join(d, "History")):
            out.append((os.path.basename(d), d))
    return out


def _sidecars(path):
    return [path] + [path + s for s in ("-wal", "-journal", "-shm") if os.path.exists(path + s)]


WEBKIT_EPOCH = 11644473600  # seconds between 1601-01-01 and 1970-01-01
MAC_EPOCH = 978307200       # seconds between 1970-01-01 and 2001-01-01


def _q(db, sql):
    try:
        return db.execute(sql).fetchall()
    except sqlite3.Error:
        return []


def _parse_copy(files, parser):
    """Parse a working copy outside the case folder, so evidence copies stay byte-identical."""
    tmp = tempfile.mkdtemp(prefix="ltriage_")
    try:
        main = None
        for f in files:
            dst = os.path.join(tmp, os.path.basename(f))
            shutil.copyfile(f, dst)
            main = main or dst
        db = sqlite3.connect(main)
        try:
            return parser(db)
        finally:
            db.close()
    except Exception:
        return [], []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _chromium_parse(db):
    hist = [{"visit_utc": iso(vt / 1e6 - WEBKIT_EPOCH) if vt else "", "url": url, "title": title,
             "visit_count": vc, "transition": tr & 0xFF if tr is not None else ""}
            for vt, url, title, vc, tr in _q(db, "SELECT v.visit_time, u.url, u.title, u.visit_count, v.transition "
                                                   "FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time")]
    dls = [{"start_utc": iso(st / 1e6 - WEBKIT_EPOCH) if st else "", "saved_to": tp, "url": url or tab,
            "referrer": ref, "bytes": tb, "mime": mime}
           for st, tp, url, tab, ref, tb, mime in _q(db, "SELECT start_time, target_path, "
                                                         "(SELECT url FROM downloads_url_chains c WHERE c.id = d.id ORDER BY chain_index DESC LIMIT 1), "
                                                         "tab_url, referrer, total_bytes, mime_type FROM downloads d")]
    return hist, dls


def _firefox_parse(db):
    hist = [{"visit_utc": iso(vd / 1e6) if vd else "", "url": url, "title": title, "visit_count": vc,
             "transition": vt}
            for vd, url, title, vc, vt in _q(db, "SELECT v.visit_date, p.url, p.title, p.visit_count, v.visit_type "
                                                 "FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id ORDER BY v.visit_date")]
    dls = [{"start_utc": iso(da / 1e6) if da else "", "saved_to": content, "url": url, "referrer": "", "bytes": "", "mime": ""}
           for da, content, url in _q(db, "SELECT a.dateAdded, a.content, p.url FROM moz_annos a "
                                          "JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id "
                                          "JOIN moz_places p ON p.id = a.place_id WHERE n.name = 'downloads/destinationFileURI'")]
    return hist, dls


def _safari_parse(db):
    hist = [{"visit_utc": iso(vt + MAC_EPOCH) if vt else "", "url": url, "title": title, "visit_count": vc, "transition": ""}
            for vt, url, title, vc in _q(db, "SELECT v.visit_time, i.url, v.title, i.visit_count FROM history_visits v "
                                             "JOIN history_items i ON i.id = v.history_item ORDER BY v.visit_time")]
    return hist, []


def collect_browsers(run):
    """Copy browser history databases for every user, then build merged history.csv and downloads.csv."""
    history, downloads, found = [], [], []
    for user, home in user_homes():
        if run.stopped():
            break
        chromium, firefox_roots, safari = _browser_roots(home)
        jobs = []
        for browser, root in chromium.items():
            for prof, pdir in _chromium_profiles(root):
                jobs.append((browser, prof, [os.path.join(pdir, "History")], _chromium_parse,
                             [os.path.join(pdir, n) for n in ("Shortcuts", "Top Sites", "Preferences")]))
        for froot in firefox_roots:
            for pdir in sorted(glob.glob(os.path.join(froot, "*"))):
                if os.path.isfile(os.path.join(pdir, "places.sqlite")):
                    jobs.append(("Firefox", os.path.basename(pdir), [os.path.join(pdir, "places.sqlite")], _firefox_parse,
                                 [os.path.join(pdir, "formhistory.sqlite"), os.path.join(pdir, "extensions.json")]))
        if safari and os.path.isdir(safari):
            jobs.append(("Safari", "Default", [os.path.join(safari, "History.db")], _safari_parse,
                         [os.path.join(safari, "Downloads.plist")]))
        for browser, prof, dbs, parser, extras in jobs:
            dest_dir = os.path.join(safe(user), safe(browser), safe(prof))
            copied = []
            for db in dbs:
                for f in _sidecars(db):
                    if f.endswith("-shm"):
                        continue
                    d = run.copy(f, os.path.join(dest_dir, os.path.basename(f)))
                    if d:
                        copied.append(d)
                    elif f == db and os.path.exists(f) and PLATFORM == "macos" and browser == "Safari":
                        run.note("Safari history is protected by macOS. Give LandullTriage Full Disk Access "
                                 "(System Settings › Privacy & Security) to collect it.")
            for e in extras:
                if os.path.isfile(e):
                    run.copy(e, os.path.join(dest_dir, os.path.basename(e)))
            if not copied:
                continue
            found.append(f"{user} / {browser} / {prof}")
            h, d = _parse_copy(copied, parser)
            for r in h:
                r.update({"user": user, "browser": browser, "profile": prof})
            for r in d:
                r.update({"user": user, "browser": browser, "profile": prof})
            history += h
            downloads += d
    history.sort(key=lambda r: r.get("visit_utc") or "")
    downloads.sort(key=lambda r: r.get("start_utc") or "")
    run.write_csv("history.csv", history, ["visit_utc", "user", "browser", "profile", "url", "title", "visit_count", "transition"])
    run.write_csv("downloads.csv", downloads, ["start_utc", "user", "browser", "profile", "url", "saved_to", "referrer", "bytes", "mime"])
    for r in downloads:
        name =(r.get("saved_to") or "").lower()
        if re.search(r"\.(exe|scr|js|jse|vbs|vbe|hta|iso|img|lnk|ps1|bat|cmd|msi|dll|dmg|pkg|sh|zip|7z|rar)$", name) and recent(_ts(r["start_utc"]), 14):
            run.flag(f"Recent download of {os.path.basename(r['saved_to'])}", f"{r['browser']} ({r['user']}) from {r['url']} at {r['start_utc']}", "low")
    run.say(f"{len(found)} browser profile(s), {len(history)} visits, {len(downloads)} downloads")
    return {"profiles": found, "visits": len(history), "downloads": len(downloads)}


def _ts(isostr):
    import datetime as dt
    try:
        return dt.datetime.strptime(isostr[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc).timestamp()
    except (ValueError, TypeError):
        return 0


def safe(s):
    from ..core import safe_name
    return safe_name(s, 60)


# ------------------------------------------------------------------ text helpers
def read_text(path, limit=20 * 1024 * 1024):
    try:
        with open(path, "rb") as fh:
            b = fh.read(limit)
        return b.decode("utf-8", "replace")
    except OSError:
        return None


def scan_script_text(run, path, text, where):
    """Flag risky patterns inside a persistence file (cron line, unit file, plist, shell rc)."""
    if not text:
        return
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        why = suspicious_cmd(s)
        if why:
            run.flag(f"{where}: {why}", f"{path}: {s[:300]}", "high")
            break
