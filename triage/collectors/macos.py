"""macOS live-response collectors. No RAM capture on modern macOS, so the live state matters more here."""

import glob
import os
import plistlib
import re
import sqlite3
import shutil
import tempfile

from ..core import iso, is_admin
from .common import (HashCache, MAC_EPOCH, collect_browsers, file_times, read_text, recent, scan_script_text,
                     suspicious_cmd, suspicious_path, user_homes)

FDA_NOTE = ("Some macOS data (Safari, TCC, KnowledgeC, other users' Library folders) is protected by privacy controls. "
            "Give LandullTriage Full Disk Access in System Settings › Privacy & Security to collect it.")


def _codesign(run, paths):
    """{path: (status, authority)} using codesign; 'unsigned', 'adhoc', 'invalid' or the first Authority line."""
    out = {}
    for p in paths:
        rc, so, se = run.run(["codesign", "-dvv", p], timeout=20, quiet=True)
        text = (se or "") + (so or "")
        if rc is None:
            out[p] = ("", "")
        elif "not signed" in text:
            out[p] = ("unsigned", "")
        elif "Signature=adhoc" in text:
            out[p] = ("adhoc", "")
        else:
            auth = re.search(r"Authority=(.+)", text)
            team = re.search(r"TeamIdentifier=(.+)", text)
            out[p] = ("signed", (auth.group(1) if auth else "") + (f" [{team.group(1)}]" if team else ""))
    return out


# ------------------------------------------------------------------ processes
def collect_processes(run):
    rc, so, _ = run.run(["ps", "-axww", "-o", "pid=,ppid=,uid=,user=,lstart=,comm="], timeout=60, quiet=True)
    rc2, so2, _ = run.run(["ps", "-axww", "-o", "pid=,args="], timeout=60, quiet=True)
    run.say("$ ps -axww")
    args = {}
    for line in (so2 or "").splitlines():
        s = line.strip()
        if s:
            pid, _, a = s.partition(" ")
            args[pid] = a.strip()
    rows = []
    for line in (so or "").splitlines():
        f = line.split(None, 9)
        if len(f) < 10:
            continue
        pid, ppid, uid, user = f[0], f[1], f[2], f[3]
        start = " ".join(f[4:9])
        comm = f[9].strip()
        rows.append({"pid": int(pid), "ppid": int(ppid), "uid": uid, "user": user, "started_local": start,
                     "exe": comm, "name": os.path.basename(comm), "cmdline": args.get(pid, "")})
    hc = HashCache()
    paths = sorted({r["exe"] for r in rows if r["exe"].startswith("/") and not r["exe"].startswith(("/System/", "/usr/", "/bin/", "/sbin/"))})
    sigs = _codesign(run, paths)
    for r in rows:
        r["sha256"] = hc.get(r["exe"]) if r["exe"].startswith("/") else ""
        st, auth = sigs.get(r["exe"], ("system" if r["exe"].startswith(("/System/", "/usr/", "/bin/", "/sbin/")) else "", ""))
        r["signature"], r["signer"] = st, auth
        label = f"{r['name']} ({r['pid']})"
        why = suspicious_path(r["exe"])
        if why:
            run.flag(f"Process {label} {why}", r["cmdline"][:300], "high")
        cw = suspicious_cmd(r["cmdline"])
        if cw:
            run.flag(f"Process {label}: {cw}", r["cmdline"][:400], "high")
        if st in ("unsigned", "adhoc") and not r["exe"].startswith(("/Applications/", "/opt/homebrew/", "/usr/local/")):
            run.flag(f"{st.capitalize()} process {label} running from outside /Applications", r["exe"], "medium")
    run.write_csv("processes.csv", rows, ["pid", "ppid", "uid", "user", "started_local", "name", "exe", "signature",
                                          "signer", "sha256", "cmdline"])
    kids = {}
    for r in rows:
        kids.setdefault(r["ppid"], []).append(r)
    out = []

    def walk(r, d):
        out.append(f"{'  ' * d}{r['pid']:>6}  {r['user']:<12} {r['cmdline'][:200]}")
        for c in kids.get(r["pid"], []):
            if d < 40 and c["pid"] != r["pid"]:
                walk(c, d + 1)
    pids = {r["pid"] for r in rows}
    for r in rows:
        if r["ppid"] not in pids or r["ppid"] == r["pid"]:
            walk(r, 0)
    run.write_text("process_tree.txt", "\n".join(out))
    if not is_admin():
        run.note("Without root, open files and some process details for other users are hidden.")
    return {"count": len(rows)}


# ------------------------------------------------------------------ network
def collect_network(run):
    rc, so, _ = run.run(["lsof", "-i", "-n", "-P", "+c", "0"], out="lsof_network.txt", timeout=120)
    rows = []
    for line in (so or "").splitlines()[1:]:
        f = line.split()
        if len(f) < 9:
            continue
        name = " ".join(f[8:])
        m = re.match(r"(\S+?)(?:->(\S+))?(?:\s+\((\w+)\))?$", name)
        local, remote, state = (m.group(1), m.group(2) or "", m.group(3) or "") if m else (name, "", "")
        rows.append({"process": f[0], "pid": f[1], "user": f[2], "proto": f[7], "type": f[4], "local": local,
                     "remote": remote, "state": state})
    exe_by_pid = {}
    if rows:
        rc, so, _ = run.run(["ps", "-axww", "-o", "pid=,comm="], timeout=60, quiet=True)
        for line in (so or "").splitlines():
            s = line.strip()
            if s:
                pid, _, c = s.partition(" ")
                exe_by_pid[pid] = c.strip()
    for r in rows:
        r["exe"] = exe_by_pid.get(r["pid"], "")
        why = suspicious_path(r["exe"])
        if why and r["state"] in ("ESTABLISHED", "LISTEN", ""):
            run.flag(f"Network activity from {r['process']} ({r['pid']}), which {why}",
                     f"{r['proto']} {r['local']} -> {r['remote']} {r['state']}", "high")
    run.write_csv("connections.csv", rows, ["proto", "local", "remote", "state", "pid", "process", "user", "exe", "type"])
    for cmd, out in ((["netstat", "-anv"], "netstat.txt"), (["ifconfig", "-a"], "ifconfig.txt"), (["arp", "-an"], "arp.txt"),
                     (["netstat", "-rn"], "routes.txt"), (["scutil", "--dns"], "dns_config.txt"), (["scutil", "--proxy"], "proxy.txt"),
                     (["networksetup", "-listallhardwareports"], "hardware_ports.txt"), (["pfctl", "-sr"], "pf_rules.txt"),
                     (["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], "app_firewall.txt"),
                     (["smbutil", "statshares", "-a"], "smb_shares.txt")):
        run.run(cmd, out=out, timeout=60)
    for f in ("/etc/hosts", "/etc/resolv.conf"):
        if os.path.exists(f):
            run.copy(f, os.path.join("etc", os.path.basename(f)))
    if not is_admin():
        run.note("Without root, lsof only shows your own processes' connections.")
    est = sum(1 for r in rows if r["state"] == "ESTABLISHED")
    lis = sum(1 for r in rows if r["state"] == "LISTEN")
    run.say(f"{len(rows)} sockets ({est} established, {lis} listening)")
    return {"sockets": len(rows), "established": est, "listening": lis}


# ------------------------------------------------------------------ system
def collect_system(run):
    for cmd, out in ((["sw_vers"], "sw_vers.txt"), (["uname", "-a"], "uname.txt"), (["sysctl", "kern.boottime"], "boot_time.txt"),
                     (["uptime"], "uptime.txt"), (["system_profiler", "SPSoftwareDataType", "SPHardwareDataType"], "system_profiler.txt"),
                     (["csrutil", "status"], "sip_status.txt"), (["spctl", "--status"], "gatekeeper.txt"),
                     (["fdesetup", "status"], "filevault.txt"), (["softwareupdate", "--history"], "update_history.txt"),
                     (["systemextensionsctl", "list"], "system_extensions.txt"), (["kmutil", "showloaded", "--list-only"], "kexts_loaded.txt"),
                     (["profiles", "status", "-type", "enrollment"], "mdm_enrollment.txt"), (["profiles", "list", "-all"], "profiles.txt"),
                     (["diskutil", "list"], "disks.txt"), (["mount"], "mount.txt"), (["df", "-h"], "df.txt"),
                     (["systemsetup", "-gettimezone"], "timezone.txt"), (["pmset", "-g", "log"], "power_log.txt"),
                     (["nvram", "-p"], "nvram.txt")):
        run.run(cmd, out=out, timeout=180)
    rc, so, _ = run.run(["csrutil", "status"], timeout=30, quiet=True)
    if so and "disabled" in so.lower():
        run.flag("System Integrity Protection is disabled", so.strip()[:200], "high")
    rc, so, _ = run.run(["spctl", "--status"], timeout=30, quiet=True)
    if so and "disabled" in so.lower():
        run.flag("Gatekeeper is disabled", so.strip(), "medium")
    apps = []
    for root in ("/Applications", "/Applications/Utilities", *[os.path.join(h, "Applications") for _, h in user_homes()]):
        for app in sorted(glob.glob(os.path.join(root, "*.app"))):
            info = {}
            try:
                with open(os.path.join(app, "Contents", "Info.plist"), "rb") as fh:
                    info = plistlib.load(fh)
            except Exception:
                pass
            t = file_times(app)
            apps.append({"app": app, "bundle_id": info.get("CFBundleIdentifier", ""),
                         "version": info.get("CFBundleShortVersionString", ""), "modified_utc": t.get("modified_utc", ""),
                         "created_utc": t.get("created_utc", "")})
            if re.search(r"(?i)anydesk|teamviewer|screenconnect|splashtop|rustdesk|ngrok|logmein|vnc", app):
                run.flag(f"Remote access app installed: {os.path.basename(app)}", app, "medium")
    run.write_csv("applications.csv", apps)
    return {"applications": len(apps)}


# ------------------------------------------------------------------ users
def collect_users(run):
    rc, so, _ = run.run(["dscl", ".", "list", "/Users", "UniqueID"], out="dscl_users.txt", timeout=60)
    accounts = []
    for line in (so or "").splitlines():
        f = line.split()
        if len(f) == 2:
            accounts.append({"user": f[0], "uid": f[1], "system_account": f[0].startswith("_") or int(f[1]) < 500 if f[1].lstrip("-").isdigit() else ""})
            if f[1] == "0" and f[0] != "root":
                run.flag(f"Account {f[0]} has UID 0", line, "high")
    run.write_csv("accounts.csv", accounts)
    rc, so, _ = run.run(["dscl", ".", "read", "/Groups/admin", "GroupMembership"], out="admins.txt", timeout=30)
    for cmd, out in ((["who"], "who.txt"), (["w"], "w.txt"), (["last"], "last.txt"), (["id"], "collector_id.txt"),
                     (["dscl", ".", "list", "/Groups", "PrimaryGroupID"], "groups.txt")):
        run.run(cmd, out=out, timeout=60)
    for f in ("/etc/sudoers", "/Library/Preferences/com.apple.loginwindow.plist"):
        if os.path.exists(f):
            run.copy(f, os.path.join("files", os.path.basename(f)))
    run.copy_tree("/etc/sudoers.d", os.path.join("files", "sudoers.d"))
    for user, home in user_homes():
        p = os.path.join(home, ".ssh", "authorized_keys")
        if os.path.isfile(p):
            run.copy(p, os.path.join("ssh", user, "authorized_keys"))
            t = file_times(p)
            if recent(t.get("_mtime"), 30):
                run.flag(f"{user}'s SSH authorized_keys changed in the last 30 days", t.get("modified_utc", ""), "medium")
    return {"accounts": len(accounts)}


# ------------------------------------------------------------------ persistence
def _plist(path):
    try:
        with open(path, "rb") as fh:
            return plistlib.load(fh)
    except Exception:
        return None


def collect_persistence(run):
    hc = HashCache()
    rows = []
    dirs = [("/Library/LaunchDaemons", "system"), ("/Library/LaunchAgents", "system")]
    for user, home in user_homes():
        dirs.append((os.path.join(home, "Library", "LaunchAgents"), user))
    for d, owner in dirs:
        for p in sorted(glob.glob(os.path.join(d, "*.plist"))):
            run.copy(p)
            pl = _plist(p) or {}
            prog = pl.get("Program") or ""
            argv = pl.get("ProgramArguments") or []
            if not prog and argv:
                prog = argv[0]
            cmd = " ".join(str(a) for a in argv) if argv else prog
            t = file_times(p)
            ft = file_times(prog) if prog else {}
            sig = _codesign(run, [prog])[prog] if prog and os.path.isfile(prog) else ("", "")
            why = "; ".join(x for x in (suspicious_path(prog), suspicious_cmd(cmd)) if x)
            row = {"plist": p, "owner": owner, "label": pl.get("Label", ""), "program": prog, "command": cmd,
                   "run_at_load": pl.get("RunAtLoad", ""), "keep_alive": bool(pl.get("KeepAlive")),
                   "plist_modified_utc": t.get("modified_utc", ""), "program_exists": bool(ft),
                   "program_signature": sig[0], "program_signer": sig[1], "sha256": hc.get(prog) if ft else "",
                   "suspicious": why}
            rows.append(row)
            if why:
                run.flag(f"Launch item {row['label'] or os.path.basename(p)}: {why}", cmd[:300], "high")
            if sig[0] in ("unsigned", "adhoc"):
                run.flag(f"Launch item {row['label'] or os.path.basename(p)} runs an {sig[0]} program", prog, "medium")
            if recent(t.get("_mtime"), 30):
                run.flag(f"Launch item added or changed in the last 30 days: {os.path.basename(p)}", cmd[:300], "medium")
            if prog and not ft and not prog.startswith("/System/"):
                run.flag(f"Launch item {os.path.basename(p)} points to a missing program", prog, "low")
    run.write_csv("launch_items.csv", rows)
    other = []
    globs = ["/etc/periodic/*/*", "/etc/rc.common", "/etc/rc.local", "/etc/emond.d/rules/*", "/private/var/db/emondClients/*",
             "/Library/StartupItems/*/*", "/Library/Security/SecurityAgentPlugins/*", "/Library/DirectoryServices/PlugIns/*",
             "/etc/zshrc", "/etc/zprofile", "/etc/bashrc", "/etc/profile", "/usr/lib/cron/tabs/*", "/private/var/at/tabs/*",
             "/Library/Managed Preferences/*", "/Library/ScriptingAdditions/*", "/Library/Extensions/*.kext/Contents/Info.plist"]
    for user, home in user_homes():
        globs += [os.path.join(home, f) for f in (".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bash_profile", ".bashrc", ".profile",
                                                  "Library/Application Scripts/*/*", "Library/Preferences/com.apple.loginitems.plist")]
    for g in globs:
        for p in glob.glob(g):
            if not os.path.isfile(p):
                continue
            run.copy(p)
            t = file_times(p)
            text = read_text(p, 1024 * 1024) if (t.get("size") or 0) < 1024 * 1024 else None
            why = ""
            if text:
                for line in text.splitlines():
                    s = line.strip()
                    if s and not s.startswith("#"):
                        why = suspicious_cmd(s) or why
            other.append({"path": p, "modified_utc": t.get("modified_utc"), "suspicious": why})
            if why:
                scan_script_text(run, p, text, "Startup file")
            if g.startswith("/etc/emond.d") or g.startswith("/Library/StartupItems") or "ScriptingAdditions" in g:
                run.flag("Legacy/rare persistence location in use", p, "medium")
    run.write_csv("other_persistence_files.csv", other)
    run.run(["sfltool", "dumpbtm"], out="background_task_management.txt", timeout=120)  # login items + launch items (13+)
    run.run(["launchctl", "list"], out="launchctl_list.txt", timeout=60)
    run.run(["crontab", "-l"], out="crontab_current_user.txt", timeout=30)
    if not is_admin():
        run.note("Without root, sfltool dumpbtm (all login items) and other users' cron tabs can't be read.")
    return {"launch_items": len(rows), "other_files": len(other)}


# ------------------------------------------------------------------ logs
def collect_logs(run):
    days = int(run.config.get("log_days") or 7)
    if is_admin():
        dest = run.path("logs", "unified.logarchive")
        if os.path.exists(dest):
            shutil.rmtree(dest, ignore_errors=True)
        rc, _, _ = run.run(["log", "collect", "--last", f"{days}d", "--output", dest], timeout=1800)
        if rc != 0:
            run.note("log collect failed; falling back to a filtered text export.")
    else:
        run.note("Without root, only a filtered text export of the unified log is possible (no .logarchive).")
    pred = ('process == "sudo" OR process == "sshd" OR process == "su" OR process == "loginwindow" OR '
            'process == "screensharingd" OR process == "authd" OR subsystem == "com.apple.xprotect" OR '
            'subsystem == "com.apple.syspolicy.exec" OR eventMessage CONTAINS[c] "authentication failure" OR '
            'process == "installd" OR process == "backgroundtaskmanagementd" OR process == "tccd"')
    run.run(["log", "show", "--last", f"{min(days, 3)}d", "--style", "syslog", "--info", "--predicate", pred],
            out="security_events.txt", timeout=900)
    for g in ("/var/log/system.log*", "/var/log/install.log*", "/var/log/wifi.log*", "/var/log/fsck_*", "/var/log/asl/*.asl",
              "/Library/Logs/DiagnosticReports/*", "/var/log/jamf.log*"):
        for p in glob.glob(g):
            if os.path.isfile(p):
                run.copy(p)
    text = read_text(run.path("logs", "security_events.txt")) or ""
    fails = len(re.findall(r"(?i)authentication failure|incorrect password|Failed password", text))
    if fails > 20:
        run.flag(f"{fails} authentication failures in the last {min(days, 3)} days", "See logs/security_events.txt", "medium")
    return {"auth_failures": fails}


# ------------------------------------------------------------------ disk artifacts
_HISTORY = [".zsh_history", ".bash_history", ".python_history", ".lesshst", ".viminfo", ".mysql_history", ".psql_history",
            ".node_repl_history", ".ssh/known_hosts", ".ssh/config", ".gitconfig"]


def collect_artifacts(run):
    n = 0
    quarantine = []
    for user, home in user_homes():
        for h in _HISTORY:
            p = os.path.join(home, h)
            if os.path.isfile(p) and run.copy(p, os.path.join("user_files", user, h.replace("/", "_"))):
                n += 1
                if "history" in h:
                    scan_script_text(run, p, read_text(p), f"{user}'s shell history")
        run.copy_tree(os.path.join(home, ".zsh_sessions"), os.path.join("user_files", user, "zsh_sessions"), max_files=500)
        qdb = os.path.join(home, "Library", "Preferences", "com.apple.LaunchServices.QuarantineEventsV2")
        if os.path.isfile(qdb):
            d = run.copy(qdb, os.path.join("quarantine", user, "QuarantineEventsV2"))
            if d:
                quarantine += [dict(r, user=user) for r in _parse_quarantine(d)]
        dl = os.path.join(home, "Downloads")
        if os.path.isdir(dl):
            rows = []
            for p in sorted(glob.glob(os.path.join(dl, "*"))):
                t = file_times(p)
                rows.append({"path": p, "size": t.get("size"), "modified_utc": t.get("modified_utc"),
                             "created_utc": t.get("created_utc")})
            run.write_csv(os.path.join("downloads_listing", f"{user}.csv"), rows)
        for f in ("Library/Application Support/com.apple.TCC/TCC.db",):
            p = os.path.join(home, f)
            if os.path.isfile(p):
                run.copy(p, os.path.join("tcc", user, "TCC.db"))
    run.write_csv("quarantine_events.csv", quarantine)
    for p in ("/Library/Application Support/com.apple.TCC/TCC.db", "/private/var/db/CoreDuet/Knowledge/knowledgeC.db"):
        if os.path.exists(p) and not run.copy(p):
            run.note(FDA_NOTE)
            break
    listing = []
    macho_found = {}
    own = os.path.abspath(run.case_dir)
    for root in ("/tmp", "/private/var/tmp", "/Users/Shared"):
        for dp, dn, fn in os.walk(root):
            if run.stopped():
                break
            dn[:] = [d for d in dn if not os.path.abspath(os.path.join(dp, d)).startswith(own)]
            if os.path.abspath(dp).startswith(own):
                continue
            for f in fn:
                p = os.path.join(dp, f)
                t = file_times(p)
                try:
                    with open(p, "rb") as fh:
                        head = fh.read(4)
                except OSError:
                    head = b""
                macho = head in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xce\xfa\xed\xfe")
                listing.append({"path": p, "size": t.get("size"), "modified_utc": t.get("modified_utc"),
                                "created_utc": t.get("created_utc"), "mach_o": macho})
                if macho and (t.get("size") or 0) < 50 * 1024 * 1024:
                    run.copy(p, os.path.join("temp_executables", p.strip("/").replace("/", "_")))
                    macho_found.setdefault(root, []).append(f"{p} (modified {t.get('modified_utc')})")
    run.write_csv("temp_dirs_listing.csv", listing)
    for root, items in macho_found.items():
        run.flag(f"{len(items)} Mach-O executable(s) in {root}", "; ".join(items[:6]) + (" …" if len(items) > 6 else ""), "high")
    if not is_admin():
        run.note(FDA_NOTE)
    return {"history_files": n, "quarantine_events": len(quarantine)}


def _parse_quarantine(path):
    tmp = tempfile.mkdtemp(prefix="ltriage_")
    try:
        work = os.path.join(tmp, "q.db")
        shutil.copyfile(path, work)
        db = sqlite3.connect(work)
        rows = db.execute("SELECT LSQuarantineTimeStamp, LSQuarantineAgentName, LSQuarantineAgentBundleIdentifier, "
                          "LSQuarantineDataURLString, LSQuarantineOriginURLString, LSQuarantineSenderName "
                          "FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp").fetchall()
        db.close()
        return [{"time_utc": iso(ts + MAC_EPOCH) if ts else "", "agent": a, "agent_bundle": b, "url": u, "origin": o,
                 "sender": s} for ts, a, b, u, o, s in rows]
    except Exception:
        return []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def collect_browsers_mod(run):
    return collect_browsers(run)


COLLECTORS = {
    "network": collect_network,
    "processes": collect_processes,
    "system": collect_system,
    "users": collect_users,
    "persistence": collect_persistence,
    "logs": collect_logs,
    "browsers": collect_browsers_mod,
    "artifacts": collect_artifacts,
}
