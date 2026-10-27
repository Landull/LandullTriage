"""Linux live-response collectors. Read /proc directly where possible; shell out for the rest."""

import glob
import os
import re
import socket
import stat
import struct

from ..core import iso, is_admin
from .common import (HashCache, collect_browsers, file_times, read_text, recent, scan_script_text, suspicious_cmd,
                     suspicious_path, user_homes)

CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100


def _boot_time():
    try:
        with open("/proc/stat") as fh:
            for line in fh:
                if line.startswith("btime"):
                    return int(line.split()[1])
    except OSError:
        pass
    return 0


def _read(p, mode="r"):
    try:
        with open(p, mode) as fh:
            return fh.read()
    except OSError:
        return None


def _users_by_uid():
    m = {}
    for line in (_read("/etc/passwd") or "").splitlines():
        f = line.split(":")
        if len(f) >= 3 and f[2].isdigit():
            m.setdefault(int(f[2]), f[0])
    return m


# ------------------------------------------------------------------ processes
def _processes():
    boot = _boot_time()
    users = _users_by_uid()
    procs = []
    for d in glob.glob("/proc/[0-9]*"):
        pid = int(os.path.basename(d))
        st = _read(f"{d}/stat")
        if not st:
            continue
        rp = st.rfind(")")
        comm = st[st.find("(") + 1:rp]
        fields = st[rp + 2:].split()
        ppid = int(fields[1])
        start = boot + int(fields[19]) / CLK_TCK if boot else 0
        cmd = (_read(f"{d}/cmdline", "rb") or b"").replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        try:
            exe = os.readlink(f"{d}/exe")
        except OSError:
            exe = ""
        try:
            cwd = os.readlink(f"{d}/cwd")
        except OSError:
            cwd = ""
        uid = ""
        for line in (_read(f"{d}/status") or "").splitlines():
            if line.startswith("Uid:"):
                uid = int(line.split()[1])
                break
        procs.append({"pid": pid, "ppid": ppid, "name": comm, "user": users.get(uid, uid), "uid": uid,
                      "start_utc": iso(start) if start else "", "exe": exe, "cwd": cwd, "cmdline": cmd,
                      "kernel_thread": not cmd and not exe})
    procs.sort(key=lambda p: p["pid"])
    return procs


def _tree(procs):
    kids = {}
    for p in procs:
        kids.setdefault(p["ppid"], []).append(p)
    pids = {p["pid"] for p in procs}
    lines = []

    def walk(p, depth):
        lines.append(f"{'  ' * depth}{p['pid']:>7}  {p['user']!s:<10} {p['name']}  {p['cmdline'][:200]}")
        for c in kids.get(p["pid"], []):
            if depth < 40:
                walk(c, depth + 1)
    for p in procs:
        if p["ppid"] not in pids:
            walk(p, 0)
    return "\n".join(lines)


def collect_processes(run):
    hc = HashCache()
    procs = _processes()
    for p in procs:
        if p["kernel_thread"]:
            continue
        exe = p["exe"]
        deleted = exe.endswith(" (deleted)")
        real = f"/proc/{p['pid']}/exe"
        p["exe_deleted"] = deleted
        p["sha256"] = hc.get(real) if (deleted or exe) else ""
        why = suspicious_path(exe.replace(" (deleted)", ""))
        cmdwhy = suspicious_cmd(p["cmdline"])
        if deleted:
            run.flag(f"Process {p['name']} ({p['pid']}) is running from a deleted file",
                     f"{exe} — the binary was removed after it started; a copy was saved", "high")
            run.copy(real, os.path.join("deleted_executables", f"{p['pid']}_{os.path.basename(exe.split(' ')[0])}"))
        if why:
            run.flag(f"Process {p['name']} ({p['pid']}) {why}", p["cmdline"] or exe, "high")
        if cmdwhy:
            run.flag(f"Process {p['name']} ({p['pid']}): {cmdwhy}", p["cmdline"][:400], "high")
        if exe and (p["cmdline"].startswith("[") or re.match(r"^(kworker|kthreadd|ksoftirqd|migration/|rcu_)", p["name"])):
            run.flag(f"Process {p['pid']} looks like a kernel thread but has an executable", f"{exe} {p['cmdline']}", "high")
    run.write_csv("processes.csv", procs, ["pid", "ppid", "name", "user", "uid", "start_utc", "exe", "exe_deleted",
                                            "sha256", "cwd", "cmdline", "kernel_thread"])
    run.write_text("process_tree.txt", _tree(procs))
    run.run(["ps", "auxwwf"], out="ps_auxwwf.txt")
    if is_admin():
        run.run(["lsof", "-n", "-P", "+c", "0"], out="lsof.txt", timeout=180)
    run.say(f"{len(procs)} processes")
    return {"count": len(procs)}


# ------------------------------------------------------------------ network
_TCP_STATES = {1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1", 5: "FIN_WAIT2", 6: "TIME_WAIT",
               7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING", 12: "NEW_SYN_RECV"}


def _addr(hexaddr, v6):
    ip, port = hexaddr.split(":")
    raw = bytes.fromhex(ip)
    if v6:
        raw = b"".join(struct.pack("<I", struct.unpack(">I", raw[i:i + 4])[0]) for i in range(0, 16, 4))
        a = socket.inet_ntop(socket.AF_INET6, raw)
    else:
        a = socket.inet_ntop(socket.AF_INET, raw[::-1])
    return a, int(port, 16)


def _inode_pids():
    m = {}
    for d in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            t = os.readlink(d)
        except OSError:
            continue
        if t.startswith("socket:["):
            m.setdefault(t[8:-1], d.split("/")[2])
    return m


def _is_public(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return a.is_global
    except ValueError:
        return False


def collect_network(run):
    inodes = _inode_pids()
    names = {}
    for p in glob.glob("/proc/[0-9]*/comm"):
        names[p.split("/")[2]] = (_read(p) or "").strip()
    exes = {}
    rows = []
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        text = _read(f"/proc/net/{proto}")
        if not text:
            continue
        for line in text.splitlines()[1:]:
            f = line.split()
            if len(f) < 10:
                continue
            try:
                la, lp = _addr(f[1], proto.endswith("6"))
                ra, rp = _addr(f[2], proto.endswith("6"))
            except (ValueError, OSError):
                continue
            state = _TCP_STATES.get(int(f[3], 16), f[3]) if proto.startswith("tcp") else ""
            pid = inodes.get(f[9], "")
            if pid and pid not in exes:
                try:
                    exes[pid] = os.readlink(f"/proc/{pid}/exe")
                except OSError:
                    exes[pid] = ""
            rows.append({"proto": proto, "local_address": la, "local_port": lp, "remote_address": ra,
                         "remote_port": rp, "state": state, "pid": pid, "process": names.get(pid, ""),
                         "exe": exes.get(pid, ""), "uid": f[7], "inode": f[9]})
    run.write_csv("connections.csv", rows)
    for r in rows:
        why = suspicious_path(r["exe"].replace(" (deleted)", ""))
        if why and (r["state"] in ("ESTABLISHED", "LISTEN") or r["proto"].startswith("udp")):
            run.flag(f"Network activity from {r['process'] or 'pid ' + str(r['pid'])}, which {why}",
                     f"{r['proto']} {r['local_address']}:{r['local_port']} -> {r['remote_address']}:{r['remote_port']} {r['state']}", "high")
    if not is_admin():
        run.note("Without root, sockets owned by other users can't be matched to processes.")
    for cmd, out in ((["ss", "-tunapeo"], "ss.txt"), (["ip", "addr"], "ip_addr.txt"), (["ip", "route", "show", "table", "all"], "ip_route.txt"),
                     (["ip", "neigh"], "arp.txt"), (["ip", "-s", "link"], "ip_link.txt"), (["iptables-save"], "iptables.txt"),
                     (["ip6tables-save"], "ip6tables.txt"), (["nft", "list", "ruleset"], "nftables.txt"),
                     (["resolvectl", "status"], "resolvectl.txt"), (["hostname", "-I"], "hostname_ips.txt")):
        run.run(cmd, out=out, timeout=60)
    for f in ("/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/hosts.allow", "/etc/hosts.deny"):
        if os.path.exists(f):
            run.copy(f, os.path.join("etc", os.path.basename(f)))
    est = sum(1 for r in rows if r["state"] == "ESTABLISHED")
    lis = sum(1 for r in rows if r["state"] == "LISTEN")
    run.say(f"{len(rows)} sockets ({est} established, {lis} listening)")
    return {"sockets": len(rows), "established": est, "listening": lis}


# ------------------------------------------------------------------ system
def collect_system(run):
    for cmd, out in ((["uname", "-a"], "uname.txt"), (["uptime"], "uptime.txt"), (["hostnamectl"], "hostnamectl.txt"),
                     (["timedatectl"], "timedatectl.txt"), (["lsmod"], "lsmod.txt"), (["mount"], "mount.txt"),
                     (["df", "-hT"], "df.txt"), (["lsblk", "-f"], "lsblk.txt"), (["lsusb"], "lsusb.txt"),
                     (["who", "-b"], "boot_time.txt"), (["dmesg", "-T"], "dmesg.txt"), (["sysctl", "-a"], "sysctl.txt"),
                     (["systemctl", "list-units", "--all", "--no-pager"], "systemd_units.txt"),
                     (["dpkg", "-l"], "packages_dpkg.txt"), (["rpm", "-qa", "--last"], "packages_rpm.txt"),
                     (["snap", "list"], "packages_snap.txt"), (["flatpak", "list"], "packages_flatpak.txt"),
                     (["getenforce"], "selinux.txt"), (["aa-status"], "apparmor.txt"), (["docker", "ps", "-a"], "docker_ps.txt")):
        run.run(cmd, out=out, timeout=120)
    for f in ("/etc/os-release", "/etc/hostname", "/etc/timezone", "/etc/machine-id", "/proc/version", "/proc/cmdline",
              "/proc/sys/kernel/tainted", "/etc/fstab", "/etc/crypttab"):
        if os.path.exists(f):
            run.copy(f, os.path.join("files", f.strip("/").replace("/", "_")))
    taint = (_read("/proc/sys/kernel/tainted") or "0").strip()
    if taint.isdigit() and int(taint) & (1 << 12 | 1 << 13):
        run.flag("Kernel is tainted by an out-of-tree or unsigned module", f"/proc/sys/kernel/tainted = {taint}", "medium")
    return {}


# ------------------------------------------------------------------ users
def collect_users(run):
    accounts = []
    shadow = {}
    if is_admin():
        for line in (_read("/etc/shadow") or "").splitlines():
            f = line.split(":")
            if len(f) >= 3:
                pw = f[1]
                state = "locked" if pw.startswith("!") or pw == "*" else "no password" if pw == "" else "password set"
                last = ""
                if f[2].isdigit():
                    last = iso(int(f[2]) * 86400)[:10]
                shadow[f[0]] = (state, last)   # hashes are never copied
    for line in (_read("/etc/passwd") or "").splitlines():
        f = line.split(":")
        if len(f) < 7:
            continue
        st, last = shadow.get(f[0], ("", ""))
        accounts.append({"user": f[0], "uid": f[2], "gid": f[3], "gecos": f[4], "home": f[5], "shell": f[6],
                         "password_state": st, "password_changed": last,
                         "can_login": not f[6].endswith(("nologin", "false", "sync", "halt", "shutdown"))})
        if f[2] == "0" and f[0] != "root":
            run.flag(f"Account {f[0]} has UID 0 (root-equivalent)", line, "high")
        if st == "no password" and accounts[-1]["can_login"]:
            run.flag(f"Account {f[0]} has an empty password and a login shell", "", "high")
    run.write_csv("accounts.csv", accounts)
    for f in ("/etc/passwd", "/etc/group", "/etc/sudoers", "/etc/login.defs"):
        if os.path.exists(f):
            run.copy(f, os.path.join("etc", os.path.basename(f)))
    run.copy_tree("/etc/sudoers.d", os.path.join("etc", "sudoers.d"))
    for cmd, out in ((["w"], "w.txt"), (["who", "-a"], "who.txt"), (["last", "-Faiwx"], "last.txt"),
                     (["lastb", "-Faiw"], "lastb.txt"), (["lastlog"], "lastlog.txt"), (["id"], "collector_id.txt"),
                     (["loginctl", "list-sessions", "--no-legend"], "sessions.txt")):
        run.run(cmd, out=out, timeout=60)
    keys = 0
    for user, home in user_homes():
        for kf in ("authorized_keys", "authorized_keys2"):
            p = os.path.join(home, ".ssh", kf)
            if os.path.isfile(p):
                run.copy(p, os.path.join("ssh", user, kf))
                keys += 1
                t = file_times(p)
                if recent(t.get("_mtime"), 30):
                    run.flag(f"{user}'s SSH {kf} changed in the last 30 days", f"{p} modified {t['modified_utc']}", "medium")
    return {"accounts": len(accounts), "authorized_keys_files": keys}


# ------------------------------------------------------------------ persistence
_PERSIST_GLOBS = [
    "/etc/crontab", "/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*", "/etc/cron.weekly/*",
    "/etc/cron.monthly/*", "/etc/anacrontab", "/var/spool/cron/*", "/var/spool/cron/crontabs/*",
    "/var/spool/cron/atjobs/*", "/var/spool/at/*", "/etc/rc.local", "/etc/rc.d/rc.local",
    "/etc/systemd/system/*.service", "/etc/systemd/system/*.timer", "/etc/systemd/system/*.socket",
    "/etc/systemd/system/*/*.service", "/etc/systemd/system/*.wants/*", "/run/systemd/system/*.service",
    "/etc/systemd/user/*.service", "/usr/lib/systemd/system-generators/*", "/etc/systemd/system-generators/*",
    "/etc/init.d/*", "/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zsh/zshrc",
    "/etc/zshrc", "/etc/environment", "/etc/ld.so.preload", "/etc/ld.so.conf.d/*", "/etc/udev/rules.d/*",
    "/etc/xdg/autostart/*", "/etc/update-motd.d/*", "/etc/modules", "/etc/modules-load.d/*",
    "/etc/pam.d/*", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*", "/etc/apt/apt.conf.d/*",
    "/etc/yum/pluginconf.d/*", "/etc/NetworkManager/dispatcher.d/*", "/etc/sudoers.d/*",
]
_USER_PERSIST = [".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_logout", ".zshrc", ".zprofile",
                 ".zshenv", ".zlogin", ".config/autostart/*", ".config/systemd/user/*.service",
                 ".config/systemd/user/*.timer", ".config/systemd/user/*/*", ".local/share/systemd/user/*",
                 ".ssh/rc", ".ssh/config", ".xinitrc", ".xsessionrc", ".config/fish/config.fish"]


def collect_persistence(run):
    rows = []
    targets = []
    for g in _PERSIST_GLOBS:
        targets += [(p, "system") for p in glob.glob(g)]
    for user, home in user_homes():
        for g in _USER_PERSIST:
            targets += [(p, user) for p in glob.glob(os.path.join(home, g))]
    seen = set()
    changed = []
    for p, owner in targets:
        if p in seen or not os.path.isfile(p):
            continue
        seen.add(p)
        t = file_times(p)
        run.copy(p)
        text = read_text(p, 2 * 1024 * 1024) if t.get("size", 0) < 2 * 1024 * 1024 else None
        why = ""
        if text:
            for line in text.splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    why = suspicious_cmd(s) or why
        rows.append({"path": p, "owner": owner, "size": t.get("size"), "modified_utc": t.get("modified_utc"),
                     "changed_utc": t.get("changed_utc"), "recent_30d": bool(recent(t.get("_ctime"), 30) or recent(t.get("_mtime"), 30)),
                     "suspicious": why})
        if why:
            scan_script_text(run, p, text, "Persistence file")
        elif rows[-1]["recent_30d"] and not p.startswith(("/etc/pam.d/", "/etc/apt/")):
            changed.append(f"{p} ({t.get('modified_utc')})")
    if changed:
        run.flag(f"{len(changed)} persistence file(s) changed in the last 30 days",
                 "; ".join(changed[:8]) + (" …see persistence/persistence_files.csv" if len(changed) > 8 else ""), "low")
    preload = (_read("/etc/ld.so.preload") or "").strip()
    if preload:
        run.flag("/etc/ld.so.preload is in use (a common rootkit technique)", preload[:300], "high")
    run.write_csv("persistence_files.csv", rows)
    for cmd, out in ((["systemctl", "list-unit-files", "--no-pager"], "systemd_unit_files.txt"),
                     (["systemctl", "list-timers", "--all", "--no-pager"], "systemd_timers.txt"),
                     (["atq"], "at_queue.txt")):
        run.run(cmd, out=out, timeout=60)
    for user, _ in user_homes():
        run.run(["crontab", "-l", "-u", user], out=f"crontab_{user}.txt", timeout=30, quiet=True)
    return {"files": len(rows)}


# ------------------------------------------------------------------ logs
_LOG_GLOBS = ["/var/log/auth.log*", "/var/log/secure*", "/var/log/syslog*", "/var/log/messages*", "/var/log/kern.log*",
              "/var/log/audit/audit.log*", "/var/log/wtmp*", "/var/log/btmp*", "/var/log/lastlog", "/var/log/cron*",
              "/var/log/dpkg.log*", "/var/log/apt/history.log*", "/var/log/apt/term.log*", "/var/log/yum.log*",
              "/var/log/dnf.log*", "/var/log/boot.log*", "/var/log/faillog", "/var/log/ufw.log*", "/var/log/sudo.log*",
              "/var/log/apache2/*.log*", "/var/log/httpd/*log*", "/var/log/nginx/*.log*", "/var/log/mysql/*.log*",
              "/var/log/samba/*", "/var/log/vsftpd.log*", "/var/log/fail2ban.log*", "/var/log/cloud-init*.log"]


def collect_logs(run):
    n = 0
    for g in _LOG_GLOBS:
        for p in sorted(glob.glob(g)):
            if os.path.isfile(p) and run.copy(p):
                n += 1
            if run.stopped():
                return {"files": n}
    days = int(run.config.get("log_days") or 7)
    run.run(["journalctl", "--since", f"-{days}d", "--no-pager", "-o", "short-iso-precise"], out="journal.txt", timeout=600)
    run.run(["journalctl", "--list-boots", "--no-pager"], out="journal_boots.txt", timeout=60)
    if not is_admin():
        run.note("Without root, auth/secure logs, btmp and the full journal aren't readable.")
    # quick highlights from auth logs
    hits = []
    pat = re.compile(r"(Failed password|Accepted (password|publickey)|Invalid user|session opened for user root|"
                     r"sudo: .*COMMAND=|useradd|usermod|groupadd|passwd\[|new user|BREAK-IN)", re.I)
    for p in sorted(glob.glob("/var/log/auth.log*") + glob.glob("/var/log/secure*")):
        if p.endswith(".gz"):
            continue
        for line in (read_text(p) or "").splitlines():
            if pat.search(line):
                hits.append({"file": p, "line": line[:500]})
    run.write_csv("auth_highlights.csv", hits, ["file", "line"])
    fails = sum(1 for h in hits if "Failed password" in h["line"] or "Invalid user" in h["line"])
    if fails > 50:
        run.flag(f"{fails} failed SSH/login attempts in the auth logs", "See logs/auth_highlights.csv", "medium")
    if sum(1 for h in hits if re.search(r"useradd|new user", h["line"])):
        run.flag("User accounts were created (auth log)", "See logs/auth_highlights.csv", "medium")
    return {"files": n, "auth_highlights": len(hits)}


# ------------------------------------------------------------------ disk artifacts
_HISTORY = [".bash_history", ".zsh_history", ".sh_history", ".history", ".python_history", ".mysql_history",
            ".psql_history", ".sqlite_history", ".lesshst", ".viminfo", ".wget-hsts", ".node_repl_history",
            ".local/share/fish/fish_history", ".rediscli_history", ".gitconfig", ".ssh/known_hosts", ".ssh/config"]


def collect_artifacts(run):
    days = 30
    hist = 0
    for user, home in user_homes():
        for h in _HISTORY:
            p = os.path.join(home, h)
            if os.path.isfile(p) and run.copy(p, os.path.join("user_files", user, h.replace("/", "_"))):
                hist += 1
                if h == ".bash_history":
                    scan_script_text(run, p, read_text(p), f"{user}'s shell history")
        bh = os.path.join(home, ".bash_history")
        if os.path.islink(bh) and os.readlink(bh) == "/dev/null":
            run.flag(f"{user}'s .bash_history is linked to /dev/null (history disabled)", bh, "medium")
    # temp folders: list everything, keep copies of small executables and scripts
    listing = []
    temp_exec = {}
    own = os.path.abspath(run.case_dir)
    for root in ("/tmp", "/var/tmp", "/dev/shm", "/run/shm"):
        for dp, dn, fn in os.walk(root):
            if run.stopped():
                break
            if os.path.abspath(dp).startswith(own):
                continue
            dn[:] = [d for d in dn if not os.path.abspath(os.path.join(dp, d)).startswith(own)]
            for f in fn + dn:
                p = os.path.join(dp, f)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                ex = bool(st.st_mode & 0o111) and stat.S_ISREG(st.st_mode)
                listing.append({"path": p, "size": st.st_size, "mode": oct(st.st_mode & 0o7777), "uid": st.st_uid,
                                "modified_utc": iso(st.st_mtime), "changed_utc": iso(st.st_ctime), "executable": ex,
                                "hidden": f.startswith(".")})
                if stat.S_ISREG(st.st_mode) and st.st_size < 10 * 1024 * 1024:
                    head = b""
                    try:
                        with open(p, "rb") as fh:
                            head = fh.read(4)
                    except OSError:
                        pass
                    if head == b"\x7fELF" or (head[:2] == b"#!" and ex):
                        run.copy(p, os.path.join("temp_executables", p.strip("/").replace("/", "_")))
                        temp_exec.setdefault(root, []).append((head == b"\x7fELF", f"{p} (modified {iso(st.st_mtime)})"))
    run.write_csv("temp_dirs_listing.csv", listing)
    for root, items in temp_exec.items():
        elf = [d for is_elf, d in items if is_elf]
        scripts = [d for is_elf, d in items if not is_elf]
        if elf:
            run.flag(f"{len(elf)} ELF executable(s) in {root}", "; ".join(elf[:6]) + (" …" if len(elf) > 6 else "")
                     + " — copies in artifacts/temp_executables", "high")
        if scripts:
            run.flag(f"{len(scripts)} executable script(s) in {root}", "; ".join(scripts[:6]) + (" …" if len(scripts) > 6 else ""),
                     "medium")
    # SUID/SGID and recently changed system files
    rc, so, _ = run.run(["find", "/", "-xdev", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-type", "f",
                         "-printf", "%m\t%u\t%TY-%Tm-%Td %TH:%TM\t%p\n"], out="suid_sgid.txt", timeout=600)
    for line in (so or "").splitlines():
        parts = line.split("\t")
        if len(parts) == 4 and not parts[3].startswith(("/usr/", "/bin/", "/sbin/", "/snap/", "/opt/", "/lib")):
            run.flag("SUID/SGID file outside system folders", line, "high")
    run.run(["find", "/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib/systemd", "/lib/systemd", "/boot",
             "-xdev", "-type", "f", "-ctime", f"-{days}", "-printf", "%TY-%Tm-%Td %TH:%TM\t%CY-%Cm-%Cd %CH:%CM\t%s\t%p\n"],
            out=f"system_files_changed_{days}d.txt", timeout=600)
    if os.path.exists("/usr/bin/dpkg"):
        run.run(["dpkg", "--verify"], out="package_verify.txt", timeout=900)
    elif os.path.exists("/usr/bin/rpm"):
        run.run(["rpm", "-Va"], out="package_verify.txt", timeout=900)
    for f in ("/etc/passwd", "/etc/group", "/etc/hosts", "/etc/ssh/sshd_config"):
        if os.path.exists(f):
            run.copy(f, os.path.join("etc", os.path.basename(f)))
    return {"history_files": hist, "temp_entries": len(listing)}


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
