"""Windows live-response collectors (PowerShell/CIM, built-in tools, the registry, raw NTFS reads)."""

import glob
import json
import os
import re
import xml.etree.ElementTree as ET

from ..core import PLATFORM, human_size, is_admin, iso
from .common import (HashCache, collect_browsers, file_times, first_exe, recent, suspicious_cmd, suspicious_path,
                     user_homes)

if PLATFORM == "windows":
    import winreg
else:  # lets the module import on other systems (tests, linting)
    winreg = None

SYSROOT = os.environ.get("SystemRoot", r"C:\Windows")
SYSDRIVE = os.environ.get("SystemDrive", "C:") + "\\"


def _ps_json(run, script, name=None, timeout=300):
    """Run PowerShell that ends in ConvertTo-Json and return a list of dicts."""
    rc, so, se = run.ps(script + " | ConvertTo-Json -Depth 4 -Compress", timeout=timeout, quiet=True)
    run.say(f"$ powershell: {script[:110]}{'...' if len(script) > 110 else ''}")
    so = (so or "").strip()
    if not so:
        if se and se.strip():
            run.say(f"  {se.strip().splitlines()[0][:200]}", "warn")
        return []
    try:
        data = json.loads(so)
    except json.JSONDecodeError:
        run.say("  couldn't parse PowerShell output", "warn")
        if name:
            run.write_text(name + ".raw.txt", so)
        return []
    if isinstance(data, dict):
        data = [data]
    return data


def _cim_time(v):
    """CIM/JSON dates come back as '/Date(1700000000000)/' or ISO strings."""
    if not v:
        return ""
    if isinstance(v, dict) and "DateTime" in v:
        v = v.get("value") or v.get("DateTime")
    m = re.search(r"/Date\((-?\d+)", str(v))
    if m:
        return iso(int(m.group(1)) / 1000)
    return str(v)


# ------------------------------------------------------------------ processes
_SYSTEM_PROCS = {
    "smss.exe": (r"\system32\smss.exe", {"system", "smss.exe"}),
    "csrss.exe": (r"\system32\csrss.exe", None),
    "wininit.exe": (r"\system32\wininit.exe", None),
    "winlogon.exe": (r"\system32\winlogon.exe", None),
    "services.exe": (r"\system32\services.exe", {"wininit.exe"}),
    "lsass.exe": (r"\system32\lsass.exe", {"wininit.exe"}),
    "svchost.exe": (r"\system32\svchost.exe", {"services.exe", "msmpeng.exe"}),
    "explorer.exe": (r"\explorer.exe", None),
    "taskhostw.exe": (r"\system32\taskhostw.exe", None),
    "spoolsv.exe": (r"\system32\spoolsv.exe", {"services.exe"}),
    "lsm.exe": (r"\system32\lsm.exe", None),
    "dllhost.exe": (r"\system32\dllhost.exe", None),
    "conhost.exe": (r"\system32\conhost.exe", None),
    "rundll32.exe": (None, None),
}
_OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe",
           "visio.exe", "acrord32.exe", "acrobat.exe", "foxitpdfreader.exe"}
_SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
           "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "msbuild.exe", "installutil.exe"}
_NO_PATH_OK = {"system", "registry", "system idle process", "idle", "memory compression", "secure system",
               "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "lsaiso.exe", "vmmem", "vmmemws"}


def _signatures(run, paths):
    if not paths:
        return {}
    import tempfile
    # the path list goes through a temp file (outside the case) so a long list can't hit the command-line limit
    fd, lst = tempfile.mkstemp(prefix="ltriage_", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(paths))
    try:
        q = lst.replace("'", "''")
        data = _ps_json(run, f"Get-Content -LiteralPath '{q}' -Encoding UTF8 | Where-Object {{ $_ }} | ForEach-Object {{ "
                             "$s = Get-AuthenticodeSignature -LiteralPath $_ -ErrorAction SilentlyContinue; "
                             "[pscustomobject]@{Path=$_; Status=[string]$s.Status; Signer=$(if ($s.SignerCertificate) "
                             "{$s.SignerCertificate.Subject} else {''})} }", timeout=600)
    finally:
        try:
            os.remove(lst)
        except OSError:
            pass
    return {d.get("Path", "").lower(): (d.get("Status", ""), d.get("Signer", "")) for d in data}


def collect_processes(run):
    procs = _ps_json(run, "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,"
                          "CommandLine,CreationDate,SessionId,ThreadCount,HandleCount,WorkingSetSize", "processes")
    owners = {}
    if is_admin():
        for d in _ps_json(run, "Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Select-Object Id,UserName"):
            owners[d.get("Id")] = d.get("UserName") or ""
    hc = HashCache()
    paths = sorted({p.get("ExecutablePath") for p in procs if p.get("ExecutablePath")})
    sigs = _signatures(run, paths)
    by_pid = {p.get("ProcessId"): p for p in procs}
    rows = []
    for p in procs:
        exe = p.get("ExecutablePath") or ""
        name = (p.get("Name") or "").lower()
        parent = by_pid.get(p.get("ParentProcessId"))
        pname = (parent.get("Name") or "").lower() if parent else ""
        st, signer = sigs.get(exe.lower(), ("", ""))
        row = {"pid": p.get("ProcessId"), "ppid": p.get("ParentProcessId"), "name": p.get("Name"),
               "parent_name": parent.get("Name") if parent else "", "user": owners.get(p.get("ProcessId"), ""),
               "created_utc": _cim_time(p.get("CreationDate")), "session": p.get("SessionId"), "exe": exe,
               "cmdline": p.get("CommandLine") or "", "signature": st, "signer": signer, "sha256": hc.get(exe),
               "threads": p.get("ThreadCount"), "handles": p.get("HandleCount"), "working_set": p.get("WorkingSetSize")}
        rows.append(row)
        label = f"{p.get('Name')} ({p.get('ProcessId')})"
        why = suspicious_path(exe)
        if why:
            run.flag(f"Process {label} {why}", row["cmdline"] or exe, "high")
        cw = suspicious_cmd(row["cmdline"])
        if cw:
            run.flag(f"Process {label}: {cw}", row["cmdline"][:400], "high")
        if name in _SYSTEM_PROCS and exe:
            want, parents = _SYSTEM_PROCS[name]
            ok_paths = {(SYSROOT + want).lower(), (SYSROOT + want.replace("system32", "syswow64")).lower()} if want else set()
            if want and exe.lower() not in ok_paths:
                run.flag(f"{p.get('Name')} ({p.get('ProcessId')}) is running from an unexpected path", exe, "high")
            if parents and parent and pname not in parents:
                run.flag(f"{p.get('Name')} ({p.get('ProcessId')}) has an unusual parent: {parent.get('Name')}",
                         f"parent pid {p.get('ParentProcessId')}", "medium")
        if name in _SHELLS and pname in _OFFICE:
            run.flag(f"{parent.get('Name')} started {p.get('Name')} ({p.get('ProcessId')})",
                     row["cmdline"][:400], "high")
        if st and st not in ("Valid",) and why:
            run.flag(f"Unsigned or invalid signature: {label}", f"{exe} — {st}", "high")
        if not exe and name not in _NO_PATH_OK and is_admin() and p.get("ProcessId", 0) > 4:
            run.flag(f"Process {label} has no executable path", row["cmdline"][:300], "low")
    run.write_csv("processes.csv", rows)
    # tree
    kids = {}
    for r in rows:
        kids.setdefault(r["ppid"], []).append(r)
    pids = {r["pid"] for r in rows}
    out = []

    def walk(r, d):
        out.append(f"{'  ' * d}{r['pid']:>6}  {r['name']}  {r['cmdline'][:180]}")
        for c in kids.get(r["pid"], []):
            if d < 40 and c["pid"] != r["pid"]:
                walk(c, d + 1)
    for r in rows:
        if r["ppid"] not in pids or r["ppid"] == r["pid"]:
            walk(r, 0)
    run.write_text("process_tree.txt", "\n".join(out))
    run.run(["tasklist", "/v", "/fo", "csv"], out="tasklist_verbose.csv", timeout=120)
    run.run(["tasklist", "/svc", "/fo", "csv"], out="tasklist_services.csv", timeout=120)
    if not is_admin():
        run.note("Without administrator rights, other users' processes have no path, owner or command line.")
    return {"count": len(rows)}


# ------------------------------------------------------------------ network
def collect_network(run):
    names = {d.get("Id"): (d.get("ProcessName"), d.get("Path")) for d in
             _ps_json(run, "Get-Process -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,Path")}
    _STATES = {1: "Closed", 2: "Listen", 3: "SynSent", 4: "SynReceived", 5: "Established", 6: "FinWait1", 7: "FinWait2",
               8: "CloseWait", 9: "Closing", 10: "LastAck", 11: "TimeWait", 12: "DeleteTCB", 100: "Bound"}
    rows = []
    for c in _ps_json(run, "Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,"
                           "RemoteAddress,RemotePort,State,OwningProcess,CreationTime"):
        pid = c.get("OwningProcess")
        nm, path = names.get(pid, ("", ""))
        state = c.get("State")
        rows.append({"proto": "TCP", "local_address": c.get("LocalAddress"), "local_port": c.get("LocalPort"),
                     "remote_address": c.get("RemoteAddress"), "remote_port": c.get("RemotePort"),
                     "state": _STATES.get(state, state), "pid": pid, "process": nm, "exe": path or "",
                     "created_utc": _cim_time(c.get("CreationTime"))})
    for c in _ps_json(run, "Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,"
                           "OwningProcess,CreationTime"):
        pid = c.get("OwningProcess")
        nm, path = names.get(pid, ("", ""))
        rows.append({"proto": "UDP", "local_address": c.get("LocalAddress"), "local_port": c.get("LocalPort"),
                     "remote_address": "", "remote_port": "", "state": "", "pid": pid, "process": nm,
                     "exe": path or "", "created_utc": _cim_time(c.get("CreationTime"))})
    run.write_csv("connections.csv", rows)
    for r in rows:
        why = suspicious_path(r["exe"])
        if why and r["state"] in ("Established", "Listen", ""):
            run.flag(f"Network activity from {r['process']} ({r['pid']}), which {why}",
                     f"{r['proto']} {r['local_address']}:{r['local_port']} -> {r['remote_address']}:{r['remote_port']} {r['state']}", "high")
    dns = _ps_json(run, "Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry,Name,Data,Type,TimeToLive,Status")
    run.write_csv("dns_cache.csv", dns)
    for cmd, out in ((["netstat", "-anob"] if is_admin() else ["netstat", "-ano"], "netstat.txt"),
                     (["ipconfig", "/all"], "ipconfig.txt"), (["ipconfig", "/displaydns"], "ipconfig_displaydns.txt"),
                     (["arp", "-a"], "arp.txt"), (["route", "print"], "route.txt"), (["net", "use"], "net_use.txt"),
                     (["net", "share"], "net_share.txt"), (["net", "session"], "net_session.txt"),
                     (["netsh", "advfirewall", "show", "allprofiles"], "firewall_profiles.txt"),
                     (["netsh", "advfirewall", "firewall", "show", "rule", "name=all", "verbose"], "firewall_rules.txt"),
                     (["netsh", "wlan", "show", "profiles"], "wlan_profiles.txt"), (["netsh", "winhttp", "show", "proxy"], "winhttp_proxy.txt"),
                     (["nbtstat", "-c"], "nbtstat_cache.txt")):
        run.run(cmd, out=out, timeout=180)
    run.ps("Get-SmbConnection -ErrorAction SilentlyContinue | Format-List *", out="smb_connections.txt")
    run.ps("Get-NetNeighbor -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String -Width 300", out="net_neighbors.txt")
    hosts = os.path.join(SYSROOT, "System32", "drivers", "etc", "hosts")
    if os.path.exists(hosts):
        run.copy(hosts, os.path.join("etc", "hosts"))
        for line in open(hosts, encoding="utf-8", errors="replace"):
            s = line.strip()
            if s and not s.startswith("#") and not re.match(r"^(127\.0\.0\.1|::1)\s+localhost\s*$", s):
                run.flag("Hosts file has custom entries", s[:200], "low")
                break
    est = sum(1 for r in rows if r["state"] == "Established")
    lis = sum(1 for r in rows if r["state"] == "Listen")
    run.say(f"{len(rows)} endpoints ({est} established, {lis} listening), {len(dns)} DNS cache entries")
    return {"endpoints": len(rows), "established": est, "listening": lis, "dns_cache": len(dns)}


# ------------------------------------------------------------------ registry helpers
def _reg_values(hive, path, view=0):
    out = []
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as k:
            i = 0
            while True:
                try:
                    n, v, t = winreg.EnumValue(k, i)
                except OSError:
                    break
                out.append((n, v, t))
                i += 1
    except OSError:
        pass
    return out


def _reg_subkeys(hive, path, view=0):
    out = []
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as k:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


def _reg_get(hive, path, name, view=0):
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def _key_time(hive, path, view=0):
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as k:
            ft = winreg.QueryInfoKey(k)[2]
            return iso(ft / 1e7 - 11644473600) if ft else ""
    except OSError:
        return ""


# ------------------------------------------------------------------ system
def collect_system(run):
    run.run(["systeminfo", "/fo", "list"], out="systeminfo.txt", timeout=300)
    run.ps("Get-CimInstance Win32_OperatingSystem | Format-List *", out="os.txt")
    run.ps("Get-CimInstance Win32_ComputerSystem | Format-List *", out="computer.txt")
    run.ps("Get-HotFix | Sort-Object InstalledOn | Format-Table -AutoSize | Out-String -Width 300", out="hotfixes.txt")
    run.ps("Get-Volume | Format-Table -AutoSize | Out-String -Width 300", out="volumes.txt")
    run.ps("Get-PSDrive -PSProvider FileSystem | Format-Table -AutoSize | Out-String -Width 300", out="drives.txt")
    run.run(["w32tm", "/query", "/status"], out="time_status.txt", timeout=60)
    run.run(["tzutil", "/g"], out="timezone.txt", timeout=30)
    run.run(["cmd", "/c", "set"], out="environment.txt", timeout=30)
    run.run(["whoami", "/all"], out="collector_whoami.txt", timeout=30)
    if is_admin():
        run.run(["manage-bde", "-status"], out="bitlocker.txt", timeout=120)
    run.ps("Get-MpComputerStatus -ErrorAction SilentlyContinue | Format-List *", out="defender_status.txt")
    run.ps("Get-MpPreference -ErrorAction SilentlyContinue | Format-List Exclusion*,Disable*", out="defender_exclusions.txt")
    det = _ps_json(run, "Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object InitialDetectionTime,"
                        "ThreatID,ProcessName,DomainUser,ActionSuccess,@{n='Resources';e={$_.Resources -join '; '}}")
    run.write_csv("defender_detections.csv", det)
    for d in det:
        t = _cim_time(d.get("InitialDetectionTime"))
        run.flag("Microsoft Defender detection", f"{t} {d.get('ProcessName') or ''} {d.get('Resources') or ''}"[:400], "high")
    excl = _ps_json(run, "Get-MpPreference -ErrorAction SilentlyContinue | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension")
    for e in excl:
        for k in ("ExclusionPath", "ExclusionProcess", "ExclusionExtension"):
            v = e.get(k)
            if v and not (isinstance(v, list) and any("N/A" in str(x) for x in v)):
                run.flag(f"Defender {k}", str(v)[:300], "medium")
    # installed software
    sw = []
    for hive, hn in ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")):
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            base = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
            for sk in _reg_subkeys(hive, base, view):
                p = base + "\\" + sk
                name = _reg_get(hive, p, "DisplayName", view)
                if not name:
                    continue
                sw.append({"name": name, "version": _reg_get(hive, p, "DisplayVersion", view) or "",
                           "publisher": _reg_get(hive, p, "Publisher", view) or "",
                           "install_date": _reg_get(hive, p, "InstallDate", view) or "",
                           "location": _reg_get(hive, p, "InstallLocation", view) or "",
                           "key_written_utc": _key_time(hive, p, view), "hive": hn})
    uniq = {(s["name"], s["version"]): s for s in sw}
    run.write_csv("installed_software.csv", sorted(uniq.values(), key=lambda s: s["key_written_utc"], reverse=True))
    for s in uniq.values():
        if re.search(r"(?i)anydesk|teamviewer|screenconnect|connectwise|atera|splashtop|rustdesk|ngrok|"
                     r"supremo|netsupport|remote ?utilities|meshagent|tightvnc|ultravnc|realvnc|zoho assist|logmein", s["name"]):
            run.flag(f"Remote access software installed: {s['name']}", f"key written {s['key_written_utc']}", "medium")
    # USB storage history
    usb = []
    base = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    for dev in _reg_subkeys(winreg.HKEY_LOCAL_MACHINE, base):
        for serial in _reg_subkeys(winreg.HKEY_LOCAL_MACHINE, base + "\\" + dev):
            p = base + "\\" + dev + "\\" + serial
            usb.append({"device": dev, "serial": serial,
                        "friendly_name": _reg_get(winreg.HKEY_LOCAL_MACHINE, p, "FriendlyName") or "",
                        "key_written_utc": _key_time(winreg.HKEY_LOCAL_MACHINE, p)})
    run.write_csv("usb_storage_history.csv", usb)
    return {"software": len(uniq), "usb_devices": len(usb), "defender_detections": len(det)}


# ------------------------------------------------------------------ users
def collect_users(run):
    users = _ps_json(run, "Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name,Enabled,SID,LastLogon,"
                          "PasswordLastSet,PasswordRequired,Description,PrincipalSource")
    for u in users:
        for k in ("LastLogon", "PasswordLastSet"):
            u[k] = _cim_time(u.get(k))
        if isinstance(u.get("SID"), dict):
            u["SID"] = u["SID"].get("Value", "")
    run.write_csv("local_users.csv", users)
    admins = _ps_json(run, "Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction SilentlyContinue | "
                           "Select-Object Name,ObjectClass,PrincipalSource")
    run.write_csv("administrators.csv", admins)
    profiles = _ps_json(run, "Get-CimInstance Win32_UserProfile | Select-Object SID,LocalPath,LastUseTime,Special,Loaded")
    for p in profiles:
        p["LastUseTime"] = _cim_time(p.get("LastUseTime"))
    run.write_csv("profiles.csv", profiles)
    for cmd, out in ((["net", "user"], "net_user.txt"), (["net", "localgroup", "administrators"], "net_admins.txt"),
                     (["net", "localgroup"], "net_localgroups.txt"), (["query", "user"], "logged_on_sessions.txt"),
                     (["net", "accounts"], "password_policy.txt"), (["cmdkey", "/list"], "stored_credentials_list.txt")):
        run.run(cmd, out=out, timeout=60)
    for u in users:
        if u.get("Enabled") and u.get("PasswordRequired") is False:
            run.flag(f"Enabled account {u.get('Name')} doesn't require a password", "", "medium")
        sid = str(u.get("SID") or "")
        if u.get("Enabled") and sid.endswith("-500"):
            run.flag("Built-in Administrator account is enabled", u.get("Name", ""), "low")
    return {"local_users": len(users), "admins": len(admins), "profiles": len(profiles)}


# ------------------------------------------------------------------ persistence
_RUN_KEYS = [r"Software\Microsoft\Windows\CurrentVersion\Run", r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
             r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx", r"Software\Microsoft\Windows\CurrentVersion\RunServices",
             r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
             r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
             r"Software\Microsoft\Windows NT\CurrentVersion\Windows",   # Load / Run values
             r"Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run",
             r"Software\Microsoft\Command Processor"]                 # AutoRun


def _hku_users():
    out = []
    for sid in _reg_subkeys(winreg.HKEY_USERS, ""):
        if sid.startswith("S-1-5-21-") and not sid.endswith("_Classes"):
            out.append(sid)
    return out


def collect_persistence(run):
    hc = HashCache()
    rows = []

    def add(location, name, command, key_time=""):
        exe = first_exe(str(command)) if command else ""
        ft = file_times(exe) if exe else {}
        row = {"location": location, "name": name, "command": command, "image": exe, "image_exists": bool(ft),
               "image_modified_utc": ft.get("modified_utc", ""), "image_created_utc": ft.get("created_utc", ""),
               "sha256": hc.get(exe) if ft else "", "key_written_utc": key_time,
               "suspicious": "; ".join(x for x in (suspicious_path(exe), suspicious_cmd(str(command))) if x)}
        rows.append(row)
        if row["suspicious"]:
            run.flag(f"Autostart {name or location}: {row['suspicious']}", f"{location} -> {str(command)[:300]}", "high")
        elif ft and recent(ft.get("_ctime"), 30) and SYSROOT.lower() not in exe.lower():
            run.flag(f"Autostart {name or location} points to a file created in the last 30 days", f"{exe}", "medium")
        return row

    hives = [(winreg.HKEY_LOCAL_MACHINE, "HKLM")] + [(winreg.HKEY_USERS, f"HKU\\{sid}") for sid in _hku_users()]
    for hive, hn in hives:
        for key in _RUN_KEYS:
            path = key if hn == "HKLM" else f"{hn[4:]}\\{key}"
            for view in ((winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY) if hn == "HKLM" else (0,)):
                kt = _key_time(hive, path, view)
                for n, v, t in _reg_values(hive, path, view):
                    if key.endswith("\\Windows") and n not in ("Load", "Run"):
                        continue
                    if key.endswith("Command Processor") and n != "AutoRun":
                        continue
                    if v in ("", None):
                        continue
                    add(f"{hn}\\{key}" + (" (32-bit)" if view == winreg.KEY_WOW64_32KEY else ""), n, v, kt)
    # Winlogon, IFEO, AppInit, LSA, BootExecute, Active Setup
    wl = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    for n in ("Shell", "Userinit", "Taskman", "AppSetup"):
        v = _reg_get(winreg.HKEY_LOCAL_MACHINE, wl, n)
        if v:
            add(f"HKLM\\{wl}", n, v, _key_time(winreg.HKEY_LOCAL_MACHINE, wl))
            norm = str(v).lower().replace(" ", "").rstrip(",")
            if (n == "Shell" and norm != "explorer.exe") or (n == "Userinit" and not norm.endswith("system32\\userinit.exe")):
                run.flag(f"Winlogon {n} has been changed", str(v), "high")
    ifeo = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    for sk in _reg_subkeys(winreg.HKEY_LOCAL_MACHINE, ifeo):
        dbg = _reg_get(winreg.HKEY_LOCAL_MACHINE, ifeo + "\\" + sk, "Debugger")
        if dbg:
            add(f"HKLM\\{ifeo}\\{sk}", "Debugger", dbg, _key_time(winreg.HKEY_LOCAL_MACHINE, ifeo + "\\" + sk))
            run.flag(f"Image File Execution Options debugger set for {sk}", str(dbg), "high")
    spe = r"Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
    for sk in _reg_subkeys(winreg.HKEY_LOCAL_MACHINE, spe):
        mp = _reg_get(winreg.HKEY_LOCAL_MACHINE, spe + "\\" + sk, "MonitorProcess")
        if mp:
            add(f"HKLM\\{spe}\\{sk}", "MonitorProcess", mp)
            run.flag(f"SilentProcessExit monitor for {sk}", str(mp), "high")
    for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        w = r"Software\Microsoft\Windows NT\CurrentVersion\Windows"
        dlls = _reg_get(winreg.HKEY_LOCAL_MACHINE, w, "AppInit_DLLs", view)
        if dlls:
            add(f"HKLM\\{w}", "AppInit_DLLs", dlls)
            run.flag("AppInit_DLLs is set", str(dlls), "high")
    lsa = r"SYSTEM\CurrentControlSet\Control\Lsa"
    for n in ("Authentication Packages", "Security Packages", "Notification Packages"):
        v = _reg_get(winreg.HKEY_LOCAL_MACHINE, lsa, n)
        if v:
            rows.append({"location": f"HKLM\\{lsa}", "name": n, "command": " ".join(v) if isinstance(v, list) else v})
    sm = r"SYSTEM\CurrentControlSet\Control\Session Manager"
    be = _reg_get(winreg.HKEY_LOCAL_MACHINE, sm, "BootExecute")
    if be:
        val = " ".join(be) if isinstance(be, list) else str(be)
        rows.append({"location": f"HKLM\\{sm}", "name": "BootExecute", "command": val})
        if val.strip().lower() != "autocheck autochk *":
            run.flag("BootExecute has extra entries", val, "medium")
    act = r"Software\Microsoft\Active Setup\Installed Components"
    for sk in _reg_subkeys(winreg.HKEY_LOCAL_MACHINE, act):
        sp = _reg_get(winreg.HKEY_LOCAL_MACHINE, act + "\\" + sk, "StubPath")
        if sp:
            add(f"HKLM\\{act}\\{sk}", "StubPath", sp, _key_time(winreg.HKEY_LOCAL_MACHINE, act + "\\" + sk))
    # startup folders
    folders = [os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), r"Microsoft\Windows\Start Menu\Programs\StartUp")]
    for user, home in user_homes():
        folders.append(os.path.join(home, r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"))
    for f in folders:
        for p in glob.glob(os.path.join(f, "*")):
            if os.path.basename(p).lower() == "desktop.ini":
                continue
            add(f"Startup folder {f}", os.path.basename(p), p)
            run.copy(p, os.path.join("startup_folders", os.path.basename(os.path.dirname(os.path.dirname(f)) or "x"),
                                     os.path.basename(p)))
    # services
    svcs = _ps_json(run, "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,"
                         "StartName,ProcessId,ServiceType")
    svc_rows = []
    for s in svcs:
        exe = first_exe(s.get("PathName") or "")
        ft = file_times(exe) if exe else {}
        why = "; ".join(x for x in (suspicious_path(exe), suspicious_cmd(s.get("PathName") or "")) if x)
        svc_rows.append({**{k: s.get(k) for k in ("Name", "DisplayName", "State", "StartMode", "PathName", "StartName",
                                                  "ProcessId", "ServiceType")},
                         "image": exe, "image_created_utc": ft.get("created_utc", ""),
                         "image_modified_utc": ft.get("modified_utc", ""), "sha256": hc.get(exe) if ft else "",
                         "suspicious": why})
        if why:
            run.flag(f"Service {s.get('Name')}: {why}", s.get("PathName") or "", "high")
        elif ft and recent(ft.get("_ctime"), 30) and s.get("StartMode") == "Auto" and SYSROOT.lower() not in exe.lower():
            run.flag(f"Auto-start service {s.get('Name')} binary created in the last 30 days", exe, "medium")
    run.write_csv("services.csv", svc_rows)
    # scheduled tasks: list + XML definitions
    run.run(["schtasks", "/query", "/fo", "csv", "/v"], out="scheduled_tasks.csv", timeout=300)
    tasks_dir = os.path.join(SYSROOT, "System32", "Tasks")
    task_rows = []
    for dp, _, fn in os.walk(tasks_dir):
        for f in fn:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, tasks_dir)
            run.copy(p, os.path.join("tasks", rel))
            try:
                with open(p, "rb") as fh:
                    raw = fh.read()
                root = ET.fromstring(raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw)
            except Exception:
                continue
            ns = {"t": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
            pre = "t:" if ns else ""
            for ex in root.iter(("{%s}Exec" % ns["t"]) if ns else "Exec"):
                cmd = (ex.findtext(f"{pre}Command", default="", namespaces=ns) or "").strip()
                args = (ex.findtext(f"{pre}Arguments", default="", namespaces=ns) or "").strip()
                author = root.findtext(f"{pre}RegistrationInfo/{pre}Author", default="", namespaces=ns)
                date = root.findtext(f"{pre}RegistrationInfo/{pre}Date", default="", namespaces=ns)
                full = f"{cmd} {args}".strip()
                exe = first_exe(cmd)
                why = "; ".join(x for x in (suspicious_path(exe), suspicious_cmd(full)) if x)
                ft = file_times(p)
                task_rows.append({"task": "\\" + rel, "command": cmd, "arguments": args, "author": author,
                                  "registered": date, "task_file_modified_utc": ft.get("modified_utc", ""),
                                  "image": exe, "suspicious": why})
                if why:
                    run.flag(f"Scheduled task \\{rel}: {why}", full[:300], "high")
                elif recent(ft.get("_mtime"), 30) and not rel.lower().startswith("microsoft\\"):
                    run.flag(f"Scheduled task \\{rel} created or changed in the last 30 days", full[:300], "medium")
    run.write_csv("scheduled_task_actions.csv", task_rows)
    if not task_rows and not is_admin():
        run.note("Scheduled task definitions (System32\\Tasks) need administrator rights.")
    # WMI event subscriptions
    wmi = {}
    for cls in ("__EventFilter", "__EventConsumer", "__FilterToConsumerBinding"):
        wmi[cls] = _ps_json(run, f"Get-CimInstance -Namespace root/subscription -ClassName {cls} -ErrorAction SilentlyContinue | "
                                 "Select-Object * -ExcludeProperty CimClass,CimInstanceProperties,CimSystemProperties")
    run.write_json("wmi_subscriptions.json", wmi)
    for c in wmi["__EventConsumer"]:
        nm = c.get("Name") or ""
        if nm in ("SCM Event Log Consumer",):
            continue
        detail = c.get("CommandLineTemplate") or c.get("ScriptText") or c.get("ExecutablePath") or json.dumps(c)[:300]
        run.flag(f"WMI event consumer '{nm}' (fileless persistence)", str(detail)[:400], "high")
    run.write_csv("autoruns.csv", rows, ["location", "name", "command", "image", "image_exists", "image_created_utc",
                                         "image_modified_utc", "sha256", "key_written_utc", "suspicious"])
    return {"autoruns": len(rows), "services": len(svc_rows), "task_actions": len(task_rows),
            "wmi_consumers": len(wmi["__EventConsumer"])}


# ------------------------------------------------------------------ logs
_CHANNELS = ["System", "Application", "Security", "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational",
             "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-TaskScheduler/Operational",
             "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
             "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
             "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", "Microsoft-Windows-Windows Defender/Operational",
             "Microsoft-Windows-WMI-Activity/Operational", "Microsoft-Windows-Bits-Client/Operational",
             "Microsoft-Windows-WinRM/Operational", "Microsoft-Windows-SMBServer/Security", "Microsoft-Windows-SMBClient/Security",
             "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", "Microsoft-Windows-CodeIntegrity/Operational",
             "Microsoft-Windows-AppLocker/EXE and DLL", "Microsoft-Windows-DNS-Client/Operational",
             "Microsoft-Windows-NTLM/Operational", "Microsoft-Windows-Shell-Core/Operational",
             "Microsoft-Windows-User Profile Service/Operational", "OpenSSH/Operational"]

_KEY_EVENTS = [("Security", [1102, 4720, 4722, 4724, 4728, 4732, 4756, 4698, 4697, 4719, 4625, 4648, 4672]),
               ("Security", [4624]),
               ("System", [104, 7045, 7040, 6005, 6006, 1074]),
               ("Microsoft-Windows-PowerShell/Operational", [4104]),
               ("Microsoft-Windows-Windows Defender/Operational", [1116, 1117, 5001, 5007]),
               ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", [21, 24, 25]),
               ("Microsoft-Windows-TaskScheduler/Operational", [106, 140, 141])]


def collect_logs(run):
    n = 0
    for ch in _CHANNELS:
        if run.stopped():
            break
        dest = run.path("logs", "evtx", ch.replace("/", "%4") + ".evtx")
        rc, so, se = run.run(["wevtutil", "epl", ch, dest, "/ow:true"], timeout=900, quiet=True)
        if rc == 0 and os.path.exists(dest):
            n += 1
            run.say(f"  exported {ch} ({human_size(os.path.getsize(dest))})")
        elif ch == "Security" and not is_admin():
            run.note("The Security log needs administrator rights.")
    days = int(run.config.get("log_days") or 7)
    events = []
    for log, ids in _KEY_EVENTS:
        idlist = ",".join(str(i) for i in ids)
        cap = 400 if 4624 in ids else 1500
        filt = (f"@{{LogName='{log}'; Id={idlist}; StartTime=(Get-Date).AddDays(-{days})}}")
        events += [{"time_utc": _cim_time(e.get("TimeCreated")), "log": log, "event_id": e.get("Id"),
                    "provider": e.get("ProviderName"), "message": (e.get("Message") or "").replace("\r", "")[:1500]}
                   for e in _ps_json(run, f"Get-WinEvent -FilterHashtable {filt} -MaxEvents {cap} -ErrorAction SilentlyContinue | "
                                          "Select-Object TimeCreated,Id,ProviderName,@{n='Message';e={$_.Message}}", timeout=600)]
    events.sort(key=lambda e: e["time_utc"])
    run.write_csv("key_events.csv", events)
    ids = [e["event_id"] for e in events]
    sev = {1102: ("Security log was cleared", "high"), 104: ("A system log was cleared", "high"),
           7045: ("New service installed", "medium"), 4720: ("User account created", "medium"),
           4732: ("Member added to a local group", "medium"), 4728: ("Member added to a global group", "medium"),
           4697: ("Service installed (Security log)", "medium"), 4698: ("Scheduled task created", "medium"),
           1116: ("Defender detected malware", "high"), 5001: ("Defender real-time protection disabled", "high"),
           4719: ("Audit policy changed", "medium")}
    for eid, (what, level) in sev.items():
        c = ids.count(eid)
        if c:
            first = next(e for e in events if e["event_id"] == eid)
            run.flag(f"{what} ({c}x in the last {days} days, event {eid})", f"first: {first['time_utc']} — {first['message'][:200]}", level)
    fails = ids.count(4625)
    if fails >= 20:
        run.flag(f"{fails} failed logons in the last {days} days (4625)", "See logs/key_events.csv", "medium")
    enc = [e for e in events if e["event_id"] == 4104 and suspicious_cmd(e["message"])]
    if enc:
        run.flag(f"{len(enc)} suspicious PowerShell script blocks (4104)", enc[0]["message"][:300], "high")
    return {"channels": n, "key_events": len(events)}


# ------------------------------------------------------------------ disk artifacts (registry, amcache, prefetch...)
def collect_artifacts(run):
    cfg = os.path.join(SYSROOT, "System32", "config")
    got = 0
    if not is_admin():
        run.note("Registry hives, Amcache, SRUM and the $MFT are locked by Windows and need administrator rights.")

    def grab(src, rel):
        nonlocal got
        if os.path.exists(src) and run.copy(src, rel):
            got += 1

    for hive in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"):
        for ext in ("", ".LOG1", ".LOG2"):
            grab(os.path.join(cfg, hive + ext), os.path.join("registry", "system", hive + ext))
    for user, home in user_homes():
        for ext in ("", ".LOG1", ".LOG2"):
            grab(os.path.join(home, "NTUSER.DAT" + ext), os.path.join("registry", user, "NTUSER.DAT" + ext))
            grab(os.path.join(home, r"AppData\Local\Microsoft\Windows\UsrClass.dat" + ext),
                 os.path.join("registry", user, "UsrClass.dat" + ext))
        ps = os.path.join(home, r"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
        if os.path.exists(ps):
            grab(ps, os.path.join("powershell_history", user, "ConsoleHost_history.txt"))
            try:
                text = open(ps, encoding="utf-8", errors="replace").read()
                for line in text.splitlines():
                    why = suspicious_cmd(line)
                    if why:
                        run.flag(f"{user}'s PowerShell history: {why}", line[:300], "high")
                        break
            except OSError:
                pass
        rec = os.path.join(home, r"AppData\Roaming\Microsoft\Windows\Recent")
        run.copy_tree(rec, os.path.join("recent", user), patterns=["*.lnk", "*.automaticDestinations-ms",
                                                                   "*.customDestinations-ms"], max_files=3000)
        for db in glob.glob(os.path.join(home, r"AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db")):
            for f in (db, db + "-wal"):
                grab(f, os.path.join("timeline", user, os.path.basename(os.path.dirname(db)), os.path.basename(f)))
    am = os.path.join(SYSROOT, "AppCompat", "Programs")
    for ext in ("", ".LOG1", ".LOG2"):
        grab(os.path.join(am, "Amcache.hve" + ext), os.path.join("amcache", "Amcache.hve" + ext))
    n_pf = run.copy_tree(os.path.join(SYSROOT, "Prefetch"), "prefetch", patterns=["*.pf"])
    if n_pf == 0 and is_admin():
        run.note("No Prefetch files (Prefetch may be disabled, which is normal on some SSD/server setups).")
    sru = os.path.join(SYSROOT, "System32", "sru")
    grab(os.path.join(sru, "SRUDB.dat"), os.path.join("srum", "SRUDB.dat"))
    # Recycle Bin metadata ($I files: original path, size and deletion time)
    rb = []
    for p in glob.glob(os.path.join(SYSDRIVE, "$Recycle.Bin", "*", "$I*")):
        d = run.copy(p, os.path.join("recycle_bin", os.path.basename(os.path.dirname(p)), os.path.basename(p)))
        if d:
            rb.append(_parse_recycle_i(p))
    run.write_csv("recycle_bin.csv", [r for r in rb if r])
    # $MFT: a full file-system timeline source
    if is_admin():
        from ..ntfsraw import NTFSVolume
        dest = run.path("artifacts", "ntfs", "$MFT")
        try:
            with open("\\\\.\\" + SYSDRIVE[:2], "rb", buffering=0) as fh:
                vol = NTFSVolume(fh)
                size, it = vol.open_data(0)
                run.say(f"Copying $MFT ({human_size(size)}) straight from the volume")
                with open(dest, "wb") as out:
                    for chunk in it(run.stopped):
                        out.write(chunk)
            run.footprint("copy", source=SYSDRIVE + "$MFT", dest=run.rel(dest), method="raw-ntfs")
            got += 1
        except Exception as e:
            run.note(f"Couldn't copy $MFT: {e}")
    return {"files": got, "prefetch": n_pf, "recycle_bin_items": len(rb)}


def _parse_recycle_i(path):
    import struct
    try:
        with open(path, "rb") as fh:
            b = fh.read()
        ver, size, ft = struct.unpack_from("<QQQ", b, 0)
        if ver == 2:
            n = struct.unpack_from("<I", b, 24)[0]
            name = b[28:28 + n * 2].decode("utf-16-le", "replace").rstrip("\x00")
        else:
            name = b[24:24 + 520].decode("utf-16-le", "replace").split("\x00")[0]
        return {"i_file": path, "original_path": name, "size": size,
                "deleted_utc": iso(ft / 1e7 - 11644473600) if ft else ""}
    except Exception:
        return None


# ------------------------------------------------------------------ memory-adjacent files
MEMFILES = ["pagefile.sys", "swapfile.sys", "hiberfil.sys"]


def memfile_sizes():
    out = {}
    for f in MEMFILES:
        p = os.path.join(SYSDRIVE, f)
        try:
            out[f] = os.stat(p).st_size
        except OSError:
            pass
    return out


def collect_memfiles(run):
    if not is_admin():
        run.note("pagefile.sys, swapfile.sys and hiberfil.sys can only be read with administrator rights.")
        return {"status": "skipped"}
    sizes = memfile_sizes()
    if not sizes:
        run.note("No pagefile, swapfile or hibernation file on the system drive.")
        return {"files": 0}
    import shutil
    total = sum(sizes.values())
    free = shutil.disk_usage(run.case_dir).free
    if free < total + 256 * 1024 * 1024:
        run.note(f"Not enough free space for these files ({human_size(total)} needed, {human_size(free)} free).")
        return {"status": "failed"}
    got = 0
    for f, size in sizes.items():
        if run.stopped():
            break
        run.say(f"Reading {f} ({human_size(size)}) from the raw volume")
        if run.copy(os.path.join(SYSDRIVE, f), os.path.join(f)):
            got += 1
    if "hiberfil.sys" in sizes:
        run.note("hiberfil.sys is compressed. Convert it with Volatility 3 (windows.hibernation plugins) or Hibr2Bin before analysis.")
    return {"files": got, "bytes": total}


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
    "memfiles": collect_memfiles,
}
