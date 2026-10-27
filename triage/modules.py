"""The list of collection modules, in order of volatility, and which platforms each one supports."""

from .core import PLATFORM

# id, title, short description per platform, needs admin, on by default, big (may be GBs)
MODULES = [
    {"id": "memory", "title": "RAM capture",
     "desc": {"windows": "Full physical memory image with WinPmem (.raw). Captured first, before anything else changes memory.",
              "linux": "Full physical memory image with AVML (LiME format). Captured first, before anything else changes memory.",
              "macos": "Not available on macOS: Apple's kernel protections block RAM capture by free tools."},
     "admin": True, "default": True, "big": True, "platforms": ["windows", "linux"]},
    {"id": "network", "title": "Network connections",
     "desc": {"windows": "TCP/UDP endpoints with owning process, DNS cache, ARP, routes, shares, firewall, hosts file.",
              "linux": "Sockets from /proc with owning process, ss, interfaces, routes, ARP, firewall rules, hosts/resolv.conf.",
              "macos": "lsof/netstat sockets with owning process, interfaces, routes, ARP, DNS and proxy config, pf rules."},
     "admin": False, "default": True, "platforms": ["windows", "linux", "macos"]},
    {"id": "processes", "title": "Running processes",
     "desc": {"windows": "Process list with parent, command line, owner, signature and SHA-256, plus a process tree.",
              "linux": "Process list from /proc with command line, owner, start time, SHA-256; saves binaries deleted from disk.",
              "macos": "Process list with command line, owner, code signature and SHA-256, plus a process tree."},
     "admin": False, "default": True, "platforms": ["windows", "linux", "macos"]},
    {"id": "system", "title": "System information",
     "desc": {"windows": "OS build, hotfixes, installed software, USB history, Defender status and detections, BitLocker, time.",
              "linux": "Kernel, OS release, uptime, modules, mounts, packages, dmesg, sysctl, containers.",
              "macos": "macOS version, hardware, SIP/Gatekeeper/FileVault, profiles/MDM, extensions, installed apps."},
     "admin": False, "default": True, "platforms": ["windows", "linux", "macos"]},
    {"id": "users", "title": "Users and logons",
     "desc": {"windows": "Local accounts, administrators, profiles, logged-on sessions, password policy.",
              "linux": "Accounts (never password hashes), sudoers, who/w/last/lastb, SSH authorized_keys.",
              "macos": "Accounts, admin group, who/w/last, sudoers, SSH authorized_keys."},
     "admin": False, "default": True, "platforms": ["windows", "linux", "macos"]},
    {"id": "persistence", "title": "Persistence",
     "desc": {"windows": "Run keys, services, scheduled tasks, startup folders, WMI subscriptions, Winlogon, IFEO, AppInit, LSA.",
              "linux": "cron, systemd units/timers, rc.local, init scripts, shell profiles, ld.so.preload, udev, autostart.",
              "macos": "LaunchAgents/Daemons (with signatures), login items, cron, periodic, emond, shell profiles."},
     "admin": False, "default": True, "platforms": ["windows", "linux", "macos"]},
    {"id": "logs", "title": "Event logs",
     "desc": {"windows": "Exports Security, System, PowerShell, RDP, Defender, Sysmon and 20 more .evtx logs, plus key events.",
              "linux": "auth/secure, syslog, audit, wtmp/btmp, package logs, the systemd journal, auth highlights.",
              "macos": "Unified log archive (.logarchive), security-relevant log events, system/install logs."},
     "admin": False, "default": True, "platforms": ["windows", "linux", "macos"]},
    {"id": "browsers", "title": "Browser history",
     "desc": {"all": "Chrome, Edge, Brave, Vivaldi, Opera, Arc, Firefox and Safari history and downloads for every user, "
                     "merged into one timeline."},
     "admin": False, "default": True, "platforms": ["windows", "linux", "macos"]},
    {"id": "artifacts", "title": "Disk artifacts",
     "desc": {"windows": "Registry hives (incl. NTUSER/UsrClass), Amcache, Prefetch, SRUM, $MFT, LNK/jump lists, "
                         "PowerShell history, Recycle Bin, Timeline.",
              "linux": "Shell histories, executables in /tmp and /dev/shm, SUID/SGID files, recently changed system files, "
                       "package verification.",
              "macos": "Shell histories, quarantine (download origin) events, TCC/KnowledgeC, Mach-O files in temp folders."},
     "admin": False, "default": True, "platforms": ["windows", "linux", "macos"]},
    {"id": "memfiles", "title": "Pagefile and hibernation file",
     "desc": {"windows": "pagefile.sys, swapfile.sys and hiberfil.sys read straight off the volume. Often several GB."},
     "admin": True, "default": False, "big": True, "platforms": ["windows"]},
]

BY_ID = {m["id"]: m for m in MODULES}


def describe(m, platform=PLATFORM):
    d = m["desc"]
    return d.get(platform) or d.get("all") or ""


def available(m, platform=PLATFORM):
    return platform in m["platforms"]


def collectors():
    if PLATFORM == "windows":
        from .collectors import windows as mod
    elif PLATFORM == "macos":
        from .collectors import macos as mod
    else:
        from .collectors import linux as mod
    from .collectors import memory
    funcs = dict(mod.COLLECTORS)
    funcs["memory"] = memory.collect
    return funcs
