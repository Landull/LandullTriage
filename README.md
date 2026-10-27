# LandullTriage

Live-response evidence collection and memory analysis for **Windows, macOS and Linux**, in one app with a simple window. Plug in a USB drive, open LandullTriage, pick what to collect, press **Start collection**. You get one case folder with everything hashed, a log of the tool's own footprint, and an HTML report that points out what's worth a closer look.

## Download

Get the latest version from the [**Releases**](https://github.com/Landull/LandullTriage/releases/latest) page. Nothing else needs to be installed.

| System | File | How to open it |
|---|---|---|
| Windows 10/11 (x64) | `LandullTriage-Windows.zip` | Unzip it and run `LandullTriage.exe` from inside the folder. |
| macOS (Apple Silicon) | `LandullTriage-macOS.zip` | Unzip it and drag **LandullTriage** into Applications. |
| Linux (x64) | `LandullTriage-Linux.tar.gz` | Extract it and run `LandullTriage/LandullTriage`. |

**First launch:** the app isn't code-signed, so your system will warn you the first time.

- **Windows:** when SmartScreen appears, click **More info** › **Run anyway**. For a full collection, use **Relaunch as administrator** in the app (or right-click › Run as administrator).
- **macOS:** open the app once, then go to System Settings › Privacy & Security and click **Open Anyway**. For Safari history, TCC and other protected data, also add LandullTriage under **Full Disk Access**.
- **Linux:** the app asks for your password (pkexec) when it starts a collection as root.

## What it collects

Modules run in **order of volatility**: the things that change fastest are captured first.

| Module | Windows | Linux | macOS |
|---|---|---|---|
| **RAM capture** | Full image with WinPmem (`.raw`) | Full image with AVML (LiME `.lime`) | Not possible with free tools on modern macOS; the live-state modules cover it |
| **Network** | TCP/UDP endpoints with owning process, DNS cache, ARP, routes, SMB, firewall, hosts | `/proc` sockets with owning process, `ss`, routes, ARP, iptables/nft | `lsof`/`netstat` with owning process, DNS/proxy config, pf |
| **Processes** | Command line, parent, owner, signature, SHA-256, tree | Command line, owner, start time, SHA-256; saves binaries deleted from disk | Command line, owner, code signature, SHA-256, tree |
| **System** | Build, hotfixes, installed software, USB history, Defender status + detections, BitLocker | Kernel, packages, modules, mounts, dmesg, containers | SIP, Gatekeeper, FileVault, MDM profiles, extensions, apps |
| **Users** | Local users, admins, profiles, sessions | Accounts (never password hashes), sudoers, last/lastb, authorized_keys | Accounts, admin group, last, authorized_keys |
| **Persistence** | Run keys, services, scheduled tasks, startup folders, WMI subscriptions, Winlogon, IFEO, AppInit, LSA, Active Setup | cron, systemd units/timers, rc/init, shell profiles, `ld.so.preload`, udev, autostart | LaunchAgents/Daemons with signatures, login items, cron, periodic, emond |
| **Event logs** | Security, System, PowerShell, RDP, Defender, Sysmon and 20 more `.evtx` + key events | auth/secure, syslog, audit, wtmp/btmp, journal | Unified log archive, security events, system/install logs |
| **Browser history** | Chrome, Edge, Brave, Vivaldi, Opera, Firefox | same | + Safari and Arc |
| **Disk artifacts** | Registry hives (incl. NTUSER/UsrClass), Amcache, Prefetch, SRUM, `$MFT`, LNK/jump lists, PowerShell history, Recycle Bin, Timeline | Shell histories, executables in `/tmp` and `/dev/shm`, SUID/SGID, recently changed system files, package verification | Shell histories, quarantine (download origin) events, TCC, KnowledgeC, Mach-O files in temp folders |
| **Pagefile & hiberfil** (off by default) | `pagefile.sys`, `swapfile.sys`, `hiberfil.sys` | — | — |

Files Windows keeps locked (registry hives, `$MFT`, pagefile, a running browser's history) are read straight off the NTFS volume, with a Volume Shadow Copy fallback.

## The case folder

```
LandullTriage_<case>_<host>_<UTC time>/
  report.html          summary, findings to review, every module's status and files
  manifest.sha256      SHA-256 of every file (sha256sum -c / shasum -a 256 -c)
  footprint.jsonl      every command LandullTriage ran and file it copied, with times
  copied_files.csv     original path, timestamps, copy method and hash of each copied file
  case.json            case details and module results
  memory/ network/ processes/ system/ users/ persistence/ logs/ browsers/ artifacts/
```

**Findings** are automatic leads, not verdicts: processes running from Temp or `/dev/shm`, encoded PowerShell, Office spawning a shell, binaries deleted from disk while running, autostarts and services pointing at user folders, WMI consumers, cleared logs, new services and accounts, UID-0 accounts, `ld.so.preload`, unsigned launch items, and more.

## Analyze memory

The **Analyze memory** page runs core [Volatility 3](https://github.com/volatilityfoundation/volatility3) plugins against any RAM image (from LandullTriage, WinPmem, AVML, DumpIt, FTK Imager, VMware `.vmem`...) and shows the results as tables you can filter. Each plugin is saved as CSV.

- **Windows images:** process list/tree/scan, command lines, network connections, injected code (malfind), services, plus optional DLLs, handles, files and hidden-process checks. Symbols download automatically from Microsoft the first time.
- **Linux and macOS images:** need a symbol table built for that exact kernel ([dwarf2json](https://github.com/volatilityfoundation/dwarf2json)); choose its folder under **Symbols**.

## Command line

The same app runs without the window, which is handy over remote shells:

```
LandullTriage --collect --out E:\cases --case IR-014 --examiner Landull --modules default
LandullTriage --collect --out /mnt/usb --modules memory,network,processes,persistence --zip
LandullTriage --analyze memory.raw --out results --os windows
```

`--modules` takes `default`, `all`, or a comma list of: `memory, network, processes, system, users, persistence, logs, browsers, artifacts, memfiles`.

## Build it yourself

Building needs Python 3.9+.

- **Windows:** double-click `build_windows.bat`. The app is built to `dist\LandullTriage\LandullTriage.exe`.
- **macOS:** double-click `Build Mac App.command`. The app is built to `dist/LandullTriage.app`.
- **Linux:** run `./build_linux.sh`.
- **Run from source:** `pip install -r requirements.txt`, then `python3 fetch_tools.py` (downloads WinPmem/AVML) and `python3 landull_triage.py`.

To ship a new version, publish a release on GitHub with a new tag such as `v1.0.1`. GitHub Actions builds all three versions, tests them (including a raw NTFS read of a locked registry hive on Windows), and attaches the downloads to the release.

## Good practice

- Save to an **external drive** when you can. The app warns you when the output is on the system drive.
- Keep the case folder and its `manifest.sha256` together; re-verify the hashes after every transfer.
- RAM capture tools load a kernel driver (WinPmem) or read `/proc/kcore` (AVML). EDR products and Windows Memory Integrity can block or alert on this; add an exclusion or expect the alert.
- Only collect from systems you own or are authorized to examine.

## Third-party components

LandullTriage is MIT licensed. Builds bundle [WinPmem](https://github.com/Velocidex/WinPmem) (Apache 2.0), [AVML](https://github.com/microsoft/avml) (MIT), [Volatility 3](https://github.com/volatilityfoundation/volatility3) (Volatility Software License) and Qt via [PySide6](https://doc.qt.io/qtforpython/) (LGPLv3). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

---
Part of [Landull](https://github.com/Landull)'s toolkits.
