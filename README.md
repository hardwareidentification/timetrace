# timetrace++

**timetrace++** is an advanced Windows forensic and automated **Screenshare (SS) / PC Checking** tool. It is purpose-built for competitive server staff, anti-cheat arbiters, and tournament inspectors to uncover hidden game cheats, automated trace scrubbers, temporal manipulation, and kernel memory injection.

Unlike basic registry viewers, timetrace++ cross-examines forensic artifacts against an immutable kernel uptime baseline to instantly identify discrepancies left behind by bypass tools, wipers, and temporary loaders.

<img width="1246" height="724" alt="Screenshot 2026-09-27 141230" src="https://github.com/user-attachments/assets/fb34fdac-9a98-41d6-9a90-d8050a905ea1" />

---

## Why timetrace++ for PC Checking?

During a live screenshare, cheaters often use batch cleaners, USB loaders, or self-destruct routines to delete files before the check begins. **timetrace++ exposes what was executed, modified, or scrubbed during the current Windows session.**

### Key Forensic Audit Modules:

- **Anti-Forensics & Cleaner Detection:** Detects manual event log wipes (`Event ID 1102/104`), USN Journal deletion/truncation, abnormally small journal allocations, and purged Prefetch directories.
- **Deep Execution Tracing:** Recovers executed cheats even if the binary was deleted:
  - Decodes obfuscated ROT13 `UserAssist` records (extracts execution count and exact launch timestamp).
  - Inspects Windows 11 `PcaAppLaunchDic.txt` for binaries launched from `\AppData\Local\Temp` or `\Public`.
  - Audits `MuiCache`, `AppCompatFlags\Layers` (run-as-admin flags), `RunMRU`, and `Jumplist` stream caches.
- **Live Memory Injection Audit:** Scans active game processes (`FiveM`, `CS2`, `Valorant`, `Minecraft`, `Fortnite`, etc.) for unbacked private executable memory pages (`PAGE_EXECUTE_READWRITE` / `PAGE_EXECUTE_READ`) typical of manual mapping and reflective DLL injection.
- **Kernel & BYOVD Exploits:** Cross-references running and staged drivers against known vulnerable exploit drivers used by mappers (`iqvw64e.sys`, `mhyprot2.sys`, `gdrv.sys`, `echo.sys`, `interception.sys`, etc.).
- **Terminal & Staging History:** Reads `PSReadLine` history for commands like `wevtutil cl`, `sc stop`, or mapper executions, and scans the DNS cache for paste sites and cheat staging endpoints.
- **Zero Dependencies:** Pure standard library. Run it directly without installing third-party pip packages on the target machine.

---

## Target Audience

- **FiveM / GTA V:** Echo, Eulen, RedEngine, and spoofer detection.
- **Counter-Strike 2 / Valorant / Apex:** Injectors, macro hooks (`interception.sys`), and unbacked memory allocations.
- **Minecraft:** Ghost clients, external autoclickers, and cleaned executable traces.
- **Tournament / League Arbiters:** Verifying clean system state prior to official matches.

---

## Quick Start (For PC Checkers)

### Method 1: Using the Batch Launcher (Recommended)
Download the repository, open the folder, and run:
```cmd run.bat``` (The script automatically triggers administrative UAC elevation required for deep memory and raw journal audits).

Method 2: Command Line
Open an Elevated Command Prompt (Administrator) and run: 
```python main.py```

PC Check Workflow & Features
Automated Triage: Runs all 36 audit checks in parallel via a non-blocking background engine without freezing the interface.

Instant Sorting & Search: Click column headers to sort by Risk Level, State, or Timestamp. Use the search bar to query specific binaries or paths.

Detailed Forensic Inspection
Double-click any entry or right-click to open the deep forensic inspector modal. View full target paths, boot discrepancies, and technical context:

<img width="712" height="591" alt="Untitledgewsgseg" src="https://github.com/user-attachments/assets/8f219c90-87a8-4177-96b0-417c9c6b3f64" />

Standalone Evidence Export
Export comprehensive HTML triage reports, JSON manifests, or CSV files to preserve findings for bans and appeal tickets:

<img width="1882" height="940" alt="Screenshot 2026-09-27 141350" src="https://github.com/user-attachments/assets/b04f2cc3-2c7e-4cf0-b0dc-992caa4b3384" />

Building a Portable .exe (For Flash Drives / SS Toolkits)
To compile timetrace++ into a single executable for your SS flash drive:
```pip install -r requirements.txt```
```pyinstaller --noconsole --onefile --icon=assets/icon.ico --add-data "assets;assets" main.py```
The compiled binary will be generated in the dist/ directory.

Disclaimer
This tool is designed strictly for competitive gaming integrity verification, authorized screenshares, server administration, and digital forensic research.

Credits
Developed and maintained by @hardwareidentification.
