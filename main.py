# timetrace++ - windows timeline discrepancy & anti-forensics auditor
# github.com/hardwareidentification

import os
import sys
import ctypes
from ctypes import wintypes
import subprocess
import re
import winreg
import threading
import queue
import hashlib
import webbrowser
import urllib.parse
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
import csv
import json
import tkinter as tk
from tkinter import filedialog, messagebox

# 64-bit or 32-bit pointer type definition
ulong_ptr = ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32

# win32 process enumeration and query access flags
TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# virtual memory page allocation and protection constants
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_EXECUTE = 0x10
page_execute_read = 0x20
page_execute_readwrite = 0x40
page_execute_writecopy = 0x80

# structure to query system virtual memory address limits
class system_info(ctypes.Structure):
    class _u(ctypes.Union):
        class _s(ctypes.Structure):
            _fields_ = [
                ("wProcessorArchitecture", wintypes.WORD),
                ("wReserved", wintypes.WORD),
            ]
        _fields_ = [("dwOemId", wintypes.DWORD), ("_s", _s)]
    _anonymous_ = ("_u",)
    _fields_ = [
        ("_u", _u),
        ("dwPageSize", wintypes.DWORD),
        ("lpMinimumApplicationAddress", ctypes.c_void_p),
        ("lpMaximumApplicationAddress", ctypes.c_void_p),
        ("dwActiveProcessorMask", ulong_ptr),
        ("dwNumberOfProcessors", wintypes.DWORD),
        ("dwProcessorType", wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD),
        ("wProcessorLevel", wintypes.WORD),
        ("wProcessorRevision", wintypes.WORD),
    ]

# structure populated by VirtualQueryEx for page-level memory inspection
class memory_basic_information(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

# structure for process snapshot iteration
class processentry32w(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ulong_ptr),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]

# check if current process has administrator rights
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

# relaunch script with administrator privileges if needed
def elevate_privileges():
    if not is_admin():
        script = os.path.abspath(sys.argv[0])
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        try:
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
            if int(ret) > 32:
                sys.exit(0)
        except Exception:
            pass

# register app id for proper windows taskbar grouping
try:
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("hardwareidentification.timetrace.audit.1.0")
except Exception:
    pass

# convert hex color string to rgb tuple
def _hex_to_rgb(value):
    value = value.lstrip("#")
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)

# blend two hex colors to calculate vertical gradient steps
def mix(color_a, color_b, amount):
    ra, ga, ba = _hex_to_rgb(color_a)
    rb, gb, bb = _hex_to_rgb(color_b)
    return "#%02x%02x%02x" % (
        round(ra + (rb - ra) * amount),
        round(ga + (gb - ga) * amount),
        round(ba + (bb - ba) * amount),
    )

# force dark mode on windows titlebar via dwm api
def apply_dark_titlebar(root):
    try:
        root.update_idletasks()
        hwnd = root.winfo_id()
        parent = ctypes.windll.user32.GetParent(hwnd)
        if parent:
            hwnd = parent

        set_attr = ctypes.windll.dwmapi.DwmSetWindowAttribute
        set_attr.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint]
        set_attr.restype = ctypes.c_long

        for attr_id in (20, 19):
            enabled = ctypes.c_int(1)
            if set_attr(ctypes.c_void_p(hwnd), attr_id, ctypes.byref(enabled), ctypes.sizeof(enabled)) == 0:
                break
    except Exception:
        pass

# calculate exact kernel boot timestamp via uptime tick count
def get_system_boot_time():
    try:
        lib = ctypes.windll.kernel32
        lib.GetTickCount64.restype = ctypes.c_uint64
        uptime_ms = lib.GetTickCount64()
        boot_timestamp = datetime.now(timezone.utc).timestamp() - (uptime_ms / 1000.0)
        return datetime.fromtimestamp(boot_timestamp, tz=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)

# sanitize raw timestamps into uniform YYYY-MM-DD HH:MM:SS format
def clean_timestamp(ts):
    if not ts or str(ts).strip() in ("", "-", "None"):
        return "-"
    clean = str(ts).replace("t", " ").replace("T", " ").rstrip("zZ")
    if "." in clean:
        clean = clean.split(".")[0]
    return clean.strip()

# convert windows 64-bit filetime to utc datetime
def filetime_to_dt(ft_int):
    if not ft_int or ft_int == 0:
        return None
    try:
        sec = (ft_int - 116444736000000000) / 10000000.0
        if sec < 0:
            return None
        return datetime.fromtimestamp(sec, tz=timezone.utc)
    except Exception:
        return None

# rot13 decoder for obfuscated userassist registry values
def rot13(text):
    out = []
    for c in text:
        if 'a' <= c <= 'z':
            out.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            out.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            out.append(c)
    return "".join(out)

# calculate sha-256 hash of a file on disk
def calculate_sha256(filepath):
    try:
        if filepath and os.path.isfile(filepath):
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest().lower()
    except Exception:
        pass
    return None

# extract sha256, sha1, or md5 hash from string via regex
def extract_hash_from_string(input_str):
    if not input_str or not isinstance(input_str, str):
        return None
    pattern = re.compile(r"\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
    m = pattern.search(input_str.replace("_", " "))
    return m.group(1).lower() if m else None

# check if target file exists on local storage
def is_file_existing(path):
    if not path or not isinstance(path, str):
        return False
    try:
        norm = os.path.normpath(os.path.expandvars(path.strip().strip('"')))
        return os.path.exists(norm)
    except Exception:
        return False

# verify if an entry is eligible for virustotal lookup
def is_vt_eligible(path, name):
    if is_file_existing(path):
        return True
    if extract_hash_from_string(path) or extract_hash_from_string(name):
        return True
    if name and any(name.lower().endswith(ext) for ext in ('.sys', '.exe', '.dll', '.dat', '.hve', '.pf')):
        return True
    return False

# open file explorer and highlight the target file
def open_in_explorer(target_path, target_name=""):
    path_to_try = target_path if is_file_existing(target_path) else target_name
    if not is_file_existing(path_to_try):
        return False
    norm = os.path.normpath(os.path.expandvars(path_to_try.strip().strip('"')))
    if os.path.isfile(norm):
        subprocess.Popen(f'explorer.exe /select,"{norm}"', shell=False)
        return True
    elif os.path.isdir(norm):
        os.startfile(norm)
        return True
    return False

# search file hash, extracted hash, or binary name on virustotal
def open_virustotal(target_path, target_name="", subsystem=""):
    if target_path and os.path.isfile(target_path):
        sha = calculate_sha256(target_path)
        if sha:
            webbrowser.open(f"https://www.virustotal.com/gui/file/{sha}")
            return
    extracted_hash = extract_hash_from_string(target_path) or extract_hash_from_string(target_name)
    if extracted_hash:
        webbrowser.open(f"https://www.virustotal.com/gui/file/{extracted_hash}")
        return
    query = ""
    if target_name and any(target_name.lower().endswith(ext) for ext in ('.sys', '.exe', '.dll', '.dat', '.hve', '.pf')):
        query = target_name.strip()
    elif target_path and any(target_path.lower().endswith(ext) for ext in ('.sys', '.exe', '.dll', '.dat', '.hve', '.pf')):
        query = os.path.basename(target_path).strip()
    if query:
        webbrowser.open(f"https://www.virustotal.com/gui/search/{urllib.parse.quote(query)}")

# search google formatted as an explicit verification question for ai overviews
def open_web_search(subsystem, details, target_name=""):
    target = target_name if target_name and target_name.lower() not in ("n/a", "-") else ""
    query = f"is {subsystem} {target} proof of cheats or windows anti-forensics {details}".strip()
    clean_query = " ".join(query.split())
    url = f"https://www.google.com/search?q={urllib.parse.quote_plus(clean_query)}"
    webbrowser.open(url)

# format row details into clipboard-ready plain text
def format_finding_text(row):
    state, subsystem, baseline, artifact_time, details, risk = row[:6]
    explanation = row[6] if len(row) > 6 else ""
    target_path = row[7] if len(row) > 7 else ""
    target_name = row[8] if len(row) > 8 else ""

    lines = [
        "timetrace++ forensic audit report",
        "--------------------------------------------------",
        f"subsystem / vector : {subsystem.lower()}",
        f"state status       : {state.lower()}",
        f"risk level         : {risk.lower()}",
        f"baseline timestamp : {baseline}",
        f"artifact timestamp : {artifact_time}",
        f"technical finding  : {details.lower()}",
        f"target path/binary : {target_path or target_name or 'n/a'}",
        f"forensic context   : {explanation.lower()}",
        "--------------------------------------------------"
    ]
    return "\n".join(lines)

# smooth rounded button rendered via canvas primitives
class RoundedButton(tk.Canvas):
    def __init__(self, parent, text, command, width=120, height=32, radius=12, bg_color="#3a3a3a", hover_color="#4a4a4a", fg_color="#ffffff", font=("segoe ui", 9), **kwargs):
        super().__init__(parent, width=width, height=height, bg=parent["bg"], highlightthickness=0, bd=0, **kwargs)
        self.command = command
        self.radius = radius
        self.bg_color = bg_color
        self.hover_color = hover_color
        self.fg_color = fg_color
        self.font = font
        self.text = text
        self.width = width
        self.height = height
        self._disabled = False
        
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)
        self.draw()

    # draw 4 corner arcs and overlapping rectangles for smooth pill shape
    def draw(self, color=None):
        self.delete("all")
        c = color or self.bg_color
        r = self.radius
        w = self.width
        h = self.height

        self.create_arc((0, 0, r*2, r*2), start=90, extent=90, fill=c, outline="")
        self.create_arc((w - r*2, 0, w, r*2), start=0, extent=90, fill=c, outline="")
        self.create_arc((0, h - r*2, r*2, h), start=180, extent=90, fill=c, outline="")
        self.create_arc((w - r*2, h - r*2, w, h), start=270, extent=90, fill=c, outline="")
        self.create_rectangle((r, 0, w - r, h), fill=c, outline="")
        self.create_rectangle((0, r, w, h - r), fill=c, outline="")

        text_color = "#555555" if self._disabled else self.fg_color
        self.create_text(w // 2, h // 2, text=self.text, fill=text_color, font=self.font)

    def _on_enter(self, e):
        if not self._disabled:
            self.draw(self.hover_color)

    def _on_leave(self, e):
        if not self._disabled:
            self.draw(self.bg_color)

    def _on_click(self, e):
        if not self._disabled and self.command:
            self.command()

    # update button disabled state and background color
    def config_state(self, state, bg=None):
        self._disabled = (state == tk.DISABLED)
        if bg:
            self.bg_color = bg
        self.draw()

# background audit engine executing forensic scans
class auditengine:
    def __init__(self, result_queue):
        self.queue = result_queue
        self.boot_dt = get_system_boot_time()
        self.boot_str = self.boot_dt.strftime("%Y-%m-%d %H:%M:%S")

    # push sanitized finding entry to ui queue
    def _record(self, state, subsystem, baseline, artifact_time, details, risk, explanation="", target_path="", target_name=""):
        cleaned_artifact = clean_timestamp(artifact_time)
        cleaned_baseline = clean_timestamp(baseline)
        self.queue.put(("ENTRY", (
            state.lower(),
            subsystem.lower(),
            cleaned_baseline,
            cleaned_artifact,
            details.lower(),
            risk.lower(),
            explanation.lower(),
            target_path,
            target_name
        )))

    # execute silent shell command with timeout and hidden console window
    def _run_cmd(self, cmd_str, timeout=6):
        try:
            res = subprocess.run(
                cmd_str,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                creationflags=0x08000000
            )
            return res.stdout
        except Exception:
            return ""

    # query windows event log via xpath and parse structured xml
    def _query_wevtutil_xml(self, channel, xpath, count=1):
        try:
            cmd = f'wevtutil qe "{channel}" "/q:{xpath}" /f:xml /c:{count}'
            out = self._run_cmd(cmd, timeout=8)
            if not out.strip():
                return []
            wrapped = f"<Events>{out}</Events>"
            root = ET.fromstring(wrapped)
            return root.findall(".//{http://schemas.microsoft.com/win/2004/08/events/event}Event")
        except Exception:
            return []

    # run all forensic audit vectors in order
    def run_all(self):
        self._record(
            "clean", "kernel baseline", self.boot_str, "-",
            "calibrated via win32 gettickcount64", "info",
            "kernel boot time calibrated as baseline against all filesystem and execution logs.",
            "", ""
        )
        self._audit_usn_journal()
        self._audit_ntfs_log_events()
        self._audit_vss_shadows()
        self._audit_prefetch_pipeline()
        self._audit_prefetch_configuration()
        self._audit_pca_artifacts()
        self._audit_shimcache()
        self._audit_amcache()
        self._audit_bam_dam()
        self._audit_userassist_deep()
        self._audit_muicache()
        self._audit_appcompatflags_layers()
        self._audit_runmru()
        self._audit_recentdocs_jumplists()
        self._audit_srudb()
        self._audit_driver_signature_enforcement()
        self._audit_kernel_debugger()
        self._audit_vulnerable_drivers_extended()
        self._audit_hvci_driver_blocklist()
        self._audit_input_hooks()
        self._audit_ramdisk_drivers()
        self._audit_eventlog_integrity()
        self._audit_log_clearing_events()
        self._audit_clock_tampering()
        self._audit_minint_registry()
        self._audit_powershell_telemetry()
        self._audit_powershell_history()
        self._audit_defender_policies()
        self._audit_pca_policy()
        self._audit_dps_service()
        self._audit_dns_client_cache()
        self._audit_usbstor_devices()
        self._audit_setupapi_logs()
        self._audit_wer_reports()
        self._audit_unbacked_executable_memory_all()
        self.queue.put(("COMPLETE", None))

    # check ntfs change journal status and allocated size
    def _audit_usn_journal(self):
        out = self._run_cmd("fsutil usn queryjournal c:")
        m_id = re.search(r"usn journal id\s*:\s*(0x[0-9a-fA-F]+|\d+)", out, re.I)
        m_sz = re.search(r"maximum size\s*:\s*(0x[0-9a-fA-F]+|\d+)", out, re.I)
        if m_id:
            self._record("clean", "usn change journal", self.boot_str, "-",
                         f"ok - journal operational (id: {m_id.group(1)})", "low",
                         "the ntfs update sequence number journal ($usnjrnl) tracks volume-level file alterations. active and functional tracking confirmed.",
                         r"C:\$Extend\$UsnJrnl", "fsutil")
        else:
            self._record("flagged", "usn change journal", self.boot_str, "-",
                         "journal query failed or journal purged", "high",
                         "failed to query or parse usn journal id. cleaners and wipers frequently purge this structure to hide file deletion traces.",
                         r"C:\$Extend\$UsnJrnl", "fsutil")
        if m_sz:
            sz_mb = int(m_sz.group(1), 0) / (1024 * 1024)
            if sz_mb < 8.0:
                self._record("suspicious", "usn journal size", self.boot_str, "-",
                             f"journal size abnormally small ({sz_mb:.1f} mb)", "medium",
                             "usn change journal size allocation is abnormally compact (<8 mb), typically indicating a recently purged and newly recreated journal structure.",
                             "", "")

    # check ntfs event log for journal truncation or deletion events (201/202)
    def _audit_ntfs_log_events(self):
        events = self._query_wevtutil_xml("System", "*[System[Provider[@Name='Ntfs'] and (EventID=201 or EventID=202)]]", 5)
        if events:
            self._record("flagged", "ntfs log resets", self.boot_str, "-",
                         f"detected {len(events)} ntfs journal reset events (eid 201/202)", "high",
                         "ntfs event logs recorded explicit journal deletion or truncation events (event id 201/202).", "", "")
        else:
            self._record("clean", "ntfs log resets", self.boot_str, "-",
                         "ok - zero journal reset events since boot", "low",
                         "no journal deletion or truncation events recorded in ntfs log.", "", "")

    # audit volume shadow copies (0 is standard on modern client nvme ssd)
    def _audit_vss_shadows(self):
        out = self._run_cmd("vssadmin list shadows")
        count = len(re.findall(r"shadow copy id:", out, re.IGNORECASE))
        if count == 0:
            self._record("clean", "volume shadow copies", self.boot_str, "-",
                         "0 shadow copies present (standard on client nvme drives)", "low",
                         "no volume shadow copies present. standard default state on modern consumer windows 10/11 installations on nvme ssds to prevent write wear.", "", "")
        else:
            self._record("clean", "volume shadow copies", self.boot_str, "-",
                         f"ok - {count} shadow copies verified", "low",
                         f"verified {count} active volume shadow copy restore points.", "", "")

    # inspect prefetch directory for wipers or known cheat executables
    def _audit_prefetch_pipeline(self):
        pf_dir = r"C:\Windows\Prefetch"
        if not os.path.exists(pf_dir):
            self._record("flagged", "prefetch storage", self.boot_str, "-",
                         "prefetch directory missing or inaccessible", "critical",
                         "prefetch directory c:\\windows\\prefetch is missing or inaccessible. complete absence indicates aggressive anti-forensic scrubbing.", pf_dir, "")
            return
        try:
            files = [os.path.join(pf_dir, f) for f in os.listdir(pf_dir) if f.lower().endswith(".pf")]
            if not files:
                self._record("flagged", "prefetch storage", self.boot_str, "-",
                             "prefetch directory empty (scrubber executed)", "high",
                             "prefetch directory is completely empty, indicating automated cleaner or wiper activity.", pf_dir, "")
                return

            cheat_patterns = [
                "cheatengine", "xenos", "extremeinjector", "injector", "kdmapper", "kdu",
                "eulen", "spoofer", "aimbot", "hags", "processhacker", "cheat", "loader"
            ]
            matches = []
            for f in files:
                base = os.path.basename(f).lower()
                for c in cheat_patterns:
                    if c in base:
                        matches.append(f)
            if matches:
                first = matches[0]
                self._record("flagged", "prefetch execution history", self.boot_str, "-",
                             f"unauthorized binaries tracked: {', '.join(set(os.path.basename(x) for x in matches))[:80]}", "critical",
                             "unauthorized tools or known cheat utilities discovered in prefetch execution history.", first, os.path.basename(first))
            else:
                self._record("clean", "prefetch execution history", self.boot_str, "-",
                             f"ok - {len(files)} prefetch files active without blacklisted signatures", "low",
                             "nominal execution cache verified without suspicious signatures.", pf_dir, "")
        except Exception as e:
            self._record("suspicious", "prefetch storage", self.boot_str, "-",
                         f"access error: {str(e)}", "medium", "access to prefetch directory restricted.", pf_dir, "")

    # check if prefetcher is explicitly disabled via memory management registry
    def _audit_prefetch_configuration(self):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters") as k:
                val, _ = winreg.QueryValueEx(k, "EnablePrefetcher")
                if val == 0:
                    self._record("flagged", "prefetch configuration", self.boot_str, "-",
                                 "enableprefetcher set to 0 (explicitly disabled)", "high",
                                 "enableprefetcher is set to 0 in registry. prefetching is explicitly disabled to suppress execution artifacts.", "", "EnablePrefetcher")
                else:
                    self._record("clean", "prefetch configuration", self.boot_str, "-",
                                 f"ok - prefetch active (flag {val})", "low", "prefetch configuration nominal.", "", "EnablePrefetcher")
        except Exception:
            self._record("clean", "prefetch configuration", self.boot_str, "-", "ok - nominal", "low", "", "", "")

    # parse windows 11 pca launch dictionary for suspicious temp executions
    def _audit_pca_artifacts(self):
        dic_path = r"C:\Windows\appcompat\pca\PcaAppLaunchDic.txt"
        if os.path.exists(dic_path):
            try:
                with open(dic_path, "r", encoding="cp1252", errors="ignore") as f:
                    lines = [line.strip() for line in f if line.strip()]
                flagged = []
                for line in lines:
                    parts = line.split("|")
                    p = parts[0]
                    t = parts[1] if len(parts) > 1 else "-"
                    p_lower = p.lower()
                    if any(term in p_lower for term in ["temp\\", "appdata\\local\\temp", "public\\", "injector", "cheat", "loader", "spoofer"]):
                        flagged.append((p, t))
                if flagged:
                    sample = flagged[-1]
                    self._record("flagged", "pca app launch dictionary", self.boot_str, sample[1],
                                 f"suspicious executable execution staged: {os.path.basename(sample[0])}", "high",
                                 "windows 11 program compatibility assistant (pcasvc) recorded suspicious binary execution from a temporary directory or known cheat naming schema in pcaapplaunchdic.txt.",
                                 sample[0], os.path.basename(sample[0]))
                else:
                    self._record("clean", "pca app launch dictionary", self.boot_str, "-",
                                 f"ok - {len(lines)} records nominal", "low", "pca launch dictionary verified.", dic_path, "")
            except Exception as e:
                self._record("suspicious", "pca app launch dictionary", self.boot_str, "-",
                             f"error reading pca dictionary: {str(e)}", "low", "", dic_path, "")
        else:
            self._record("clean", "pca app launch dictionary", self.boot_str, "-",
                         "pca dictionary inactive or pre-windows 11 22h2", "info", "", "", "")

    # check appcompatcache to catch wiped shimcache artifacts
    def _audit_shimcache(self):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache") as k:
                val, _ = winreg.QueryValueEx(k, "AppCompatCache")
                if not val or len(val) == 0:
                    self._record("flagged", "shimcache database", self.boot_str, "-",
                                 "appcompatcache is zero-length (scrubbed)", "high",
                                 "appcompatcache registry data is empty. shimcache retains up to 1024 binary executions; an empty value confirms deliberate anti-forensic registry wiping.", "", "AppCompatCache")
                else:
                    self._record("clean", "shimcache database", self.boot_str, "-",
                                 f"ok - serialized shimcache active ({len(val)} bytes)", "low", "appcompatcache active.", "", "AppCompatCache")
        except Exception:
            self._record("suspicious", "shimcache database", self.boot_str, "-", "unable to read appcompatcache", "medium", "", "", "")

    # check amcache hive presence and detect truncation
    def _audit_amcache(self):
        p = r"C:\Windows\appcompat\Programs\Amcache.hve"
        if os.path.exists(p):
            try:
                sz_mb = os.path.getsize(p) / (1024 * 1024)
                if sz_mb < 0.2:
                    self._record("suspicious", "amcache registry hive", self.boot_str, "-",
                                 f"amcache.hve truncated ({sz_mb:.2f} mb)", "medium",
                                 "amcache.hve is abnormally truncated (<200 kb). amcache stores sha-1 hashes and installation metadata; truncation indicates partial wipe.", p, "Amcache.hve")
                else:
                    self._record("clean", "amcache registry hive", self.boot_str, "-",
                                 f"ok - amcache active ({sz_mb:.1f} mb)", "low", "active amcache.hve database verified.", p, "Amcache.hve")
            except Exception:
                self._record("clean", "amcache registry hive", self.boot_str, "-", "ok - accessible", "low", "", p, "")
        else:
            self._record("flagged", "amcache registry hive", self.boot_str, "-",
                         "amcache.hve missing from disk", "high",
                         "amcache.hve is missing from disk, indicating application inventory database purging.", p, "")

    # audit background activity moderator execution registry keys across user sids
    def _audit_bam_dam(self):
        entries = 0
        found = False
        paths = [
            r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
            r"SYSTEM\CurrentControlSet\Services\bam\UserSettings",
            r"SYSTEM\CurrentControlSet\Services\dam\UserSettings"
        ]
        for p in paths:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, p) as k:
                    found = True
                    sub_count, _, _ = winreg.QueryInfoKey(k)
                    for i in range(sub_count):
                        sid = winreg.EnumKey(k, i)
                        try:
                            with winreg.OpenKey(k, sid) as sk:
                                _, v_count, _ = winreg.QueryInfoKey(sk)
                                entries += v_count
                        except Exception:
                            pass
                    break
            except Exception:
                continue
        if not found:
            self._record("suspicious", "bam/dam execution keys", self.boot_str, "-", "bam subkeys inaccessible", "medium", "", "", "bam")
        elif entries == 0:
            self._record("flagged", "bam/dam execution keys", self.boot_str, "-",
                         "bam execution keys empty (registry wiper detected)", "high",
                         "background activity monitor (bam) registry keys are completely empty. bam tracks per-user binary execution; an empty key proves registry scrubbing.", "", "bam")
        else:
            self._record("clean", "bam/dam execution keys", self.boot_str, "-",
                         f"ok - {entries} executions tracked across user sids", "low", "bam telemetry verified.", "", "bam")

    # decode userassist entries via rot13 and extract execution filetime
    def _audit_userassist_deep(self):
        base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        cheat_terms = ["cheat", "injector", "xenos", "kdmapper", "spoofer", "loader", "aimbot", "hack"]
        flagged = []
        total_tracked = 0
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base) as k:
                sub_count, _, _ = winreg.QueryInfoKey(k)
                for i in range(sub_count):
                    guid = winreg.EnumKey(k, i)
                    try:
                        with winreg.OpenKey(k, f"{guid}\\Count") as ck:
                            _, val_c, _ = winreg.QueryInfoKey(ck)
                            for v_i in range(val_c):
                                raw_name, data, _ = winreg.EnumValue(ck, v_i)
                                total_tracked += 1
                                decoded = rot13(raw_name)
                                decoded_lower = decoded.lower()
                                if any(term in decoded_lower for term in cheat_terms):
                                    exec_dt_str = "-"
                                    # extract filetime from 72-byte structure offset 68..76
                                    if isinstance(data, bytes) and len(data) >= 72:
                                        ft_raw = int.from_bytes(data[68:76], byteorder="little")
                                        dt = filetime_to_dt(ft_raw)
                                        if dt:
                                            exec_dt_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                                    flagged.append((decoded, exec_dt_str))
                    except Exception:
                        pass
            if flagged:
                sample = flagged[-1]
                self._record("flagged", "userassist rot13 decoder", self.boot_str, sample[1],
                             f"cheat launch artifact resolved: {os.path.basename(sample[0])}", "critical",
                             f"decoded userassist execution trace: {sample[0]}", sample[0], os.path.basename(sample[0]))
            elif total_tracked == 0:
                self._record("flagged", "userassist rot13 decoder", self.boot_str, "-",
                             "userassist count keys empty (wiper artifact)", "high",
                             "userassist registry cache is completely empty. explorer records rot13-encoded application launch metrics here; empty state indicates gui history wiping.", "", "UserAssist")
            else:
                self._record("clean", "userassist rot13 decoder", self.boot_str, "-",
                             f"ok - {total_tracked} userassist records verified without cheat signatures", "low", "", "", "UserAssist")
        except Exception:
            self._record("clean", "userassist rot13 decoder", self.boot_str, "-", "userassist nominal", "low", "", "", "UserAssist")

    # scan muicache for lingering executable names or temporary paths
    def _audit_muicache(self):
        mui_path = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
        found_cheats = []
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, mui_path) as k:
                _, val_c, _ = winreg.QueryInfoKey(k)
                for i in range(val_c):
                    name, _, _ = winreg.EnumValue(k, i)
                    name_clean = name.split(".ApplicationCompany")[0].split(".FriendlyAppName")[0]
                    lower_name = name_clean.lower()
                    if any(t in lower_name for t in ["cheat", "injector", "kdmapper", "spoofer", "aimbot", "loader", "temp\\"]):
                        found_cheats.append(name_clean)
            if found_cheats:
                sample = found_cheats[-1]
                self._record("flagged", "muicache execution store", self.boot_str, "-",
                             f"suspicious executable name: {os.path.basename(sample)}", "high",
                             f"muicache retains launch reference: {sample}", sample, os.path.basename(sample))
            else:
                self._record("clean", "muicache execution store", self.boot_str, "-", "ok - no cheat signatures in muicache", "low", "", "", "MuiCache")
        except Exception:
            self._record("clean", "muicache execution store", self.boot_str, "-", "muicache key nominal", "low", "", "", "MuiCache")

    # check appcompatflags layers for elevated or shimmed binaries
    def _audit_appcompatflags_layers(self):
        roots = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers")
        ]
        suspicious = []
        for hive, path in roots:
            try:
                with winreg.OpenKey(hive, path) as k:
                    _, val_c, _ = winreg.QueryInfoKey(k)
                    for i in range(val_c):
                        bin_path, flags, _ = winreg.EnumValue(k, i)
                        if any(t in bin_path.lower() for t in ["temp", "appdata", "cheat", "loader", "inject", "spoofer"]):
                            suspicious.append((bin_path, flags))
            except Exception:
                continue
        if suspicious:
            sample = suspicious[-1]
            self._record("flagged", "appcompat layers elevation", self.boot_str, "-",
                         f"elevated/shimmed executable staged: {os.path.basename(sample[0])}", "high",
                         f"binary assigned compatibility layer ({sample[1]}): {sample[0]}", sample[0], os.path.basename(sample[0]))
        else:
            self._record("clean", "appcompat layers elevation", self.boot_str, "-", "ok - appcompat layers nominal", "low", "", "", "")

    # check explorer run command history (win+r)
    def _audit_runmru(self):
        mru_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, mru_path) as k:
                _, val_c, _ = winreg.QueryInfoKey(k)
                if val_c <= 1:
                    self._record("suspicious", "runmru command history", self.boot_str, "-",
                                 "run dialog history empty (cleaner artifact)", "medium",
                                 "run command dialog history (win+r) is empty. wiping runmru indicates automated cleanup activity.", "", "RunMRU")
                else:
                    self._record("clean", "runmru command history", self.boot_str, "-",
                                 f"ok - {val_c - 1} entries retained", "low", "", "", "RunMRU")
        except Exception:
            self._record("clean", "runmru command history", self.boot_str, "-", "runmru key nominal", "low", "", "", "RunMRU")

    # check automaticdestinations folder for jumplist wiping
    def _audit_recentdocs_jumplists(self):
        recent_path = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations")
        if os.path.exists(recent_path):
            try:
                dest_files = os.listdir(recent_path)
                if len(dest_files) == 0:
                    self._record("suspicious", "jumplist stream cache", self.boot_str, "-",
                                 "automaticdestinations folder empty (wiper artifact)", "medium",
                                 "automaticdestinations jumplist stream directory is empty, indicating automated user activity wiping.", recent_path, "")
                else:
                    self._record("clean", "jumplist stream cache", self.boot_str, "-",
                                 f"ok - {len(dest_files)} streams present", "low", "", recent_path, "")
            except Exception:
                self._record("clean", "jumplist stream cache", self.boot_str, "-", "nominal", "low", "", recent_path, "")
        else:
            self._record("clean", "jumplist stream cache", self.boot_str, "-", "nominal", "low", "", recent_path, "")

    # inspect srudb.dat resource monitor database size and integrity
    def _audit_srudb(self):
        p = r"C:\Windows\System32\sru\srudb.dat"
        if os.path.exists(p):
            try:
                sz = os.path.getsize(p) / (1024 * 1024)
                if sz < 0.5:
                    self._record("flagged", "srudb resource metrics", self.boot_str, "-",
                                 f"srudb.dat abnormally small ({sz:.2f} mb, reset suspected)", "high",
                                 "srudb.dat is abnormally small (<0.5 mb). srudb tracks network and process usage; a reset hides network download and staging activity.", p, "srudb.dat")
                else:
                    self._record("clean", "srudb resource metrics", self.boot_str, "-",
                                 f"ok - srudb database active ({sz:.1f} mb)", "low", "", p, "srudb.dat")
            except Exception as e:
                self._record("suspicious", "srudb resource metrics", self.boot_str, "-", f"file locked: {str(e)}", "medium", "", p, "srudb.dat")
        else:
            self._record("flagged", "srudb resource metrics", self.boot_str, "-",
                         "srudb.dat missing (telemetry deleted)", "critical", "srudb.dat deleted from disk.", p, "srudb.dat")

    # check bcdedit for testsigning or kernel debugging flags
    def _audit_driver_signature_enforcement(self):
        out = self._run_cmd("bcdedit /enum {current}")
        flags = []
        if re.search(r"testsigning\s+(yes|true|1)", out, re.I):
            flags.append("testsigning enabled")
        if re.search(r"nointegritychecks\s+(yes|true|1)", out, re.I):
            flags.append("nointegritychecks active")
        if re.search(r"debug\s+(yes|true|1)", out, re.I):
            flags.append("kernel debugging active")
        if flags:
            self._record("flagged", "driver signature enforcement", self.boot_str, "-",
                         f"unsigned kernel drivers permitted: {', '.join(flags)}", "critical",
                         "driver signature enforcement (dse) policy violated via bcdedit. unsigned ring 0 drivers can be loaded.", "", "")
        else:
            self._record("clean", "driver signature enforcement", self.boot_str, "-",
                         "ok - testsigning disabled, code integrity enforced", "low", "", "", "")

    # detect attached kernel debugger via ntquerysysteminformation class 0x23
    def _audit_kernel_debugger(self):
        try:
            ntdll = ctypes.windll.ntdll
            debug_info = (ctypes.c_uint8 * 2)()
            ret_len = ctypes.c_ulong()
            status = ntdll.NtQuerySystemInformation(0x23, ctypes.byref(debug_info), ctypes.sizeof(debug_info), ctypes.byref(ret_len))
            if status == 0 and (debug_info[0] or not debug_info[1]):
                self._record("flagged", "kernel debugger probe", self.boot_str, "-",
                             "active kernel debugger attached (windbg/kd)", "critical",
                             "active kernel debugger attached (windbg/kd) detected via ntquerysysteminformation class 0x23. allows dynamic kernel memory patching.", "", "")
            else:
                self._record("clean", "kernel debugger probe", self.boot_str, "-", "ok - no kernel debugger present", "low", "", "", "")
        except Exception:
            self._record("clean", "kernel debugger probe", self.boot_str, "-", "clean", "low", "", "", "")

    # scan system for known vulnerable exploit drivers (byovd / loldrivers)
    def _audit_vulnerable_drivers_extended(self):
        byovd_catalog = [
            "rtcore64.sys", "gdrv.sys", "mhyprot2.sys", "capcom.sys", "iqvw64e.sys",
            "procexp.sys", "echo.sys", "dbkp.sys", "dbk64.sys", "dbutil_2_3.sys",
            "kprocesshacker.sys", "asusgio.sys", "atsiv.sys", "glckio2.sys", "eneio64.sys",
            "amdrvr64.sys", "winring0.sys", "directio64.sys", "phymem64.sys", "asrrdrv.sys"
        ]
        drivers_dir = r"C:\Windows\System32\drivers"
        found = []
        for drv in byovd_catalog:
            p = os.path.join(drivers_dir, drv)
            if os.path.exists(p):
                found.append(drv)
            else:
                out = self._run_cmd(f"sc query {os.path.splitext(drv)[0]}")
                if "RUNNING" in out or "STOPPED" in out:
                    found.append(f"{drv} (service)")
        if found:
            primary = found[0].replace(" (service)", "")
            full_p = os.path.join(drivers_dir, primary)
            self._record("flagged", "vulnerable exploit drivers (byovd)", self.boot_str, "-",
                         f"high-risk signed exploit driver staged: {', '.join(found)}", "critical",
                         "bring your own vulnerable driver (byovd): high-risk signed drivers with known read/write physical memory ioctl primitives detected.",
                         full_p if os.path.exists(full_p) else "", primary)
        else:
            self._record("clean", "vulnerable exploit drivers (byovd)", self.boot_str, "-",
                         "ok - no known byovd exploit drivers registered", "low", "", drivers_dir, "")

    # check code integrity vulnerable driver blocklist enforcement
    def _audit_hvci_driver_blocklist(self):
        blocklist = False
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\CI\Config") as k:
                val, _ = winreg.QueryValueEx(k, "VulnerableDriverBlocklistEnable")
                blocklist = (val == 1)
        except Exception:
            blocklist = False
        if not blocklist:
            self._record("suspicious", "vulnerable driver blocklist", self.boot_str, "-",
                         "microsoft vulnerable driver blocklist disabled", "medium",
                         "vulnerable driver blocklist is disabled in code integrity configuration.", "", "VulnerableDriverBlocklistEnable")
        else:
            self._record("clean", "vulnerable driver blocklist", self.boot_str, "-",
                         "ok - vulnerable driver blocklist active", "low", "", "", "VulnerableDriverBlocklistEnable")

    # check for interception driver used by hardware aimbots/macros
    def _audit_input_hooks(self):
        interception = r"C:\Windows\System32\drivers\interception.sys"
        has_srv = "RUNNING" in self._run_cmd("sc query interception")
        if os.path.exists(interception) or has_srv:
            self._record("flagged", "input emulation drivers", self.boot_str, "-",
                         "interception driver detected (macro / aimbot hook)", "high",
                         "interception.sys kernel filter driver detected. intercepts and injects hardware mouse/keyboard packets without synthetic flags (llmhf_injected), commonly used by aimbots and recoil macros.",
                         interception if os.path.exists(interception) else "", "interception.sys")
        else:
            self._record("clean", "input emulation drivers", self.boot_str, "-",
                         "ok - standard input driver stack verified", "low", "", r"c:\windows\system32\drivers", "interception.sys")

    # check for volatile ramdisk drivers (e.g. imdisk)
    def _audit_ramdisk_drivers(self):
        if "RUNNING" in self._run_cmd("sc query imdisk"):
            self._record("flagged", "ramdisk volatile storage", self.boot_str, "-",
                         "imdisk virtual disk running (ephemeral execution)", "high",
                         "imdisk virtual disk driver is running. volatile ram disks are commonly used by cheat loaders to prevent disk forensics.", "", "imdisk.sys")
        else:
            self._record("clean", "ramdisk volatile storage", self.boot_str, "-", "ok - no imdisk service active", "low", "", "", "")

    # check eventlog service startup mode and runtime status
    def _audit_eventlog_integrity(self):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\EventLog") as k:
                start_mode, _ = winreg.QueryValueEx(k, "Start")
                if start_mode != 2:
                    self._record("flagged", "eventlog service state", self.boot_str, "-",
                                 f"eventlog start mode altered ({start_mode})", "critical",
                                 "eventlog startup set to manual or disabled.", "", "")
                    return
            if "RUNNING" not in self._run_cmd("sc query EventLog"):
                self._record("flagged", "eventlog service state", self.boot_str, "-",
                             "eventlog service stopped or thread suspended", "critical",
                             "audit logging suppressed by terminating or suspending eventlog service threads.", "", "")
            else:
                self._record("clean", "eventlog service state", self.boot_str, "-", "ok - operational", "low", "", "", "")
        except Exception:
            self._record("suspicious", "eventlog service state", self.boot_str, "-", "query failed", "medium", "", "", "")

    # check event logs for manual log clearing events 1102 and 104
    def _audit_log_clearing_events(self):
        sec_evts = self._query_wevtutil_xml("Security", "*[System[(EventID=1102)]]", 1)
        if sec_evts:
            node = sec_evts[0].find(".//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated")
            t_str = node.attrib.get("SystemTime", "-") if node is not None else "-"
            self._record("flagged", "security log tampering", self.boot_str, t_str,
                         "event 1102 logged: security audit log was manually cleared", "critical",
                         "event id 1102 logged: security audit log was explicitly cleared. definitive indicator of anti-forensic activity.", "", "")
        else:
            self._record("clean", "security log tampering", self.boot_str, "-", "ok - security log intact", "low", "", "", "")

        sys_evts = self._query_wevtutil_xml("System", "*[System[(EventID=104)]]", 1)
        if sys_evts:
            node = sys_evts[0].find(".//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated")
            t_str = node.attrib.get("SystemTime", "-") if node is not None else "-"
            self._record("flagged", "system log tampering", self.boot_str, t_str,
                         "event 104 logged: system event log was manually cleared", "critical",
                         "event id 104 logged: system event log was cleared.", "", "")
        else:
            self._record("clean", "system log tampering", self.boot_str, "-", "ok - system log intact", "low", "", "", "")

    # check kernel-general event id 1 for manual system clock modifications
    def _audit_clock_tampering(self):
        events = self._query_wevtutil_xml("System", "*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and (EventID=1)]]", 1)
        if events:
            node = events[0].find(".//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated")
            t_str = node.attrib.get("SystemTime", "-") if node is not None else "-"
            self._record("flagged", "system clock shift", self.boot_str, t_str,
                         "event 1 logged: system time shifted manually", "critical",
                         "kernel-general event id 1 logged: system time was manually adjusted. used for timestomping or cheat license manipulation.", "", "")
        else:
            self._record("clean", "system clock shift", self.boot_str, "-", "ok - no manual clock shifts", "low", "", "", "")

    # detect minint registry evasion key used to mimic winpe
    def _audit_minint_registry(self):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\MiniNT"):
                self._record("flagged", "minint evasion registry", self.boot_str, "-",
                             "minint key active (winpe evasion mode)", "critical",
                             "minint registry subkey detected. forces windows into winpe mode, suppressing event viewer and telemetry policies.", "", "MiniNT")
        except FileNotFoundError:
            self._record("clean", "minint evasion registry", self.boot_str, "-", "ok - minint key absent", "low", "", "")
        except Exception:
            self._record("clean", "minint evasion registry", self.boot_str, "-", "nominal", "low", "", "")

    # check powershell scriptblock logging policy status
    def _audit_powershell_telemetry(self):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging") as k:
                val, _ = winreg.QueryValueEx(k, "EnableScriptBlockLogging")
                if val == 0:
                    self._record("suspicious", "powershell telemetry", self.boot_str, "-",
                                 "scriptblock logging is explicitly turned off via local policy", "medium",
                                 "powershell scriptblock logging explicitly disabled via local policy (event id 4104 suppressed).", "", "EnableScriptBlockLogging")
                else:
                    self._record("clean", "powershell telemetry", self.boot_str, "-", "ok - scriptblock logging policy active", "low", "", "EnableScriptBlockLogging")
        except Exception:
            self._record("clean", "powershell telemetry", self.boot_str, "-", "ok - policy default", "low", "", "")

    # scan psreadline terminal history for anti-forensic cleaning commands
    def _audit_powershell_history(self):
        ps_history = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
        if os.path.exists(ps_history):
            try:
                with open(ps_history, "r", encoding="utf-8", errors="ignore") as f:
                    lines = [l.strip() for l in f if l.strip()]
                cheat_commands = []
                patterns = ["wevtutil", "deletejournal", "sc stop", "kdmapper", "kdu", "driver", "certutil", "downloadstring", "invoke-expression"]
                for line in lines:
                    line_lower = line.lower()
                    if any(p in line_lower for p in patterns):
                        cheat_commands.append(line)
                if cheat_commands:
                    sample = cheat_commands[-1]
                    self._record("flagged", "powershell console history", self.boot_str, "-",
                                 f"suspicious command staged: {sample[:70]}", "high",
                                 f"psreadline console history contains administrative or anti-forensic commands: {sample}", ps_history, "ConsoleHost_history.txt")
                else:
                    self._record("clean", "powershell console history", self.boot_str, "-",
                                 f"ok - {len(lines)} commands retained without suspicious patterns", "low", "", ps_history, "")
            except Exception:
                self._record("clean", "powershell console history", self.boot_str, "-", "accessible", "low", "", ps_history, "")
        else:
            self._record("clean", "powershell console history", self.boot_str, "-", "psreadline history absent", "low", "", "")

    # verify defender real-time monitoring policy
    def _audit_defender_policies(self):
        try:
            def_key = r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, def_key) as k:
                val, _ = winreg.QueryValueEx(k, "DisableRealtimeMonitoring")
                if val == 1:
                    self._record("flagged", "defender realtime protection", self.boot_str, "-",
                                 "disablerealtimemonitoring is active via policy", "critical",
                                 "windows defender realtime monitoring disabled via registry policy.", "", "DisableRealtimeMonitoring")
                    return
        except Exception:
            pass
        self._record("clean", "defender realtime protection", self.boot_str, "-", "ok - realtime monitoring enabled", "low", "", "")

    # check program compatibility assistant policy
    def _audit_pca_policy(self):
        try:
            pca_key = r"SOFTWARE\Policies\Microsoft\Windows\AppCompat"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, pca_key) as k:
                val, _ = winreg.QueryValueEx(k, "DisablePCA")
                if val == 1:
                    self._record("flagged", "program compatibility assistant", self.boot_str, "-",
                                 "disablepca policy enabled (execution telemetry disabled)", "high",
                                 "program compatibility assistant disabled via registry policy (execution telemetry suppressed).", "", "DisablePCA")
                    return
        except Exception:
            pass
        self._record("clean", "program compatibility assistant", self.boot_str, "-", "ok - pca active", "low", "", "")

    # check diagnostic policy service
    def _audit_dps_service(self):
        if "RUNNING" in self._run_cmd("sc query dps"):
            self._record("clean", "diagnostic policy (dps)", self.boot_str, "-", "ok - dps running (srudb active)", "low", "", "")
        else:
            self._record("flagged", "diagnostic policy (dps)", self.boot_str, "-",
                         "dps service is stopped/disabled (srudb logging bypass)", "high",
                         "diagnostic policy service (dps) is stopped or disabled. suppresses execution logging into srudb.dat.", "", "dps")

    # check dns client cache for suspicious paste domains or cheat endpoints
    def _audit_dns_client_cache(self):
        out = self._run_cmd("ipconfig /displaydns")
        bad_domains = ["rentry.co", "hastebin.com", "pastebin.com", "anonfiles", "gofile.io", "catbox.moe", "cheat", "spoofer", "aimbot", "discordapp.com/api/webhooks"]
        matched = []
        for d in bad_domains:
            if d in out.lower():
                matched.append(d)
        if matched:
            self._record("flagged", "dns resolution cache", self.boot_str, "-",
                         f"suspicious network domains cached: {', '.join(set(matched))}", "high",
                         "dns resolution cache contains lookups to high-risk staging sites, discord webhooks, or cheat endpoints.", "", matched[0])
        else:
            self._record("clean", "dns resolution cache", self.boot_str, "-", "ok - dns resolver cache contains no high-risk cheat domains", "low", "", "")

    # check connected external storage devices in usbstor
    def _audit_usbstor_devices(self):
        p = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
        devices = []
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, p) as k:
                sub_count, _, _ = winreg.QueryInfoKey(k)
                for i in range(sub_count):
                    devices.append(winreg.EnumKey(k, i))
            if devices:
                self._record("suspicious", "usb mass storage history", self.boot_str, "-",
                             f"{len(devices)} external storage devices logged in usbstor", "medium",
                             f"usbstor records external storage hardware: {', '.join(devices[:3])}", "", "USBSTOR")
            else:
                self._record("clean", "usb mass storage history", self.boot_str, "-", "0 usbstor entries recorded", "low", "", "USBSTOR")
        except Exception:
            self._record("clean", "usb mass storage history", self.boot_str, "-", "usbstor nominal", "low", "", "")

    # check setupapi device installation log for truncation
    def _audit_setupapi_logs(self):
        p = r"C:\Windows\INF\setupapi.dev.log"
        if os.path.exists(p):
            try:
                sz_mb = os.path.getsize(p) / (1024 * 1024)
                if sz_mb < 0.1:
                    self._record("suspicious", "setupapi device log", self.boot_str, "-",
                                 f"setupapi.dev.log truncated ({sz_mb:.2f} mb)", "medium",
                                 "setupapi device installation log purged to conceal external hardware attachments.", p, "setupapi.dev.log")
                else:
                    self._record("clean", "setupapi device log", self.boot_str, "-",
                                 f"ok - active setupapi log intact ({sz_mb:.1f} mb)", "low", "", p, "setupapi.dev.log")
            except Exception:
                self._record("clean", "setupapi device log", self.boot_str, "-", "setupapi nominal", "low", "", p)
        else:
            self._record("clean", "setupapi device log", self.boot_str, "-", "setupapi.dev.log absent", "low", "", "")

    # check windows error reporting archives for cheat crashes
    def _audit_wer_reports(self):
        wer_dir = r"C:\ProgramData\Microsoft\Windows\WER\ReportArchive"
        if os.path.exists(wer_dir):
            try:
                reports = os.listdir(wer_dir)
                cheats = [r for r in reports if any(t in r.lower() for t in ["cheat", "inject", "hook", "loader"])]
                if cheats:
                    self._record("flagged", "windows error reporting", self.boot_str, "-",
                                 f"crash dumps matched cheat names: {cheats[0][:60]}", "high",
                                 f"wer crash archive retained unhandled crash report: {cheats[0]}",
                                 os.path.join(wer_dir, cheats[0]), cheats[0])
                else:
                    self._record("clean", "windows error reporting", self.boot_str, "-",
                                 f"ok - {len(reports)} crash reports nominal", "low", "", wer_dir, "")
            except Exception:
                self._record("clean", "windows error reporting", self.boot_str, "-", "nominal", "low", "", wer_dir)
        else:
            self._record("clean", "windows error reporting", self.boot_str, "-", "wer archive nominal", "low", "", "")

    # scan game process memory for unbacked executable private pages (reflective injection)
    def _audit_unbacked_executable_memory_all(self):
        kernel32 = ctypes.windll.kernel32
        target_processes = []
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap != -1:
            pe32 = processentry32w()
            pe32.dwSize = ctypes.sizeof(processentry32w)
            success = kernel32.Process32FirstW(snap, ctypes.byref(pe32))
            while success:
                name = pe32.szExeFile.lower()
                # filter explicitly for competitive games and injectors
                if any(x in name for x in ["game", "cs2", "valorant", "fivem", "minecraft", "fortnite", "r5apex", "cheat"]):
                    target_processes.append((pe32.th32ProcessID, pe32.szExeFile))
                success = kernel32.Process32NextW(snap, ctypes.byref(pe32))
            kernel32.CloseHandle(snap)

        if not target_processes:
            self._record("clean", "process memory backing", self.boot_str, "-",
                         "ok - no active target game processes found to audit", "low",
                         "no matching target game executables currently active for memory query.", "", "")
            return

        sys_info = system_info()
        kernel32.GetSystemInfo(ctypes.byref(sys_info))
        min_addr = sys_info.lpMinimumApplicationAddress or 0x10000
        max_addr = sys_info.lpMaximumApplicationAddress or 0x7FFFFFFEFFFF

        injected_procs = []
        for pid, name in target_processes:
            h_proc = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if not h_proc:
                continue
            curr_addr = int(min_addr) if isinstance(min_addr, int) else (min_addr.value if min_addr else 0x10000)
            stop_addr = int(max_addr) if isinstance(max_addr, int) else (max_addr.value if max_addr else 0x7FFFFFFEFFFF)
            mbi = memory_basic_information()
            unbacked_rwx = 0
            while curr_addr < stop_addr:
                res = kernel32.VirtualQueryEx(h_proc, ctypes.c_void_p(curr_addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
                if res == 0:
                    break
                # flag unbacked private committed memory with execute permissions
                if mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE:
                    if mbi.Protect in (PAGE_EXECUTE, page_execute_read, page_execute_readwrite, page_execute_writecopy):
                        unbacked_rwx += 1
                curr_addr += mbi.RegionSize
            kernel32.CloseHandle(h_proc)
            if unbacked_rwx > 0:
                injected_procs.append(f"{name} (pid {pid}: {unbacked_rwx} unbacked pages)")

        if injected_procs:
            self._record("flagged", "process memory backing", self.boot_str, "-",
                         f"unbacked executable code detected: {', '.join(injected_procs)[:80]}", "critical",
                         "private committed executable memory without backing file image on disk; signature of reflective injection.", "", "")
        else:
            self._record("clean", "process memory backing", self.boot_str, "-",
                         f"ok - audited {len(target_processes)} game processes without unbacked code", "low", "", "")

# main tkinter gui application
class timetraceapp:
    def __init__(self, root):
        self.root = root
        self.root.title("timetrace++")
        self.root.geometry("1240x700")
        self.root.minsize(980, 520)
        self.root.configure(bg="#121212")

# load application icon (pyinstaller & standalone compatible)
        base_dir = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        ico_path = os.path.join(base_dir, "assets", "icon.ico")
        if not os.path.exists(ico_path):
            ico_path = os.path.join(base_dir, "icon.ico")
        if not os.path.exists(ico_path):
            ico_path = os.path.join(base_dir, "favicon.ico")

        if os.path.exists(ico_path):
            try:
                self.root.iconbitmap(ico_path)
            except Exception:
                pass

        if os.path.exists(ico_path):
            try:
                self.root.iconbitmap(ico_path)
            except Exception:
                pass

        # filter state variables
        self.var_flagged = tk.BooleanVar(value=True)
        self.var_clean = tk.BooleanVar(value=True)
        self.search_var = tk.StringVar()

        # data storage and sorting registers
        self.all_entries = []
        self.visible_rows = []
        self.selected = set()
        self.scroll_y = 0
        self.hover = None
        self.resize_job = None
        self.is_scanning = False
        self.sort_col = 0
        self.sort_reverse = False

        self.result_queue = queue.Queue()

        # canvas table layout parameters
        self.GRAD_TOP = "#202020"
        self.GRAD_BOTTOM = "#ff69b4"
        self.HEAD_H = 28
        self.ROW_H = 24
        self.PAD = 12

        self.COLUMNS = [
            ("state", "state", 100),
            ("subsystem", "check / subsystem", 230),
            ("baseline", "baseline / boot time", 150),
            ("artifact_time", "artifact timestamp", 150),
            ("details", "result & audit findings", 420),
            ("risk", "risk level", 90),
        ]
        self.STATE_COLOR = {
            "clean": "#4ade80",
            "flagged": "#f87171",
            "suspicious": "#facc15",
        }
        self.RISK_COLOR = {
            "critical": "#ff6b8a",
            "high": "#f87171",
            "medium": "#facc15",
            "low": "#cbd5e1",
            "info": "#cbd5e1",
        }

        self.build_ui()
        self.search_var.trace_add("write", lambda *args: self.apply_filters())
        apply_dark_titlebar(root)

        # start async audit scan immediately
        self.start_async_scan()
        self.root.after(40, self.process_queue)

    # construct navigation controls, search box, and table canvas
    def build_ui(self):
        top_frame = tk.Frame(self.root, bg=self.GRAD_TOP, padx=14, pady=10)
        top_frame.pack(fill=tk.X)

        # smooth rounded search box wrapper
        search_w, search_h, search_r = 260, 32, 12
        search_canvas = tk.Canvas(top_frame, width=search_w, height=search_h, bg=self.GRAD_TOP, highlightthickness=0, bd=0)
        search_canvas.pack(side=tk.LEFT, padx=(0, 14))

        sb_bg = "#2b2b2b"
        search_canvas.create_arc((0, 0, search_r*2, search_r*2), start=90, extent=90, fill=sb_bg, outline="")
        search_canvas.create_arc((search_w - search_r*2, 0, search_w, search_r*2), start=0, extent=90, fill=sb_bg, outline="")
        search_canvas.create_arc((0, search_h - search_r*2, search_r*2, search_h), start=180, extent=90, fill=sb_bg, outline="")
        search_canvas.create_arc((search_w - search_r*2, search_h - search_r*2, search_w, search_h), start=270, extent=90, fill=sb_bg, outline="")
        search_canvas.create_rectangle((search_r, 0, search_w - search_r, search_h), fill=sb_bg, outline="")
        search_canvas.create_rectangle((0, search_r, search_w, search_h - search_r), fill=sb_bg, outline="")

        search_entry = tk.Entry(
            search_canvas,
            textvariable=self.search_var,
            bg=sb_bg,
            fg="#cccccc",
            insertbackground="#ffffff",
            relief=tk.FLAT,
            font=("segoe ui", 9),
            bd=0
        )
        search_canvas.create_window(search_w // 2, search_h // 2, window=search_entry, width=search_w - 24, height=20)
        search_entry.insert(0, "search artifacts...")
        search_entry.bind("<FocusIn>", lambda e: search_entry.delete(0, tk.END) if search_entry.get() == "search artifacts..." else None)

        # filter checkboxes
        for text, var in [
            ("flagged / suspicious", self.var_flagged),
            ("clean / verified", self.var_clean)
        ]:
            cb = tk.Checkbutton(
                top_frame,
                text=text,
                variable=var,
                command=self.apply_filters,
                bg=self.GRAD_TOP,
                fg="#cccccc",
                selectcolor="#3a3a3a",
                activebackground=self.GRAD_TOP,
                activeforeground="#ffffff",
                font=("segoe ui", 9)
            )
            cb.pack(side=tk.LEFT, padx=6)

        # export popup menu handler
        def show_export_menu():
            menu = tk.Menu(self.root, tearoff=0, bg="#1e1e1e", fg="#ffffff", activebackground="#ff69b4", activeforeground="#000000", font=("segoe ui", 9))
            menu.add_command(label="export standalone html report", command=self.export_html)
            menu.add_command(label="export structured json", command=self.export_json)
            menu.add_command(label="export delimited csv", command=self.export_csv)
            x = self.btn_export.winfo_rootx()
            y = self.btn_export.winfo_rooty() + self.btn_export.winfo_height()
            menu.post(x, y)

        # rounded action buttons on right side
        self.btn_export = RoundedButton(
            top_frame,
            text="export report",
            command=show_export_menu,
            width=130,
            height=32,
            radius=12,
            bg_color="#3a3a3a",
            hover_color="#4a4a4a"
        )
        self.btn_export.pack(side=tk.RIGHT, padx=4)

        self.btn_refresh = RoundedButton(
            top_frame,
            text="rescan",
            command=self.start_async_scan,
            width=130,
            height=32,
            radius=12,
            bg_color="#3a3a3a",
            hover_color="#4a4a4a"
        )
        self.btn_refresh.pack(side=tk.RIGHT, padx=4)

        # bottom status bar
        bottom_frame = tk.Frame(self.root, bg=self.GRAD_BOTTOM, padx=12, pady=5)
        bottom_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_left = tk.Label(
            bottom_frame,
            text="initializing forensic auditor...",
            bg=self.GRAD_BOTTOM,
            fg="#260512",
            font=("segoe ui", 9)
        )
        self.status_left.pack(side=tk.LEFT)

        status_right = tk.Label(
            bottom_frame,
            text="timetrace++ | double-click row for inspection & virustotal | click header to sort",
            bg=self.GRAD_BOTTOM,
            fg="#1a0410",
            font=("segoe ui", 9, "bold")
        )
        status_right.pack(side=tk.RIGHT)

        # main table canvas
        self.canvas = tk.Canvas(self.root, bg=self.GRAD_TOP, highlightthickness=0, bd=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.canvas.bind("<Configure>", self.on_resize)
        self.canvas.bind("<MouseWheel>", self.on_wheel)
        self.canvas.bind("<Button-1>", self.on_click)
        self.canvas.bind("<Double-Button-1>", self.on_double_click)
        self.canvas.bind("<Button-3>", self.on_right_click)
        self.canvas.bind("<Motion>", self.on_motion)
        self.canvas.bind("<Leave>", self.on_leave)
        self.root.bind("<Return>", lambda e: self.open_inspector())

    # start background thread to execute system audit
    def start_async_scan(self):
        if self.is_scanning:
            return
        self.is_scanning = True
        self.all_entries = []
        self.visible_rows = []
        self.btn_refresh.config_state(tk.DISABLED, bg="#2a2a2a")
        self.status_left.config(text="scanning system artifacts asynchronously...")
        self.redraw()

        engine = auditengine(self.result_queue)
        t = threading.Thread(target=engine.run_all, daemon=True)
        t.start()

    # drain result queue sent by background thread
    def process_queue(self):
        try:
            while True:
                msg_type, payload = self.result_queue.get_nowait()
                if msg_type == "ENTRY":
                    self.all_entries.append(payload)
                    self.apply_filters()
                elif msg_type == "COMPLETE":
                    self.is_scanning = False
                    self.btn_refresh.config_state(tk.NORMAL, bg="#3a3a3a")
                    self.apply_filters()
        except queue.Empty:
            pass
        self.root.after(40, self.process_queue)

    # debounce window resize event
    def on_resize(self, event):
        if self.resize_job:
            self.canvas.after_cancel(self.resize_job)
        self.resize_job = self.canvas.after(40, self.redraw)

    # repaint entire canvas
    def redraw(self):
        self.resize_job = None
        self.clamp_scroll()
        self.paint_background()
        self.paint_table()

    # draw dark vertical gradient
    def paint_background(self):
        c = self.canvas
        c.delete("bg")
        w = max(1, c.winfo_width())
        h = max(1, c.winfo_height())
        for y in range(h):
            c.create_rectangle(
                0, y, w, y + 1,
                fill=mix(self.GRAD_TOP, self.GRAD_BOTTOM, y / (h - 1) if h > 1 else 0),
                outline="",
                tags="bg"
            )

    # calculate total height of all visible rows
    def content_height(self):
        return self.HEAD_H + 8 + len(self.visible_rows) * self.ROW_H + 8

    # clamp scroll position within valid bounds
    def clamp_scroll(self):
        limit = max(0, self.content_height() - max(1, self.canvas.winfo_height()))
        self.scroll_y = max(0, min(self.scroll_y, limit))

    # truncate strings that exceed column width
    def fit_text(self, text, width):
        room = max(4, int((width - 14) / 6))
        if len(text) <= room:
            return text
        return text[: room - 1] + "…"

    # paint table headers and visible rows
    def paint_table(self):
        c = self.canvas
        c.delete("table")
        w = max(1, c.winfo_width())
        h = max(1, c.winfo_height())
        if w <= 1 or h <= 1:
            return

        c.create_rectangle(0, 0, w, self.HEAD_H, fill="#191919", outline="", tags="table")
        x = self.PAD
        for col_idx, (_cid, title, cw) in enumerate(self.COLUMNS):
            t_str = title
            if col_idx == self.sort_col:
                t_str += " ^" if not self.sort_reverse else " v"
            c.create_text(
                x + 6, self.HEAD_H // 2, text=t_str, anchor="w",
                fill="#f3f4f6", font=("segoe ui", 8, "bold"), tags="table"
            )
            x += cw

        y = self.HEAD_H + 8 - self.scroll_y
        for index, row in enumerate(self.visible_rows):
            if y + self.ROW_H >= self.HEAD_H and y <= h:
                self.paint_row(index, row, y, w)
            y += self.ROW_H

        self.paint_scrollbar(w, h)

    # render single row with hover and selection blend
    def paint_row(self, index, row, y, w):
        c = self.canvas
        state = str(row[0]).lower()
        here = mix(self.GRAD_TOP, self.GRAD_BOTTOM, min(1.0, max(0.0, (y + self.ROW_H / 2) / max(1, self.canvas.winfo_height()))))
        bg = mix(here, "#000000", 0.5)
        if index in self.selected:
            bg = mix(bg, "#60a5fa", 0.35)
        elif index == self.hover:
            bg = mix(bg, "#ffffff", 0.08)

        c.create_rectangle(
            self.PAD, y, w - self.PAD - 8, y + self.ROW_H - 2,
            fill=bg, outline="", tags="table"
        )

        x = self.PAD
        for col, (_cid, _title, cw) in enumerate(self.COLUMNS):
            if col == 0:
                text = state
                color = self.STATE_COLOR.get(state, "#e5e7eb")
            elif col == 5:
                text = str(row[col]).lower()
                color = self.RISK_COLOR.get(text, "#cbd5e1")
            else:
                text = str(row[col])
                color = "#d1d5db"
            c.create_text(
                x + 6, y + (self.ROW_H - 2) / 2, text=self.fit_text(text, cw), anchor="w",
                fill=color, font=("segoe ui", 8), tags="table"
            )
            x += cw

    # render custom scrollbar
    def paint_scrollbar(self, w, h):
        content = self.content_height()
        view = h
        if content <= view or view <= self.HEAD_H + 10:
            return
        c = self.canvas
        track = view - self.HEAD_H - 4
        thumb = max(30, int(track * (view / content)))
        limit = content - view
        pos = (self.scroll_y / limit) if limit > 0 else 0
        top = self.HEAD_H + 2 + int((track - thumb) * pos)
        c.create_rectangle(w - 10, self.HEAD_H + 2, w - 5, h - 2, fill="#2a2a2a", outline="", tags="table")
        c.create_rectangle(w - 10, top, w - 5, top + thumb, fill="#f4f4f5", outline="", tags="table")

    # get row index from canvas y coordinate
    def row_at(self, y):
        if y <= self.HEAD_H:
            return None
        index = int((y - (self.HEAD_H + 8 - self.scroll_y)) // self.ROW_H)
        if 0 <= index < len(self.visible_rows):
            return index
        return None

    # handle mouse wheel scrolling
    def on_wheel(self, event):
        if self.content_height() <= max(1, self.canvas.winfo_height()):
            return "break"
        self.scroll_y -= int(event.delta / 120) * self.ROW_H * 3
        self.clamp_scroll()
        self.paint_table()
        return "break"

    # handle column header sorting and row selection
    def on_click(self, event):
        if event.y <= self.HEAD_H:
            x = self.PAD
            for col_idx, (_cid, _title, cw) in enumerate(self.COLUMNS):
                if x <= event.x < x + cw:
                    if self.sort_col == col_idx:
                        self.sort_reverse = not self.sort_reverse
                    else:
                        self.sort_col = col_idx
                        self.sort_reverse = False
                    self.apply_filters()
                    return
                x += cw
            return

        index = self.row_at(event.y)
        if index is None:
            self.selected.clear()
        elif event.state & 0x0004:
            self.selected.symmetric_difference_update({index})
        else:
            self.selected = {index}
        self.paint_table()

    # handle double click to inspect row finding
    def on_double_click(self, event):
        index = self.row_at(event.y)
        if index is not None:
            self.selected = {index}
            self.paint_table()
            self.open_inspector(index)

    # right click context menu with red disabled options
    def on_right_click(self, event):
        index = self.row_at(event.y)
        if index is not None:
            self.selected = {index}
            self.paint_table()

            row = self.visible_rows[index]
            target_path = row[7] if len(row) > 7 else ""
            target_name = row[8] if len(row) > 8 else ""

            has_file = is_file_existing(target_path)
            has_vt = is_vt_eligible(target_path, target_name)

            menu = tk.Menu(
                self.root, tearoff=0,
                bg="#141414", fg="#dcdcdc",
                activebackground="#ff69b4", activeforeground="#000000",
                disabledforeground="#ef4444",
                font=("segoe ui", 9)
            )
            menu.add_command(label="forensic inspection & details", command=lambda: self.open_inspector(index))
            menu.add_command(
                label="open in file explorer" if has_file else "open in file explorer (unavailable)",
                command=lambda: self.quick_explorer(index),
                state=tk.NORMAL if has_file else tk.DISABLED
            )
            menu.add_command(
                label="search on virustotal" if has_vt else "search on virustotal (unavailable)",
                command=lambda: self.quick_virustotal(index),
                state=tk.NORMAL if has_vt else tk.DISABLED
            )
            menu.add_command(
                label="search on web (is this proof of cheats?)",
                command=lambda: self.quick_web_search(index)
            )
            menu.add_separator()
            menu.add_command(label="copy finding details", command=lambda: self.quick_copy(index))
            menu.post(event.x_root, event.y_root)

    # track hover position
    def on_motion(self, event):
        index = self.row_at(event.y)
        if index != self.hover:
            self.hover = index
            self.paint_table()
        self.paint_tip(event)

    def on_leave(self, event):
        self.hover = None
        self.canvas.delete("tip")
        self.paint_table()

    # render tooltip on long texts
    def paint_tip(self, event):
        c = self.canvas
        c.delete("tip")
        if self.hover is None:
            return
        x = self.PAD
        col = None
        for i, (_cid, _title, cw) in enumerate(self.COLUMNS):
            if x <= event.x < x + cw:
                col = i
                break
            x += cw
        if col is None:
            return
        row = self.visible_rows[self.hover]
        full = f"{str(row[0]).lower()}" if col == 0 else str(row[col])
        if len(full) < 20:
            return
        w = max(1, c.winfo_width())
        room = min(int(w * 0.6), 620)
        text = self.fit_text(full, room)
        box = 6 * len(text) + 16
        tx = min(event.x + 14, max(4, w - box - 6))
        ty = min(event.y + 20, max(0, c.winfo_height() - 24))
        c.create_rectangle(tx, ty, tx + box, ty + 20, fill="#0b0b0b", outline="#ff69b4", tags="tip")
        c.create_text(tx + 8, ty + 10, text=text, anchor="w", fill="#f3f4f6", font=("segoe ui", 8), tags="tip")

    # quick action handlers
    def quick_explorer(self, index):
        if 0 <= index < len(self.visible_rows):
            row = self.visible_rows[index]
            target_path = row[7] if len(row) > 7 else ""
            target_name = row[8] if len(row) > 8 else ""
            open_in_explorer(target_path, target_name)

    def quick_virustotal(self, index):
        if 0 <= index < len(self.visible_rows):
            row = self.visible_rows[index]
            subsystem = row[1]
            target_path = row[7] if len(row) > 7 else ""
            target_name = row[8] if len(row) > 8 else ""
            open_virustotal(target_path, target_name, subsystem)

    def quick_web_search(self, index):
        if 0 <= index < len(self.visible_rows):
            row = self.visible_rows[index]
            subsystem = row[1]
            details = row[4]
            target_name = row[8] if len(row) > 8 else ""
            open_web_search(subsystem, details, target_name)

    def quick_copy(self, index):
        if 0 <= index < len(self.visible_rows):
            row = self.visible_rows[index]
            text = format_finding_text(row)
            self.root.clipboard_clear()
            self.root.clipboard_append(text)

    # open detailed modal inspection window
    def open_inspector(self, index=None):
        if index is None:
            if not self.selected:
                return
            index = next(iter(self.selected))
        if not (0 <= index < len(self.visible_rows)):
            return

        row = self.visible_rows[index]
        state, subsystem, baseline, artifact_time, details, risk = row[:6]
        explanation = row[6] if len(row) > 6 else "no additional details available."
        target_path = row[7] if len(row) > 7 else ""
        target_name = row[8] if len(row) > 8 else ""

        has_file = is_file_existing(target_path)
        has_vt = is_vt_eligible(target_path, target_name)

        modal = tk.Toplevel(self.root)
        modal.title(f"forensic inspector - {subsystem.lower()}")
        modal.geometry("710x560")
        modal.configure(bg="#121212")
        modal.resizable(False, False)
        modal.transient(self.root)
        modal.grab_set()

        apply_dark_titlebar(modal)

        # modal header
        head_frame = tk.Frame(modal, bg="#1a1a1a", padx=16, pady=12)
        head_frame.pack(fill=tk.X)

        title_lbl = tk.Label(head_frame, text=subsystem.lower(), bg="#1a1a1a", fg="#ffffff", font=("segoe ui", 11, "bold"))
        title_lbl.pack(anchor=tk.W)

        badge_frame = tk.Frame(head_frame, bg="#1a1a1a")
        badge_frame.pack(anchor=tk.W, pady=(4, 0))

        state_color = self.STATE_COLOR.get(state.lower(), "#ffffff")
        risk_color = self.RISK_COLOR.get(risk.lower(), "#ffffff")

        lbl_state = tk.Label(badge_frame, text=f"status: {state.lower()}", bg="#262626", fg=state_color, font=("segoe ui", 9, "bold"), padx=8, pady=2)
        lbl_state.pack(side=tk.LEFT, padx=(0, 8))

        lbl_risk = tk.Label(badge_frame, text=f"risk: {risk.lower()}", bg="#262626", fg=risk_color, font=("segoe ui", 9, "bold"), padx=8, pady=2)
        lbl_risk.pack(side=tk.LEFT)

        # modal body with metadata grid
        body_frame = tk.Frame(modal, bg="#121212", padx=16, pady=12)
        body_frame.pack(fill=tk.BOTH, expand=True)

        meta_grid = tk.Frame(body_frame, bg="#181818", padx=12, pady=10)
        meta_grid.pack(fill=tk.X, pady=(0, 10))

        fields = [
            ("baseline / boot:", baseline),
            ("artifact timestamp:", artifact_time),
            ("technical finding:", details.lower()),
            ("target path / binary:", target_path or target_name or "n/a"),
        ]

        for r_i, (label, val) in enumerate(fields):
            tk.Label(meta_grid, text=label, bg="#181818", fg="#9ca3af", font=("segoe ui", 8, "bold")).grid(row=r_i, column=0, sticky="w", pady=2)
            tk.Label(meta_grid, text=val, bg="#181818", fg="#f3f4f6", font=("segoe ui", 8)).grid(row=r_i, column=1, sticky="w", padx=(12, 0), pady=2)

        tk.Label(body_frame, text="forensic analysis & context:", bg="#121212", fg="#ff69b4", font=("segoe ui", 9, "bold")).pack(anchor=tk.W, pady=(0, 4))

        txt_frame = tk.Frame(body_frame, bg="#181818", padx=2, pady=2)
        txt_frame.pack(fill=tk.BOTH, expand=True)

        txt = tk.Text(txt_frame, bg="#181818", fg="#e5e7eb", font=("segoe ui", 9), wrap=tk.WORD, bd=0, padx=10, pady=8)
        txt.insert("1.0", explanation.lower())
        txt.config(state=tk.DISABLED)
        txt.pack(fill=tk.BOTH, expand=True)

        # bottom buttons bar (unavailable buttons shown in red)
        bottom_bar = tk.Frame(modal, bg="#1a1a1a", padx=16, pady=10)
        bottom_bar.pack(fill=tk.X, side=tk.BOTTOM)

        btn_explorer = tk.Button(
            bottom_bar,
            text="open in file explorer" if has_file else "open in file explorer (unavailable)",
            command=lambda: open_in_explorer(target_path, target_name),
            state=tk.NORMAL if has_file else tk.DISABLED,
            bg="#262626" if has_file else "#161616",
            fg="#ffffff" if has_file else "#ef4444",
            disabledforeground="#ef4444",
            activebackground="#333333",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            padx=10,
            pady=3,
            font=("segoe ui", 9)
        )
        btn_explorer.pack(side=tk.LEFT, padx=(0, 6))

        btn_vt = tk.Button(
            bottom_bar,
            text="virustotal scan" if has_vt else "virustotal scan (unavailable)",
            command=lambda: open_virustotal(target_path, target_name, subsystem),
            state=tk.NORMAL if has_vt else tk.DISABLED,
            bg="#262626" if has_vt else "#161616",
            fg="#38bdf8" if has_vt else "#ef4444",
            disabledforeground="#ef4444",
            activebackground="#333333",
            activeforeground="#38bdf8",
            relief=tk.FLAT,
            padx=10,
            pady=3,
            font=("segoe ui", 9)
        )
        btn_vt.pack(side=tk.LEFT, padx=(0, 6))

        btn_web = tk.Button(
            bottom_bar,
            text="search on web (is this proof of cheats?)",
            command=lambda: open_web_search(subsystem, details, target_name),
            bg="#262626",
            fg="#facc15",
            activebackground="#333333",
            activeforeground="#facc15",
            relief=tk.FLAT,
            padx=10,
            pady=3,
            font=("segoe ui", 9)
        )
        btn_web.pack(side=tk.LEFT, padx=(0, 6))

        def on_copy_click():
            self.root.clipboard_clear()
            self.root.clipboard_append(format_finding_text(row))
            btn_copy.config(text="copied to clipboard")
            modal.after(1500, lambda: btn_copy.config(text="copy finding"))

        btn_copy = tk.Button(
            bottom_bar,
            text="copy finding",
            command=on_copy_click,
            bg="#262626",
            fg="#ffffff",
            activebackground="#333333",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            padx=10,
            pady=3,
            font=("segoe ui", 9)
        )
        btn_copy.pack(side=tk.LEFT)

        btn_close = tk.Button(
            bottom_bar,
            text="close",
            command=modal.destroy,
            bg="#3a3a3a",
            fg="#ffffff",
            activebackground="#4a4a4a",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            padx=12,
            pady=3,
            font=("segoe ui", 9)
        )
        btn_close.pack(side=tk.RIGHT)

    # filter and sort table entries
    def apply_filters(self):
        if not hasattr(self, "canvas"):
            return

        query = self.search_var.get().strip().lower()
        if query == "search artifacts...":
            query = ""

        flagged_count = 0
        clean_count = 0
        rows = []

        for row in self.all_entries:
            state = row[0]
            if state in ("flagged", "suspicious"):
                flagged_count += 1
                if not self.var_flagged.get():
                    continue
            elif state == "clean":
                clean_count += 1
                if not self.var_clean.get():
                    continue

            if query and not any(query in str(val).lower() for val in row[:6]):
                continue

            rows.append(row)

        if self.sort_col is not None:
            rows.sort(key=lambda x: str(x[self.sort_col]).lower(), reverse=self.sort_reverse)

        self.visible_rows = rows
        self.selected.clear()
        self.clamp_scroll()
        self.paint_table()

        total = len(self.all_entries)
        status_text = f"showing {len(rows)} / {total} | {flagged_count} flagged/suspicious | {clean_count} clean @hardwareidentification on github"
        if self.is_scanning:
            status_text = f"scanning in progress... ({len(rows)} vectors collected)"
        self.status_left.config(text=status_text)

    # export results to csv
    def export_csv(self):
        f = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if not f:
            return
        try:
            with open(f, "w", newline="", encoding="utf-8") as out:
                writer = csv.writer(out)
                writer.writerow(["State", "Subsystem", "Baseline", "ArtifactTimestamp", "Details", "Risk", "Context", "TargetPath", "TargetName"])
                for row in self.all_entries:
                    writer.writerow(row)
            messagebox.showinfo("Export Successful", f"Exported {len(self.all_entries)} records to CSV.")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

    # export results to json
    def export_json(self):
        f = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if not f:
            return
        try:
            data = []
            for r in self.all_entries:
                data.append({
                    "state": r[0], "subsystem": r[1], "baseline": r[2], "artifact_time": r[3],
                    "details": r[4], "risk": r[5], "context": r[6], "target_path": r[7], "target_name": r[8]
                })
            with open(f, "w", encoding="utf-8") as out:
                json.dump(data, out, indent=2)
            messagebox.showinfo("Export Successful", f"Exported {len(self.all_entries)} records to JSON.")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

    # export standalone html audit report
    def export_html(self):
        f = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML Documents", "*.html")])
        if not f:
            return
        try:
            html = [
                "<!DOCTYPE html><html><head><meta charset='utf-8'><title>timetrace++ Forensic Report</title>",
                "<style>",
                "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 24px; }",
                "h1 { color: #38bdf8; font-size: 24px; margin-bottom: 4px; }",
                "table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }",
                "th { background: #1e293b; color: #94a3b8; text-align: left; padding: 10px; border-bottom: 1px solid #334155; }",
                "td { padding: 9px 10px; border-bottom: 1px solid #1e293b; }",
                "tr:hover { background: #1e293b; }",
                ".clean { color: #4ade80; font-weight: bold; }",
                ".flagged { color: #f87171; font-weight: bold; }",
                ".suspicious { color: #facc15; font-weight: bold; }",
                ".critical { color: #ef4444; font-weight: bold; }",
                "</style></head><body>",
                "<h1>timetrace++ Anti-Cheat Forensic Report</h1>",
                f"<p>Audit Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>",
                "<table><thead><tr><th>State</th><th>Subsystem</th><th>Baseline</th><th>Artifact Time</th><th>Finding</th><th>Risk</th><th>Target</th></tr></thead><tbody>"
            ]
            for r in self.all_entries:
                st_cls = r[0]
                rk_cls = r[5]
                html.append(
                    f"<tr><td class='{st_cls}'>{r[0].lower()}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td>"
                    f"<td>{r[4]}</td><td class='{rk_cls}'>{r[5].lower()}</td><td>{r[7] or r[8] or '-'}</td></tr>"
                )
            html.append("</tbody></table></body></html>")
            with open(f, "w", encoding="utf-8") as out:
                out.write("\n".join(html))
            messagebox.showinfo("Export Successful", f"Exported triage report to {f}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

# application entry point
if __name__ == "__main__":
    elevate_privileges()
    root = tk.Tk()
    app = timetraceapp(root)
    root.mainloop()