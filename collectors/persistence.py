# collectors/persistence.py
# Category C — Persistence (7 artefacts, MIXED)
#   run_keys_hklm    STATIC         (mode 1)
#   run_keys_hkcu    STATIC         (mode 1)
#   winlogon_keys    STATIC         (mode 1)
#   startup_folder_system STATIC    (mode 1)
#   wmi_subscriptions STATIC        (mode 1)
#   services         SEMI-STATIC    (mode 2)
#   scheduled_tasks  DYNAMIC        (mode 3, pre-filter: exclude \Microsoft\)

import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import config as cfg
from collectors._shared import read_registry_value, run_command

logger = logging.getLogger(__name__)

# ── CONSTANTS ─────────────────────────────────────────────────────
RUN_KEY       = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
RUN_KEY_HKLM  = RUN_KEY  # HKLM hive — machine-wide autostart
RUN_KEY_HKCU  = RUN_KEY  # HKCU hive — per-user autostart (same subkey path, different hive)
WINLOGON_KEY  = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
TASKS_ROOT    = Path(r"C:\Windows\System32\Tasks")
STARTUP_FOLDER = Path(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
TASK_NS       = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


# ═══════════════════════════════════════════════════════════════════
# STATIC collectors (mode 1)
# ═══════════════════════════════════════════════════════════════════

def collect_run_keys_hklm() -> dict:
    """HKLM Run key — machine-wide autostart registry entries."""
    result = read_registry_value("HKLM", RUN_KEY_HKLM)
    return {"status": result["status"], "data": result["data"]}


def collect_run_keys_hkcu() -> dict:
    """HKCU Run key — per-user autostart registry entries."""
    result = read_registry_value("HKCU", RUN_KEY_HKCU)
    return {"status": result["status"], "data": result["data"]}


def collect_winlogon_keys() -> dict:
    """Winlogon Userinit and Shell values — hijack detection.

    These two values are the canonical Winlogon hijack targets. Only
    collecting the three values relevant to persistence, not the full
    key, to keep the diff signal-to-noise ratio high.
    """
    result = read_registry_value("HKLM", WINLOGON_KEY)
    if result["status"] != "ok":
        return {"status": result["status"], "data": {}}

    raw = result["data"]
    data = {
        "Userinit":               raw.get("Userinit"),
        "Shell":                  raw.get("Shell"),
        "UserInitMprLogonScript": raw.get("UserInitMprLogonScript"),
    }
    return {"status": "ok", "data": data}


def collect_startup_folder_system() -> dict:
    """System startup folder — files here run for all users at login."""
    if not STARTUP_FOLDER.exists():
        return {"status": "not_found", "data": {}}

    data = {}
    try:
        for f in STARTUP_FOLDER.iterdir():
            if not f.is_file():
                continue
            target = _resolve_lnk(str(f)) if f.suffix.lower() == ".lnk" else None
            data[f.name] = {"target_path": target}
        return {"status": "ok", "data": data}
    except Exception as e:
        logger.error(f"startup_folder_system failed: {e}")
        return {"status": "error", "data": {}, "error": str(e)}


def _resolve_lnk(lnk_path: str) -> str | None:
    """Resolve a .lnk shortcut to its target via WScript.Shell."""
    try:
        import win32com.client
        shell = win32com.client.Dispatch("WScript.Shell")
        return shell.CreateShortcut(lnk_path).TargetPath
    except Exception:
        return None


def collect_wmi_subscriptions() -> dict:
    """WMI event subscription triplet via PowerShell.

    Uses PowerShell Get-WmiObject instead of the Python WMI library
    because root/subscription throws COM error 0x80041002 on clean
    Windows 11 VMs when queried via the Python WMI library.
    """
    import json

    def _ps_query(wmi_class):
        result = run_command(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"Get-WmiObject -Namespace root/subscription "
             f"-Class {wmi_class} -ErrorAction SilentlyContinue "
             f"| ConvertTo-Json -Depth 3"],
            timeout=cfg.SUBPROCESS_TIMEOUT_SECONDS,
        )
        raw = result.get("stdout", "").strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
            return data if isinstance(data, list) else [data]
        except Exception:
            return []

    try:
        filters = {}
        for f in _ps_query("__EventFilter"):
            name = f.get("Name", "unknown")
            filters[name] = {
                "query": f.get("Query"),
                "query_language": f.get("QueryLanguage"),
            }

        consumers = {}
        for cls in ["ActiveScriptEventConsumer", "CommandLineEventConsumer",
                    "LogFileEventConsumer", "NTEventLogEventConsumer", "SMTPEventConsumer"]:
            for obj in _ps_query(cls):
                name = obj.get("Name", "unknown")
                consumers[name] = {
                    "class": cls,
                    "action": (obj.get("CommandLineTemplate")
                               or obj.get("ScriptText")
                               or obj.get("Filename")),
                }

        bindings = {}
        for b in _ps_query("__FilterToConsumerBinding"):
            filter_ref = str(b.get("Filter", ""))
            consumer_ref = str(b.get("Consumer", ""))
            bindings[f"{filter_ref}|{consumer_ref}"] = {
                "filter": filter_ref,
                "consumer": consumer_ref,
            }

        return {
            "status": "ok",
            "data": {"filters": filters, "consumers": consumers, "bindings": bindings},
        }
    except Exception as e:
        logger.error(f"wmi_subscriptions failed: {e}")
        return {"status": "error", "data": {}, "error": str(e)}


# ═══════════════════════════════════════════════════════════════════
# DYNAMIC collector (mode 3)
# ═══════════════════════════════════════════════════════════════════

def collect_scheduled_tasks() -> dict:
    """Parse task XML files from C:\\Windows\\System32\\Tasks\\.

    Pre-filter (applied here, not in comparator): skip anything under
    the \\Microsoft\\ namespace — OS-managed tasks that change on every
    patch cycle. Only third-party and user-created tasks are collected.

    XML chosen over schtasks text output because:
    - Locale-independent (schtasks output is English-only fixed-width)
    - Handles multi-action and nested-trigger tasks correctly
    - Structured data, no regex parsing of display text
    """
    if not TASKS_ROOT.exists():
        return {"status": "not_found", "data": {}}

    data = {}
    try:
        for task_file in TASKS_ROOT.rglob("*"):
            if not task_file.is_file():
                continue

            # Pre-filter: skip Microsoft namespace
            relative = task_file.relative_to(TASKS_ROOT)
            if relative.parts and relative.parts[0].lower() == "microsoft":
                continue

            # Key format: leading backslash + forward-slash separators.
            # suppression.py SR-008 normalises with replace("\\","/") before
            # matching — both sides must use this same convention or the
            # suppressor breaks. Do not change one without changing the other.
            task_name = "\\" + str(relative).replace("\\", "/")
            task_def  = _parse_task_xml(task_file)
            if task_def is not None:
                data[task_name] = task_def

        return {"status": "ok", "data": data}
    except Exception as e:
        logger.error(f"scheduled_tasks failed: {e}")
        return {"status": "error", "data": {}, "error": str(e)}


def _parse_task_xml(task_file: Path) -> dict | None:
    """Parse one task XML file. Returns None on parse failure."""
    try:
        root = ET.parse(task_file).getroot()
        ns   = TASK_NS

        # Enabled state
        enabled = None
        settings = root.find(f"{ns}Settings")
        if settings is not None:
            el = settings.find(f"{ns}Enabled")
            enabled = el.text if el is not None else None

        # Principal (run-as account)
        run_as = None
        principals = root.find(f"{ns}Principals")
        if principals is not None:
            p = principals.find(f"{ns}Principal")
            if p is not None:
                uid = p.find(f"{ns}UserId")
                gid = p.find(f"{ns}GroupId")
                run_as = (uid.text if uid is not None
                          else gid.text if gid is not None else None)

        # Actions — all Exec actions in order
        actions = []
        actions_el = root.find(f"{ns}Actions")
        if actions_el is not None:
            for ex in actions_el.findall(f"{ns}Exec"):
                cmd  = ex.find(f"{ns}Command")
                args = ex.find(f"{ns}Arguments")
                actions.append({
                    "command":   cmd.text  if cmd  is not None else None,
                    "arguments": args.text if args is not None else None,
                })

        # Triggers — type tag + start boundary
        triggers = []
        triggers_el = root.find(f"{ns}Triggers")
        if triggers_el is not None:
            for trig in triggers_el:
                tag   = trig.tag.replace(ns, "")
                start = trig.find(f"{ns}StartBoundary")
                triggers.append({
                    "type":  tag,
                    "start": start.text if start is not None else None,
                })

        return {
            "enabled":  enabled,
            "run_as":   run_as,
            "actions":  actions,
            "triggers": triggers,
        }

    except ET.ParseError as e:
        logger.warning(f"XML parse error in {task_file.name}: {e}")
        return None
    except Exception as e:
        logger.warning(f"Unexpected error parsing {task_file.name}: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════
# SEMI-STATIC collector (mode 2)
# ═══════════════════════════════════════════════════════════════════

def collect_services() -> dict:
    """Services via PowerShell Get-WmiObject Win32_Service.

    Uses PowerShell instead of the Python wmi library to avoid COM errors
    on this VM (DEVLOG Session 3). Signing status uses a single batched PS
    call across all unique binary paths — a standard Windows 11 install has
    80-120 services; per-service calls would take 2-10 minutes.
    """
    import json

    result = run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "Get-WmiObject Win32_Service | Select-Object Name,DisplayName,"
         "PathName,StartMode,StartName,State | ConvertTo-Json -Compress -Depth 2"],
        timeout=cfg.SUBPROCESS_TIMEOUT_SECONDS * 2,
    )
    if result["status"] not in ("ok", "nonzero_exit"):
        return {"status": result["status"], "data": {}, "error": result.get("stderr", "")}
    raw = result["stdout"].strip()
    if not raw:
        return {"status": "error", "data": {}, "error": "Get-WmiObject returned no output"}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            parsed = [parsed]
    except Exception as e:
        logger.error(f"services: JSON parse failed: {e}")
        return {"status": "error", "data": {}, "error": str(e)}

    services = {}
    for svc in parsed:
        name = svc.get("Name", "")
        if not name:
            continue
        services[name] = {
            "display_name":   svc.get("DisplayName"),
            "binary_path":    svc.get("PathName"),
            "start_type":     svc.get("StartMode"),
            "run_as":         svc.get("StartName"),
            "state":          svc.get("State"),
            "signing_status": None,  # populated below
        }

    if not services:
        return {"status": "error", "data": {}, "error": "no services parsed from output"}

    # Batch signing status — one PS call for all unique exe paths
    signing_map = _batch_signing_status(
        {name: svc["binary_path"]
         for name, svc in services.items()
         if svc["binary_path"]}
    )
    for name, svc in services.items():
        svc["signing_status"] = signing_map.get(name, "unknown")

    return {"status": "ok", "data": services}


def _extract_exe_path(raw_path: str) -> str:
    """Extract the exe path from a service PathName.

    PathName examples:
      "C:\\Windows\\system32\\svchost.exe" -k netsvcs   → quoted, easy
      C:\\Windows\\System32\\lsass.exe                  → unquoted, no args
      C:\\Program Files\\App\\service.exe -param         → unquoted WITH space in path

    The original raw.split()[0] breaks for the third case — it returns
    'C:\\Program' instead of the full path. The fix finds the .exe boundary
    using a lazy regex that stops at the first .exe occurrence.
    """
    raw = raw_path.strip()
    if not raw:
        return ""
    # Case 1: double-quoted path (most robust — spaces handled by quotes)
    m = re.match(r'"([^"]+)"', raw)
    if m:
        return m.group(1)
    # Case 2: unquoted — match drive-letter path through .exe boundary.
    # Lazy *? stops at the FIRST .exe, which is the binary before any args.
    m = re.match(r'([A-Za-z]:[^\t\n"]*?\.exe)', raw, re.IGNORECASE)
    if m:
        return m.group(1)
    # Fallback for non-exe service paths (rare: drivers, kernel components)
    return raw.split()[0]


def _batch_signing_status(name_to_path: dict) -> dict:
    """Get Authenticode signing status for all service binaries in one PS call.

    Deduplicates by exe path (svchost.exe hosts many services — one
    signature check, many service entries). Returns {service_name: status}.
    """
    if not name_to_path:
        return {}

    # name -> exe_path (deduplicated exe_paths for PS call)
    name_to_exe = {
        name: _extract_exe_path(raw)
        for name, raw in name_to_path.items()
        if raw
    }

    # Build a PS hashtable: svcName -> exePath, output "name\tstatus" per line
    entries = []
    for name, exe in name_to_exe.items():
        # Escape single quotes for PS string literal
        safe_name = name.replace("'", "''")
        safe_exe  = exe.replace("'", "''")
        entries.append(f"@{{N='{safe_name}';E='{safe_exe}'}}")

    ps_array = ",".join(entries)
    ps_script = (
        f"$cache=@{{}};$pairs=@({ps_array});"
        "foreach($p in $pairs){"
        "  if(-not $cache.ContainsKey($p.E)){"
        "    try{$s=Get-AuthenticodeSignature -FilePath $p.E -EA SilentlyContinue;"
        "        $cache[$p.E]=if($s){$s.Status.ToString()}else{'Unknown'}}"
        "    catch{$cache[$p.E]='Error'}"
        "  }"
        "  Write-Output ($p.N+[char]9+$cache[$p.E])"
        "}"
    )

    result = run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        timeout=cfg.SUBPROCESS_TIMEOUT_SECONDS * 6,  # batch call needs longer
    )

    signing_map = {}
    if result["status"] not in ("ok", "nonzero_exit"):
        logger.warning(f"signing_status batch PS call failed: {result['status']}")
        return signing_map

    if result.get("stderr"):
        logger.warning(f"signing_status PS stderr: {result['stderr'][:500]}")

    if result["stdout"]:
        for line in result["stdout"].splitlines():
            line = line.strip()
            if "\t" in line:
                name, status = line.split("\t", 1)
                signing_map[name] = status

    if not signing_map:
        logger.warning(
            f"signing_status batch PS returned no results. "
            f"stdout preview: {result['stdout'][:300]}"
        )

    return signing_map