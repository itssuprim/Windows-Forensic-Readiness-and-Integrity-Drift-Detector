# collectors/audit.py
# Category H — Audit/Logging (3 artefacts, MIXED)
#   event_log_cleared    STATIC      (mode 1) — CRITICAL_ARTEFACT
#   defender_status      SEMI-STATIC (mode 2)
#   defender_exclusions  SEMI-STATIC (mode 2)

import json
import logging

import config as cfg
from collectors._shared import run_command

logger = logging.getLogger(__name__)

# Security 1102 = audit log cleared by an administrator.
# System 104    = event log cleared (legacy, also fires on Security log clear
#                 on some Windows versions).
# MaxEvents 100 per log — if more than 100 clearing events exist on a host
# that is itself a finding worth manual review, not a collection problem.
_LOG_CLEARED_PS = (
    "$e=@();"
    "$e+=Get-WinEvent -LogName Security"
    " -FilterXPath '*[System[EventID=1102]]' -MaxEvents 100 -EA SilentlyContinue;"
    "$e+=Get-WinEvent -LogName System"
    " -FilterXPath '*[System[EventID=104]]' -MaxEvents 100 -EA SilentlyContinue;"
    "$e | Select-Object"
    " @{N='time';E={$_.TimeCreated.ToString('o')}},"
    " @{N='event_id';E={$_.Id}},"
    " @{N='log_name';E={$_.LogName}}"
    " | ConvertTo-Json -Compress"
)

_DEFENDER_STATUS_PS = (
    "Get-MpComputerStatus | ForEach-Object {"
    "  [PSCustomObject]@{"
    "    AntivirusEnabled=$_.AntivirusEnabled;"
    "    RealTimeProtectionEnabled=$_.RealTimeProtectionEnabled;"
    "    AMServiceEnabled=$_.AMServiceEnabled;"
    "    NISEnabled=$_.NISEnabled;"
    "    AntivirusSignatureVersion=$_.AntivirusSignatureVersion;"
    "    AntivirusSignatureLastUpdated=if($_.AntivirusSignatureLastUpdated)"
    "      {$_.AntivirusSignatureLastUpdated.ToString('o')}else{$null}"
    "  }"
    "} | ConvertTo-Json -Compress"
)

_DEFENDER_EXCL_PS = (
    "$p=Get-MpPreference;"
    "[PSCustomObject]@{"
    "  Paths=$p.ExclusionPath;"
    "  Processes=$p.ExclusionProcess;"
    "  Extensions=$p.ExclusionExtension"
    "} | ConvertTo-Json -Compress"
)


def collect_event_log_cleared() -> dict:
    """Security event 1102 and System event 104 — audit log cleared.

    Keyed by ISO-8601 timestamp. An empty dict is the clean baseline;
    any entry is a finding. This artefact is a CRITICAL_ARTEFACT — it
    bypasses suppression and is always included in comparator output.

    Collecting last 100 events per log. More than 100 clearing events
    warrants manual review regardless of what this collector returns.
    """
    result = run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         _LOG_CLEARED_PS],
        timeout=cfg.SUBPROCESS_TIMEOUT_SECONDS,
    )
    if result["status"] not in ("ok", "nonzero_exit"):
        return {"status": result["status"], "data": {}}
    raw = result["stdout"].strip()
    if not raw:
        return {"status": "ok", "data": {}}
    try:
        events = json.loads(raw)
        if isinstance(events, dict):
            events = [events]
        data = {}
        for ev in events:
            t = ev.get("time", "")
            # suffix event_id to key to handle two events at the same second
            key = f"{t}_{ev.get('event_id', '')}"
            data[key] = {
                "time":     t,
                "event_id": ev.get("event_id"),
                "log_name": ev.get("log_name"),
            }
        return {"status": "ok", "data": data}
    except Exception as e:
        logger.error(f"event_log_cleared: JSON parse failed: {e}")
        return {"status": "error", "data": {}, "error": str(e)}


def collect_defender_status() -> dict:
    """Windows Defender / MpComputerStatus — real-time protection state.

    Key fields: AntivirusEnabled, RealTimeProtectionEnabled, AMServiceEnabled,
    NISEnabled, signature version and last-updated timestamp.
    A change in any field (especially RealTimeProtectionEnabled→False) is a
    high-priority drift signal.
    """
    result = run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         _DEFENDER_STATUS_PS],
        timeout=cfg.SUBPROCESS_TIMEOUT_SECONDS,
    )
    if result["status"] not in ("ok", "nonzero_exit"):
        return {"status": result["status"], "data": {}}
    raw = result["stdout"].strip()
    if not raw:
        return {"status": "ok", "data": {}}
    try:
        obj = json.loads(raw)
        # Get-MpComputerStatus returns a single object, never a list
        if isinstance(obj, list):
            obj = obj[0] if obj else {}
        data = {
            "antivirus_enabled":           obj.get("AntivirusEnabled"),
            "real_time_protection_enabled": obj.get("RealTimeProtectionEnabled"),
            "am_service_enabled":           obj.get("AMServiceEnabled"),
            "nis_enabled":                  obj.get("NISEnabled"),
            "signature_version":            obj.get("AntivirusSignatureVersion"),
            "signature_last_updated":       obj.get("AntivirusSignatureLastUpdated"),
        }
        return {"status": "ok", "data": data}
    except Exception as e:
        logger.error(f"defender_status: JSON parse failed: {e}")
        return {"status": "error", "data": {}, "error": str(e)}


def collect_defender_exclusions() -> dict:
    """Windows Defender exclusion lists from Get-MpPreference.

    Exclusions are a common attacker move — adding a path/process exclusion
    lets malware run without triggering scans. An addition here is a
    high-priority drift signal even on an otherwise quiet snapshot.
    Returns paths, processes, and extensions as sorted lists (sorted for
    stable comparator diffs — order in Get-MpPreference output is not stable).
    """
    result = run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         _DEFENDER_EXCL_PS],
        timeout=cfg.SUBPROCESS_TIMEOUT_SECONDS,
    )
    if result["status"] not in ("ok", "nonzero_exit"):
        return {"status": result["status"], "data": {}}
    raw = result["stdout"].strip()
    if not raw:
        return {"status": "ok", "data": {}}
    try:
        obj = json.loads(raw)

        def _norm(val) -> list:
            if val is None:
                return []
            if isinstance(val, list):
                return sorted(str(v) for v in val if v is not None)
            return sorted([str(val)])

        data = {
            "paths":      _norm(obj.get("Paths")),
            "processes":  _norm(obj.get("Processes")),
            "extensions": _norm(obj.get("Extensions")),
        }
        return {"status": "ok", "data": data}
    except Exception as e:
        logger.error(f"defender_exclusions: JSON parse failed: {e}")
        return {"status": "error", "data": {}, "error": str(e)}
