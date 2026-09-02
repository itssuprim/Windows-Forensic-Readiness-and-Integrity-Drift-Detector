# collectors/network.py
# Category E — Network (3 artefacts, MIXED)
#   hosts_file       STATIC      (mode 1)
#   firewall_rules   SEMI-STATIC (mode 2)
#   listening_ports  DYNAMIC     (mode 3, raw — filter "ports_below_1024"
#                                 is metadata for comparator.py, not applied here)

import json
import logging
from pathlib import Path

import config as cfg
from collectors._shared import run_command

logger = logging.getLogger(__name__)

HOSTS_FILE = Path(r"C:\Windows\System32\drivers\etc\hosts")

# Direction/Action/Enabled/Profile are PowerShell enums — .ToString() forces
# string output; without it ConvertTo-Json serializes them as integers.
_FW_PS = (
    "Get-NetFirewallRule | ForEach-Object {"
    "  [PSCustomObject]@{"
    "    Name=$_.Name;"
    "    DisplayName=$_.DisplayName;"
    "    Direction=$_.Direction.ToString();"
    "    Action=$_.Action.ToString();"
    "    Enabled=$_.Enabled.ToString();"
    "    Profile=$_.Profile.ToString()"
    "  }"
    "} | ConvertTo-Json -Compress"
)

# Get-Process runs once to build a PID→Name map; joined inline during the
# ForEach — no per-port Get-Process calls.
# Get-Process .Id is Int32; Get-NetTCPConnection .OwningProcess is UInt32.
# .NET hashtable equality fails across types even for equal values, so both
# sides must be cast to [int] for ContainsKey to match.
_PORTS_PS = (
    "$pm=@{};"
    "Get-Process | ForEach-Object { $pm[[int]$_.Id]=$_.Name };"
    "Get-NetTCPConnection -State Listen | ForEach-Object {"
    "  [PSCustomObject]@{"
    "    LocalAddress=$_.LocalAddress;"
    "    LocalPort=$_.LocalPort;"
    "    OwningProcess=$_.OwningProcess;"
    "    ProcessName=if($pm.ContainsKey([int]$_.OwningProcess)){$pm[[int]$_.OwningProcess]}else{'unknown'}"
    "  }"
    "} | ConvertTo-Json -Compress"
)


def collect_hosts_file() -> dict:
    """Parse Windows hosts file. Returns {hostname: ip} — last entry wins."""
    try:
        text = HOSTS_FILE.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return {"status": "not_found", "data": {}}
    except PermissionError:
        return {"status": "access_denied", "data": {}}
    except OSError as e:
        return {"status": "error", "data": {}, "error": str(e)}

    entries = {}
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            ip = parts[0]
            for hostname in parts[1:]:
                entries[hostname] = ip
    return {"status": "ok", "data": entries}


def collect_firewall_rules() -> dict:
    """Windows Firewall rules via Get-NetFirewallRule. Keyed by rule Name."""
    result = run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", _FW_PS],
        timeout=cfg.SUBPROCESS_TIMEOUT_SECONDS,
    )
    if result["status"] not in ("ok", "nonzero_exit"):
        return {"status": result["status"], "data": {}}
    raw = result["stdout"].strip()
    if not raw:
        return {"status": "ok", "data": {}}
    try:
        rules = json.loads(raw)
        if isinstance(rules, dict):
            rules = [rules]
        data = {
            r["DisplayName"]: {
                "name":      r.get("Name"),
                "direction": r.get("Direction"),
                "action":    r.get("Action"),
                "enabled":   r.get("Enabled"),
                "profile":   r.get("Profile"),
            }
            for r in rules
            if r.get("DisplayName")
        }
        return {"status": "ok", "data": data}
    except Exception as e:
        logger.error(f"firewall_rules: JSON parse failed: {e}")
        return {"status": "error", "data": {}, "error": str(e)}


def collect_listening_ports() -> dict:
    """TCP listening ports via Get-NetTCPConnection. All ports returned raw.

    TCP only — UDP endpoints are out of scope for this artefact. UDP does
    not have a Listen state in the Windows networking model; bound UDP
    sockets produce high OS churn (DNS client, SSDP, mDNS) and belong in
    a separate artefact if needed.

    ProcessName resolved via a single batched Get-Process call (PID→Name
    hashtable built once, joined inline) — no per-port PS invocations.

    The filter tag "ports_below_1024" in config.py is metadata for
    comparator.py — this collector does not pre-filter by port number.
    Keyed by "address:port" for comparator identity.
    """
    result = run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PORTS_PS],
        timeout=cfg.SUBPROCESS_TIMEOUT_SECONDS,
    )
    if result["status"] not in ("ok", "nonzero_exit"):
        return {"status": result["status"], "data": {}}
    raw = result["stdout"].strip()
    if not raw:
        return {"status": "ok", "data": {}}
    try:
        ports = json.loads(raw)
        if isinstance(ports, dict):
            ports = [ports]
        data = {}
        for p in ports:
            addr = p.get("LocalAddress", "")
            port = p.get("LocalPort", "")
            data[f"{addr}:{port}"] = {
                "local_address":  addr,
                "local_port":     port,
                "owning_process": p.get("OwningProcess"),
                "process_name":   p.get("ProcessName"),
            }
        return {"status": "ok", "data": data}
    except Exception as e:
        logger.error(f"listening_ports: JSON parse failed: {e}")
        return {"status": "error", "data": {}, "error": str(e)}
