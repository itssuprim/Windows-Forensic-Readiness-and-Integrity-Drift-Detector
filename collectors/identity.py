# collectors/identity.py
# Category A — Identity (3 artefacts, all STATIC)
#   local_users, local_groups, password_policy

import logging
import re

from collectors._shared import run_command

logger = logging.getLogger(__name__)


def collect_local_users() -> dict:
    """Local users via PowerShell ADSI (WinNT provider).

    ADSI WinNT reads UserFlags bits directly — same source as WMI
    Win32_UserAccount, without the Python wmi library that triggers COM
    errors on this VM (DEVLOG Session 3). Returns the same field set so
    existing baselines stay comparable.

    UserFlags bitmask (ADS_USER_FLAG_ENUM):
      0x0002  ADS_UF_ACCOUNTDISABLE
      0x0010  ADS_UF_LOCKOUT
      0x0020  ADS_UF_PASSWD_NOTREQD  (inverted → password_required)
      0x0040  ADS_UF_PASSWD_CANT_CHANGE (inverted → password_changeable)
      0x10000 ADS_UF_DONT_EXPIRE_PASSWD (inverted → password_expires)
    """
    import json

    ps_script = (
        "$c = [ADSI]\"WinNT://$env:COMPUTERNAME\";"
        "$out = @{};"
        "$c.Children | Where-Object {$_.SchemaClassName -eq 'user'} | ForEach-Object {"
        # $_.Name is a plain string on WinNT DirectoryEntry — no .Value needed.
        # $_.UserFlags IS a COM property wrapper, so .Value extracts the int.
        "  $n = [string]$_.Name;"
        "  $f = [int]$_.UserFlags.Value;"
        "  try {"
        "    $sid = (New-Object System.Security.Principal.NTAccount($env:COMPUTERNAME,$n)).Translate([System.Security.Principal.SecurityIdentifier]).Value"
        "  } catch { $sid = $null };"
        "  $out[$n] = @{"
        "    sid=$sid;"
        "    disabled=[bool]($f -band 0x0002);"
        "    lockout=[bool]($f -band 0x0010);"
        "    password_required=-not [bool]($f -band 0x0020);"
        "    password_changeable=-not [bool]($f -band 0x0040);"
        "    password_expires=-not [bool]($f -band 0x10000);"
        "    account_type=512"
        "  }"
        "};"
        "$out | ConvertTo-Json -Compress -Depth 3"
    )

    result = run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script]
    )
    if result["status"] not in ("ok", "nonzero_exit"):
        return {"status": result["status"], "data": {}, "error": result.get("stderr", "")}
    raw = result["stdout"].strip()
    if not raw:
        return {"status": "ok", "data": {}}
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return {"status": "error", "data": {}, "error": "unexpected JSON structure"}
        return {"status": "ok", "data": data}
    except Exception as e:
        logger.error(f"local_users collection failed: {e}")
        return {"status": "error", "data": {}, "error": str(e)}


def collect_local_groups() -> dict:
    """Group names + SIDs via PowerShell Get-LocalGroup, members via net localgroup.

    Get-LocalGroup replaces WMI Win32_Group to avoid the Python wmi
    library (COM errors on this VM, DEVLOG Session 3). Members are still
    populated via net localgroup — faster than any WMI association traversal.
    """
    import json

    result = run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "Get-LocalGroup | Select-Object Name,"
         "@{N='SID';E={$_.SID.Value}} | ConvertTo-Json -Compress"],
    )
    if result["status"] not in ("ok", "nonzero_exit"):
        return {"status": result["status"], "data": {}, "error": result.get("stderr", "")}
    raw = result["stdout"].strip()
    if not raw:
        return {"status": "ok", "data": {}}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            parsed = [parsed]
        data = {g["Name"]: {"sid": g.get("SID"), "members": []} for g in parsed}
    except Exception as e:
        logger.error(f"local_groups collection failed: {e}")
        return {"status": "error", "data": {}, "error": str(e)}

    # Populate members via net localgroup — one call per group.
    # Output format is fixed: member names start after the dashed separator line.
    for group_name in data:
        result = run_command(["net", "localgroup", group_name])
        if result["status"] != "ok":
            continue
        members = []
        after_separator = False
        for line in result["stdout"].splitlines():
            line = line.strip()
            if line.startswith("---"):
                after_separator = True
                continue
            if after_separator and line and not line.startswith("The command"):
                members.append(line)
        data[group_name]["members"] = members

    return {"status": "ok", "data": data}


def collect_password_policy() -> dict:
    """`net accounts` — min password length, max age, lockout threshold.

    net accounts output is fixed-width English text tied to locale;
    this is a known fragility and is flagged as a Day-9 scenario-test
    item, not silently trusted.
    """
    result = run_command(["net", "accounts"])
    if result["status"] != "ok":
        return {"status": result["status"], "data": {}, "raw": result.get("stderr", "")}

    fields = {
        "min_password_length": r"Minimum password length\s*:\s*(\S+)",
        "max_password_age_days": r"Maximum password age.*?:\s*(\S+)",
        "min_password_age_days": r"Minimum password age.*?:\s*(\S+)",
        "lockout_threshold": r"Lockout threshold\s*:\s*(\S+)",
        "lockout_duration_min": r"Lockout duration.*?:\s*(\S+)",
        "password_history": r"Length of password history maintained\s*:\s*(\S+)",
    }

    data = {}
    for key, pattern in fields.items():
        m = re.search(pattern, result["stdout"], re.IGNORECASE)
        data[key] = m.group(1) if m else None

    return {"status": "ok", "data": data, "raw": result["stdout"]}