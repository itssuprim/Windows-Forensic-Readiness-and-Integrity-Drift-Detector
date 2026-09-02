# collectors/access.py
# Category B — Access Control (2 artefacts, all STATIC)
#   rdp_config, uac_settings

import logging

from collectors._shared import read_registry_value

logger = logging.getLogger(__name__)

RDP_KEY = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
RDP_TCP_KEY = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
UAC_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"


def collect_rdp_config() -> dict:
    """RDP enabled/disabled + listening port.

    fDenyTSConnections: 0 = RDP enabled, 1 = disabled.
    PortNumber lives under the RDP-Tcp WinStations subkey, not the
    parent Terminal Server key — two reads, reported together as one
    artefact since they are only meaningful read as a pair.
    """
    enabled_result = read_registry_value("HKLM", RDP_KEY, "fDenyTSConnections")
    port_result = read_registry_value("HKLM", RDP_TCP_KEY, "PortNumber")

    if enabled_result["status"] != "ok":
        return {"status": enabled_result["status"], "data": {}}

    deny_flag = enabled_result["data"].get("fDenyTSConnections")
    data = {
        "rdp_enabled": (deny_flag == 0),
        "port": port_result["data"].get("PortNumber") if port_result["status"] == "ok" else None,
    }
    return {"status": "ok", "data": data}


def collect_uac_settings() -> dict:
    """UAC level + ConsentPromptBehaviorAdmin from Policies\\System.

    EnableLUA: 0 = UAC fully disabled — this alone is CRITICAL-worthy
    on its own regardless of the prompt behaviour value, so it is kept
    as its own field rather than collapsed into one derived "level".
    """
    result = read_registry_value("HKLM", UAC_KEY)
    if result["status"] != "ok":
        return {"status": result["status"], "data": {}}

    raw = result["data"]
    data = {
        "enable_lua": raw.get("EnableLUA"),
        "consent_prompt_behavior_admin": raw.get("ConsentPromptBehaviorAdmin"),
        "prompt_on_secure_desktop": raw.get("PromptOnSecureDesktop"),
    }
    return {"status": "ok", "data": data}
