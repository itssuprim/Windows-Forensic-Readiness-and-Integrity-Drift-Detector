# collectors/kernel.py
# Category G — Kernel/Boot (3 artefacts, MIXED)
#   lsa_protection    STATIC   (mode 1) — CRITICAL_ARTEFACT
#   secure_boot_state STATIC   (mode 1)
#   loaded_drivers    DYNAMIC  (mode 3, filter "unsigned_or_unknown_publisher"
#                               is metadata for comparator.py — collect all)

import csv
import io
import logging

import config as cfg
from collectors._shared import read_registry_value, run_command

logger = logging.getLogger(__name__)

_LSA_KEY    = r"SYSTEM\CurrentControlSet\Control\Lsa"
_SECBOOT_KEY = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"


def collect_lsa_protection() -> dict:
    """Read HKLM\\...\\Lsa\\RunAsPPL.

    RunAsPPL values: 0=unprotected, 1=PPL (Protected Process Light),
    2=PPLite (Windows 11 22H2+, PPL with UEFI lock — stronger than 1).
    Value absent (not_found) is equivalent to 0 — unprotected.
    not_found is itself a meaningful finding, not an error to suppress.
    """
    return read_registry_value("HKLM", _LSA_KEY, "RunAsPPL")


def collect_secure_boot_state() -> dict:
    """Read HKLM\\...\\SecureBoot\\State\\UEFISecureBootEnabled.

    1 = Secure Boot on, 0 = off, not_found = key absent (common on VMs
    and legacy BIOS systems where Secure Boot is not supported).
    """
    return read_registry_value("HKLM", _SECBOOT_KEY, "UEFISecureBootEnabled")


def collect_loaded_drivers() -> dict:
    """Loaded kernel drivers via driverquery /FO CSV /V.

    Returns all drivers — the filter tag "unsigned_or_unknown_publisher" in
    config.py is metadata for comparator.py to apply when checking new
    entries against known-good publishers. Path field included so the
    comparator can run Authenticode checks if needed.
    Keyed by Module Name for comparator identity.
    """
    result = run_command(
        ["driverquery", "/FO", "CSV", "/V"],
        timeout=cfg.SUBPROCESS_TIMEOUT_SECONDS,
    )
    if result["status"] not in ("ok", "nonzero_exit"):
        return {"status": result["status"], "data": {}}
    raw = result["stdout"].strip()
    if not raw:
        return {"status": "ok", "data": {}}
    try:
        reader = csv.DictReader(io.StringIO(raw))
        data = {}
        for row in reader:
            name = row.get("Module Name", "").strip()
            if not name:
                continue
            data[name] = {
                "display_name": row.get("Display Name", "").strip(),
                "driver_type":  row.get("Driver Type", "").strip(),
                "start_mode":   row.get("Start Mode", "").strip(),
                "state":        row.get("State", "").strip(),
                "path":         row.get("Path", "").strip(),
            }
        return {"status": "ok", "data": data}
    except Exception as e:
        logger.error(f"loaded_drivers: CSV parse failed: {e}")
        return {"status": "error", "data": {}, "error": str(e)}
