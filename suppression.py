# suppression.py
# Per-artefact suppression functions for Mode 2 (semi-static) artefacts.
#
# Each suppressor is a callable class instance exposing:
#   __call__(change, windows_update_confirmed=False) -> bool
#       True  = suppress (log to CoC, exclude from alerts)
#       False = do not suppress (becomes a Finding/alert)
#   .rule_id  : str — SR-XXX identifier written to the CoC suppression log
#   .reason(change) : str — human-readable reason for the CoC entry
#
# The universal gate in comparator.py is checked BEFORE calling the suppressor.
# For CRITICAL_ARTEFACTS (wmi_subscriptions, run_keys_hklm, etc.), the gate
# fires and these functions are never called — they only handle mode-2 artefacts.
#
# SUPPRESS_FNS at the bottom of this file is the dict passed to
# comparator.run_comparison(suppress_fns=...) by run.py.

import logging
import re

logger = logging.getLogger(__name__)


# ── HELPERS ───────────────────────────────────────────────────────────────────

def _changed_fields(baseline_val: dict, current_val: dict) -> set:
    """Return the set of keys that differ between two dicts."""
    bv = baseline_val or {}
    cv = current_val or {}
    all_keys = set(bv) | set(cv)
    return {k for k in all_keys if bv.get(k) != cv.get(k)}


def _parse_version(version_str: str):
    """Parse a dotted-decimal version string into a comparable tuple.

    Returns a tuple of ints, or None if the string cannot be parsed.
    Handles "1.2.3", "1.2.3.4", "1.2.3.456 (build)" etc.
    """
    if not version_str:
        return None
    m = re.match(r"(\d+(?:\.\d+)+)", str(version_str).strip())
    if not m:
        return None
    try:
        return tuple(int(x) for x in m.group(1).split("."))
    except ValueError:
        return None


def _is_downgrade(baseline_version: str, current_version: str) -> bool:
    """Return True if current_version is strictly less than baseline_version."""
    b = _parse_version(baseline_version)
    c = _parse_version(current_version)
    if b is None or c is None:
        return False  # Cannot parse → assume no downgrade (conservative for suppression)
    # Pad shorter tuple with zeros for comparison
    length = max(len(b), len(c))
    b = b + (0,) * (length - len(b))
    c = c + (0,) * (length - len(c))
    return c < b


def _is_major_version_change(baseline_version: str, current_version: str) -> bool:
    """Return True if the major version component (first) changed."""
    b = _parse_version(baseline_version)
    c = _parse_version(current_version)
    if b is None or c is None:
        return False
    return b[0] != c[0]


# ── SR-001 — Services ─────────────────────────────────────────────────────────

class _SuppressServices:
    """Suppress three categories of expected service churn:

    1. Modified Microsoft-signed services during Windows Update (original SR-001):
       - change_type "modified" only
       - signing_status Valid in current snapshot
       - run_as, binary_path, display_name all unchanged
       - only state or start_type fields changed
       - windows_update_confirmed (Event ID 19 between snapshots)

    2. Known high-churn Microsoft services (whitelist, no WU required):
       Services in _STATE_CHURN_SERVICES rotate state independently of Windows
       Update. Suppressed on "modified" when signing_status Valid and only
       state/start_type changed. Windows Update path takes priority; this is
       the fallback for noisy services between update cycles.

    3. Per-user service instance churn (added / removed):
       Windows creates short-lived per-session service instances named
       BaseName_XXXXXXXX (underscore + 6-8 hex chars), e.g. OneSyncSvc_40be3.
       These are OS-managed; the suffix changes each session. Suppress when:
       - change_type is "added" or "removed"
       - key matches ^.+_[0-9a-fA-F]{6,8}$
       - the base name (suffix stripped) is in _PER_USER_SERVICE_BASES
       - signing_status is "Valid" in the current snapshot entry (added only)
       An unknown base name or unsigned binary is never suppressed.
    """
    rule_id = "SR-001"

    _CRITICAL_FIELDS = {"run_as", "binary_path", "display_name"}
    _ALLOWED_CHANGED = {"state", "start_type"}
    _INSTANCE_RE = re.compile(r'^(.+)_[0-9a-fA-F]{6,8}$')
    _STATE_CHURN_SERVICES = {
        'WaaSMedicSvc',    # Windows Update Medic Service
        'gpsvc',           # Group Policy Client
        'NetSetupSvc',     # Network Setup Service
        'TrustedInstaller', # Windows Modules Installer
        'wuauserv',        # Windows Update
        'wlidsvc',         # Microsoft Account Sign-in Assistant
        'BITS',            # Background Intelligent Transfer
        'CryptSvc',        # Cryptographic Services
        'msiserver',       # Windows Installer
        'CoworkVMService', # Claude desktop app — expected baseline on this VM (DEVLOG Session 3)
        # Reboot-churn services — state/start_type rotates on every boot cycle
        'InventorySvc',                    # Compatibility Telemetry / inventory
        'UsoSvc',                          # Update Session Orchestrator
        'DoSvc',                           # Delivery Optimization
        'wmiApSrv',                        # WMI Performance Adapter
        'StorSvc',                         # Storage Service
        'sppsvc',                          # Software Protection (license activation)
        'PcaSvc',                          # Program Compatibility Assistant
        'wuqlsvc',                         # Windows Update Quality Layer
        'WdiSystemHost',                   # Diagnostic Service Host
        'whesvc',                          # Windows Hardware Error Architecture
        'WPDBusEnum',                      # Portable Device Enumerator
        'WerSvc',                          # Windows Error Reporting
        'RasMan',                          # Remote Access Connection Manager
        'InstallService',                  # Microsoft Store Install Service
        'PrintDeviceConfigurationService', # Printer driver configuration
        'VaultSvc',                        # Credential Manager
        'WSearch',                         # Windows Search indexer
        'tzautoupdate',                    # Time Zone Auto Update
        'MicrosoftEdgeElevationService',   # Edge auto-updater
        'VSS',                             # Volume Shadow Copy
        'wscsvc',                          # Security Center
        'SecurityHealthService',           # Windows Defender Health
        'vmvss',                           # Hyper-V Volume Shadow Copy
        'FrameServerMonitor',              # Windows Camera Frame Server Monitor
        'SstpSvc',                         # Secure Socket Tunneling Protocol (VPN)
    }
    _PER_USER_SERVICE_BASES = {
        'OneSyncSvc', 'WpnUserService', 'CDPUserSvc', 'MessagingService',
        'PimIndexMaintenanceSvc', 'UserDataSvc', 'UnistoreSvc', 'AarSvc',
        'cbdhsvc', 'BcastDVRUserService', 'CaptureService', 'DevicePickerUserSvc',
        'DeviceAssociationBrokerSvc', 'DevicesFlowUserSvc', 'BluetoothUserService',
        'PrintWorkflowUserSvc', 'ConsentUxUserSvc', 'UdkUserSvc', 'PenService',
        'NPSMSvc', 'P9RdrService', 'CloudBackupRestoreSvc', 'webthreatdefusersvc',
        'CredentialEnrollmentManagerUserSvc',
    }

    def __call__(self, change, windows_update_confirmed=False, baseline_data=None):
        # ── Category 3: per-user instance churn (added / removed) ────────────
        if change.change_type in ("added", "removed"):
            m = self._INSTANCE_RE.match(change.key)
            if not m:
                return False  # Name does not match the instance pattern
            base_name = m.group(1)
            if base_name not in self._PER_USER_SERVICE_BASES:
                return False  # Unknown base — novel service, always alert
            if change.change_type == "added":
                cv = change.current_value or {}
                if cv.get("signing_status") != "Valid":
                    return False  # Unsigned binary mimicking this pattern — alert
            return True

        # ── Categories 1 & 2: modified Microsoft-signed services ──────────────
        if change.change_type != "modified":
            return False
        cv = change.current_value or {}
        if cv.get("signing_status") != "Valid":
            return False  # Unsigned or unknown — alert
        changed = _changed_fields(change.baseline_value, change.current_value)
        if changed & self._CRITICAL_FIELDS:
            return False  # Critical field changed — alert
        if not changed.issubset(self._ALLOWED_CHANGED | {"signing_status"}):
            return False  # Unexpected field changed — alert
        # Primary path: Windows Update confirmed
        if windows_update_confirmed:
            return True
        # Fallback path: known high-churn service whose state rotates independently
        if change.key in self._STATE_CHURN_SERVICES:
            return True
        return False

    def reason(self, change):
        if change.change_type in ("added", "removed"):
            m = self._INSTANCE_RE.match(change.key)
            base = m.group(1) if m else change.key
            signing = ""
            if change.change_type == "added":
                cv = change.current_value or {}
                signing = f", signing_status {cv.get('signing_status', 'unknown')}"
            return (
                f"Per-user service instance '{change.key}' {change.change_type}: "
                f"base name '{base}' is a known Windows per-user service template"
                f"{signing}"
            )
        changed = _changed_fields(change.baseline_value, change.current_value)
        if change.key in self._STATE_CHURN_SERVICES:
            return (
                f"Known high-churn Microsoft service: state/start_type change on "
                f"'{change.key}', signing_status Valid"
            )
        return (
            f"Microsoft-signed service '{change.key}': "
            f"field(s) {changed & self._ALLOWED_CHANGED} changed, "
            f"Windows Update confirmed (Event ID 19)"
        )


suppress_services = _SuppressServices()


# ── SR-002 — Critical Binary Hashes ──────────────────────────────────────────

class _SuppressCriticalBinaryHashes:
    """Suppress binary hash changes only when Windows Update is confirmed.

    Hash changes on critical system binaries (cmd.exe, powershell.exe,
    svchost.exe, lsass.exe, explorer.exe) are a primary tamper signal.
    The ONLY safe basis for suppression is Windows Update (Event ID 19),
    which explains why a Microsoft-maintained binary changed on disk.

    If Windows Update is NOT confirmed, every hash change is an alert —
    even if the binary is still Microsoft-signed. An attacker who replaces
    a signed binary with a different signed binary (e.g. an older version
    with a known vulnerability) would pass a signing check but not a WU check.
    """
    rule_id = "SR-002"

    def __call__(self, change, windows_update_confirmed=False):
        if not windows_update_confirmed:
            return False
        # Only suppress hash changes, not status changes (not_found, access_denied)
        cv = change.current_value or {}
        bv = change.baseline_value or {}
        if cv.get("status") != "ok" or bv.get("status") != "ok":
            return False  # Binary disappeared or became inaccessible — alert
        return True

    def reason(self, change):
        cv = change.current_value or {}
        new_hash = cv.get("sha256", "unknown")[:16]
        return (
            f"Binary hash changed on '{change.key}': "
            f"new SHA-256 prefix {new_hash}..., "
            f"Windows Update confirmed (Event ID 19)"
        )


suppress_critical_binary_hashes = _SuppressCriticalBinaryHashes()


# ── SR-003 — Installed Software ───────────────────────────────────────────────

class _SuppressInstalledSoftware:
    """Suppress known-publisher minor version increments (patch updates).

    Suppress ONLY when ALL of:
      - change_type is "modified" (removals are always alerts — T1562)
      - publisher is unchanged and non-empty
      - version increment, not a downgrade
      - major version component unchanged (major bump = treat as alert)

    A removal of installed software (change_type="removed") is always an
    alert — it is a potential T1562 defensive-tool removal indicator.
    A new GUID (change_type="added") is always an alert — new software
    installed without a baseline entry is suspicious.
    """
    rule_id = "SR-003"

    def __call__(self, change, windows_update_confirmed=False):
        if change.change_type != "modified":
            return False
        bv = change.baseline_value or {}
        cv = change.current_value or {}
        b_pub = (bv.get("publisher") or "").strip()
        c_pub = (cv.get("publisher") or "").strip()
        if not b_pub or b_pub != c_pub:
            return False  # Publisher changed or unknown — alert
        b_ver = bv.get("version", "")
        c_ver = cv.get("version", "")
        if _is_downgrade(b_ver, c_ver):
            return False  # Version downgrade — alert
        if _is_major_version_change(b_ver, c_ver):
            return False  # Major version bump — alert (larger change than a patch)
        return True

    def reason(self, change):
        bv = change.baseline_value or {}
        cv = change.current_value or {}
        return (
            f"Software '{change.key}' ({cv.get('display_name', 'unknown')}): "
            f"version {bv.get('version')} → {cv.get('version')}, "
            f"publisher '{cv.get('publisher')}' unchanged"
        )


suppress_installed_software = _SuppressInstalledSoftware()


# ── SR-004 — Firewall Rules ───────────────────────────────────────────────────

class _SuppressFirewallRules:
    """Firewall rule suppression — two distinct cases (conservative on both).

    Case A — Enabled-toggle on existing rule:
      Suppress only when Enabled toggled False→True on an existing Allow rule
      (re-enabling a known-good Allow rule after a state flip).

    Case B — GUID-named rule added/removed by a known Microsoft app (SR-010):
      Windows apps register firewall rules at runtime via the Firewall API.
      Rules registered this way are named with raw GUIDs; the display_name
      carries the human-readable label. Microsoft Teams is the primary example:
      it rotates inbound/outbound Allow rules each time it launches or updates,
      producing symmetric added/removed churn across cycles.

      Suppress only when ALL of:
        - Name matches bare-GUID pattern {XXXXXXXX-…-XXXXXXXXXXXX}
        - display_name is in _KNOWN_DISPLAYS (tight whitelist)
        - Action is "Allow" — Block rule additions/removals are always notable

    NEVER suppress:
      - Rule removals or additions with unknown display_name (case B only)
      - Rules where Action changes (Block → Allow is critical)
      - Block rule additions/removals (both cases)

    NOTE: display_name is not authenticated — any process with sufficient
    privilege can register a rule with any name. _KNOWN_DISPLAYS must stay
    tight. Expand it only after confirming a display_name comes from a
    Microsoft app that rotates GUID rules on this VM.
    """
    rule_id = "SR-004"

    _GUID_RE = re.compile(
        r'^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}'
        r'-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'
    )
    _KNOWN_DISPLAYS = {
        "Microsoft Teams",
        "Microsoft Teams (work or school)",
        "Microsoft Teams (personal)",
    }

    def __call__(self, change, windows_update_confirmed=False, baseline_data=None):
        # ── Case B: GUID-named rule churn from known Microsoft apps ──────────
        if change.change_type in ("added", "removed"):
            if not self._GUID_RE.match(change.key):
                return False  # Non-GUID additions/removals are always alerts
            val = change.current_value if change.change_type == "added" else change.baseline_value
            val = val or {}
            if (val.get("display_name") or "").strip() not in self._KNOWN_DISPLAYS:
                return False  # Unknown display name — alert
            if (val.get("action") or "").strip() != "Allow":
                return False  # Non-Allow rule churn — alert
            return True

        # ── Case A: Enabled-toggle on existing rule ──────────────────────────
        if change.change_type != "modified":
            return False
        bv = change.baseline_value or {}
        cv = change.current_value or {}
        if bv.get("action") != cv.get("action"):
            return False
        if bv.get("direction") != cv.get("direction"):
            return False
        if bv.get("enabled") == "False" and cv.get("enabled") == "True":
            if cv.get("action") == "Allow":
                return True
        return False

    def reason(self, change):
        if change.change_type in ("added", "removed"):
            val = change.current_value if change.change_type == "added" else change.baseline_value
            val = val or {}
            dn   = val.get("display_name", "unknown")
            act  = val.get("action", "unknown")
            dir_ = val.get("direction", "unknown")
            return (
                f"GUID-named firewall rule '{change.key}' ({change.change_type}) "
                f"— DisplayName='{dn}', Action={act}, Direction={dir_} "
                f"— Microsoft app dynamically registering/deregistering rules (SR-010)"
            )
        return (
            f"Firewall rule '{change.key}' re-enabled (Enabled: False → True), "
            f"Action and Direction unchanged"
        )


suppress_firewall_rules = _SuppressFirewallRules()


# ── SR-005 — Defender Status ──────────────────────────────────────────────────

class _SuppressDefenderStatus:
    """Suppress Defender definition update (signature version/timestamp only).

    defender_status is a flat dict keyed by field name. The comparator
    produces one Change per field that differs. This suppressor is called
    once per changed field.

    Suppress ONLY when change.key is signature_version or
    signature_last_updated — these change on every definition update
    and are expected high-frequency benign churn.

    NEVER suppress changes to any protection-state boolean:
      antivirus_enabled, real_time_protection_enabled, am_service_enabled,
      nis_enabled. A False value in any of these is a CRITICAL finding.
    """
    rule_id = "SR-005"

    _SUPPRESSIBLE_FIELDS = {"signature_version", "signature_last_updated"}
    _PROTECTION_FIELDS = {
        "antivirus_enabled",
        "real_time_protection_enabled",
        "am_service_enabled",
        "nis_enabled",
    }

    def __call__(self, change, windows_update_confirmed=False):
        if change.key in self._PROTECTION_FIELDS:
            return False  # Never suppress protection-state changes
        return change.key in self._SUPPRESSIBLE_FIELDS

    def reason(self, change):
        return (
            f"Defender definition update: {change.key} changed "
            f"from '{change.baseline_value}' to '{change.current_value}' — "
            f"expected benign churn from signature update cycle"
        )


suppress_defender_status = _SuppressDefenderStatus()


# ── SR-006 — Defender Exclusions ─────────────────────────────────────────────

class _SuppressDefenderExclusions:
    """Suppress exclusion removals; never suppress additions.

    defender_exclusions data has keys paths/processes/extensions, each a
    sorted list. The comparator produces one Change per key when the list
    content changes (change_type is always "modified" since the keys are fixed).

    Suppress ONLY when the new list is a subset of the old list (removal
    of exclusions is safe — it increases the scan surface). A mixed change
    (some removed, some added) is treated as an addition and not suppressed.

    NEVER suppress additions — adding a Defender exclusion is a common
    attacker move to allow malware to run without triggering scans (T1562.001).
    Temp-directory paths in additions are CRITICAL severity (handled by
    severity_engine, not this suppressor).
    """
    rule_id = "SR-006"

    def __call__(self, change, windows_update_confirmed=False):
        bv = change.baseline_value
        cv = change.current_value
        b_set = set(bv) if isinstance(bv, list) else set()
        c_set = set(cv) if isinstance(cv, list) else set()
        if c_set == b_set:
            return False  # No real change — comparator should not have fired, but guard it
        # Any additions → never suppress
        if c_set - b_set:
            return False
        # Only removals → suppress (fewer exclusions = wider scan surface = safe)
        return True

    def reason(self, change):
        bv = change.baseline_value or []
        cv = change.current_value or []
        b_set = set(bv) if isinstance(bv, list) else set()
        c_set = set(cv) if isinstance(cv, list) else set()
        removed = b_set - c_set
        return (
            f"Defender exclusion '{change.key}' list reduced — "
            f"removed: {sorted(removed)} — "
            f"fewer exclusions increases scan coverage (safe)"
        )


suppress_defender_exclusions = _SuppressDefenderExclusions()


# ── SR-007 — DLL Hijack Paths ─────────────────────────────────────────────────

class _SuppressDllHijackPaths:
    """Suppress PATH directory changes where writability remains safe.

    dll_hijack_paths is keyed by directory path; each entry has exists and
    writable_by_users fields. The forensic risk is a directory that becomes
    writable by non-privileged identities (Everyone/Users/Authenticated Users),
    enabling DLL planting.

    Suppress ONLY when:
      - change_type is "added" and the new directory has writable_by_users=False
        (a new PATH entry that is not user-writable is not a hijack surface)
      - change_type is "modified" and writable_by_users is still False in
        the current snapshot (the directory changed in some way but is still
        locked down)

    NEVER suppress:
      - change_type is "removed" (PATH manipulation is suspicious)
      - Any change where writable_by_users becomes True (primary alert condition)
      - Any change where exists becomes False (missing PATH directory is a
        hijack surface — attacker can create the directory and control it)
    """
    rule_id = "SR-007"

    def __call__(self, change, windows_update_confirmed=False):
        if change.change_type == "removed":
            return False  # PATH directory removed — suspicious
        cv = change.current_value or {}
        if cv.get("writable_by_users"):
            return False  # Currently writable by non-privileged users — alert
        if not cv.get("exists", True):
            return False  # Directory does not exist — alert (future hijack surface)
        return True  # Change is benign — directory still exists and locked down

    def reason(self, change):
        cv = change.current_value or {}
        return (
            f"PATH directory '{change.key}' changed "
            f"(change_type={change.change_type}) — "
            f"writable_by_users={cv.get('writable_by_users')}, "
            f"exists={cv.get('exists')} — not a hijack surface"
        )


suppress_dll_hijack_paths = _SuppressDllHijackPaths()


# ── SR-008 — Scheduled Tasks (SoftLanding churn) ──────────────────────────────

class _SuppressScheduledTasks:
    """Suppress GUID-rotating SoftLanding scheduled task churn.

    SoftLanding tasks appear under \\SoftLanding\\ in the Tasks namespace
    and rotate GUIDs between cycles — produces added/removed noise that is
    not meaningful drift on this VM.

    Suppress ONLY:
      - change_type "added" or "removed" where key starts with \\SoftLanding\\

    NEVER suppress:
      - change_type "modified" (a modified SoftLanding task is unexpected — alert)
      - Any task outside the \\SoftLanding\\ path
    """
    rule_id = "SR-008"

    def __call__(self, change, windows_update_confirmed=False):
        if change.change_type == "modified":
            return False
        # Collector stores keys with forward-slash separators after the leading
        # backslash (e.g. \SoftLanding/SID/TaskName), so check both forms.
        key = change.key.replace("\\", "/")
        return key.startswith("/SoftLanding/")

    def reason(self, change):
        return (
            f"SoftLanding task '{change.key}' {change.change_type} — "
            f"GUID-rotating Windows feature task, not meaningful drift"
        )


suppress_scheduled_tasks = _SuppressScheduledTasks()


# ── SR-009 — Listening Ports (RPC Endpoint Mapper svchost rotation) ───────────

class _SuppressListeningPorts:
    """Suppress port 135 owning-process churn between boot cycles.

    Port 135 (RPC Endpoint Mapper) is always present on Windows but the
    svchost instance hosting it gets a new PID on every boot. The collector
    stores owning_process (PID) and process_name, so a PID rotation produces
    a "modified" finding even though nothing meaningful changed.

    Suppress ONLY:
      - change_type "modified" where the port number extracted from the key is 135
        (keys are "address:port", e.g. "0.0.0.0:135" or ":::135")
      - process_name is "svchost" in the current snapshot (confirms it is still
        the OS RPC host — an unknown process taking port 135 is never suppressed)

    NEVER suppress:
      - "added" or "removed" on port 135 (port appearing/disappearing is notable)
      - Any other port number
      - Any port whose current process_name is not svchost
    """
    rule_id = "SR-009"

    def __call__(self, change, windows_update_confirmed=False):
        if change.change_type != "modified":
            return False
        # Key format: "address:port"
        parts = change.key.rsplit(":", 1)
        if len(parts) != 2 or parts[1] != "135":
            return False
        cv = change.current_value or {}
        return (cv.get("process_name") or "").lower() == "svchost"

    def reason(self, change):
        cv = change.current_value or {}
        return (
            f"Port 135 (RPC Endpoint Mapper) owning_process rotated on "
            f"'{change.key}' — svchost PID changes each boot, "
            f"current process_name='{cv.get('process_name')}'"
        )


suppress_listening_ports = _SuppressListeningPorts()


# ── SUPPRESS_FNS — passed to comparator.run_comparison() ─────────────────────
# Maps each artefact name to its suppressor instance.
# Artefacts not in this dict get no suppressor in run_comparison()
# (all changes become findings).

SUPPRESS_FNS = {
    "services":               suppress_services,
    "installed_software_64":  suppress_installed_software,
    "firewall_rules":         suppress_firewall_rules,
    "critical_binary_hashes": suppress_critical_binary_hashes,
    "dll_hijack_paths":       suppress_dll_hijack_paths,
    "defender_status":        suppress_defender_status,
    "defender_exclusions":    suppress_defender_exclusions,
    "scheduled_tasks":        suppress_scheduled_tasks,
    "listening_ports":        suppress_listening_ports,
}
