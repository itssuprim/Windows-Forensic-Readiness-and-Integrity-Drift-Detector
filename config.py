# config.py - Windows Forensic Readiness and Integrity Drift Detector
# Constants, paths, artefact registry.

import getpass
import socket
from pathlib import Path

# ── IDENTITY ──────────────────────────────────
try:
    AGENT_ID = f"{getpass.getuser()}@{socket.gethostname()}"
except Exception:
    AGENT_ID = f"{getpass.getuser()}@unknown-host"
AGENT_VERSION = "1.0.0"
TOOL_NAME = "WindowsForensicDriftDetector"

# ── PATHS ─────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent

DIRS = {
    "snapshots": PROJECT_ROOT / "snapshots",
    "backups":   PROJECT_ROOT / "backups",
    "reports":   PROJECT_ROOT / "reports",
    "coc_log":   PROJECT_ROOT / "coc_log",
    "logs":      PROJECT_ROOT / "logs",
    "rules":     PROJECT_ROOT / "rules",
}

def ensure_dirs() -> None:
    """Create all project directories and the collectors package stub.

    Called explicitly by collection_agent.py and run.py at startup rather
    than at import time — importing config in test scripts or the REPL should
    not write to the filesystem as a side effect.
    """
    for _d in DIRS.values():
        _d.mkdir(parents=True, exist_ok=True)
    _collectors_dir = PROJECT_ROOT / "collectors"
    _collectors_dir.mkdir(exist_ok=True)
    _collectors_init = _collectors_dir / "__init__.py"
    if not _collectors_init.exists():
        _collectors_init.touch()

APP_LOG   = DIRS["logs"] / "forensic_tool.log"
ALERT_LOG = DIRS["logs"] / "drift_alerts.log"
COC_LOG_FILE = DIRS["coc_log"] / "chain_of_custody.json"

# ── COLLECTION SETTINGS ───────────────────────
WMI_TIMEOUT_SECONDS        = 15
SUBPROCESS_TIMEOUT_SECONDS = 20

HASH_ALGORITHM   = "sha256"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# ── ARTEFACT REGISTRY ─────────────────────────
# type:            STATIC | SEMI-STATIC | DYNAMIC
# comparator_mode: 1 (static diff) | 2 (semi-static + suppression) | 3 (dynamic + pre-filter)
# module/func:     collection_agent.py imports these dynamically — adding an
#                  artefact means adding a row here only, never touching
#                  collection_agent.py.
#
# Collector files land per day:
#   collectors/identity.py    — DONE   (Day 1-2)
#   collectors/access.py      — DONE   (Day 1-2)
#   collectors/persistence.py — Day 3-4
#   collectors/software.py    — Day 5
#   collectors/network.py     — Day 5
#   collectors/filesystem.py  — Day 5
#   collectors/kernel.py      — Day 6
#   collectors/audit.py       — Day 6
#
# Artefacts pointing at not-yet-built modules will show collection_status:
# "collector_error" in the snapshot until that file lands — the crash
# isolation in collection_agent.run_collector() handles it gracefully.

ARTEFACTS = {

    # ── Category A — Identity (3) — ALL STATIC ───────────────────────
    "local_users": {
        "category": "A",
        "type": "STATIC",
        "comparator_mode": 1,
        "module": "collectors.identity",
        "func":   "collect_local_users",
    },
    "local_groups": {
        "category": "A",
        "type": "STATIC",
        "comparator_mode": 1,
        "module": "collectors.identity",
        "func":   "collect_local_groups",
    },
    "password_policy": {
        "category": "A",
        "type": "STATIC",
        "comparator_mode": 1,
        "module": "collectors.identity",
        "func":   "collect_password_policy",
    },

    # ── Category B — Access Control (2) — ALL STATIC ─────────────────
    "rdp_config": {
        "category": "B",
        "type": "STATIC",
        "comparator_mode": 1,
        "module": "collectors.access",
        "func":   "collect_rdp_config",
    },
    "uac_settings": {
        "category": "B",
        "type": "STATIC",
        "comparator_mode": 1,
        "module": "collectors.access",
        "func":   "collect_uac_settings",
    },

    # ── Category C — Persistence (7) — MIXED ─────────────────────────
    "run_keys_hklm": {
        "category": "C",
        "type": "STATIC",
        "comparator_mode": 1,
        "module": "collectors.persistence",
        "func":   "collect_run_keys_hklm",
    },
    "run_keys_hkcu": {
        "category": "C",
        "type": "STATIC",
        "comparator_mode": 1,
        "module": "collectors.persistence",
        "func":   "collect_run_keys_hkcu",
    },
    "scheduled_tasks": {
        "category": "C",
        "type": "DYNAMIC",
        "comparator_mode": 3,
        "filter": "exclude_microsoft_namespace",
        "module": "collectors.persistence",
        "func":   "collect_scheduled_tasks",
    },
    "services": {
        "category": "C",
        "type": "SEMI-STATIC",
        "comparator_mode": 2,
        "module": "collectors.persistence",
        "func":   "collect_services",
    },
    "wmi_subscriptions": {
        "category": "C",
        "type": "STATIC",
        "comparator_mode": 1,
        "module": "collectors.persistence",
        "func":   "collect_wmi_subscriptions",
    },
    "winlogon_keys": {
        "category": "C",
        "type": "STATIC",
        "comparator_mode": 1,
        "module": "collectors.persistence",
        "func":   "collect_winlogon_keys",
    },
    "startup_folder_system": {
        "category": "C",
        "type": "STATIC",
        "comparator_mode": 1,
        "module": "collectors.persistence",
        "func":   "collect_startup_folder_system",
    },

    # ── Category D — Software (1) — SEMI-STATIC ──────────────────────
    "installed_software_64": {
        "category": "D",
        "type": "SEMI-STATIC",
        "comparator_mode": 2,
        "module": "collectors.software",
        "func":   "collect_installed_software_64",
    },

    # ── Category E — Network (3) — MIXED ─────────────────────────────
    "hosts_file": {
        "category": "E",
        "type": "STATIC",
        "comparator_mode": 1,
        "module": "collectors.network",
        "func":   "collect_hosts_file",
    },
    "firewall_rules": {
        "category": "E",
        "type": "SEMI-STATIC",
        "comparator_mode": 2,
        "module": "collectors.network",
        "func":   "collect_firewall_rules",
    },
    "listening_ports": {
        "category": "E",
        "type": "DYNAMIC",
        "comparator_mode": 3,
        "filter": "ports_below_1024",
        "module": "collectors.network",
        "func":   "collect_listening_ports",
    },

    # ── Category F — Filesystem (3) — SEMI-STATIC ────────────────────
    "critical_binary_hashes": {
        "category": "F",
        "type": "SEMI-STATIC",
        "comparator_mode": 2,
        "module": "collectors.filesystem",
        "func":   "collect_critical_binary_hashes",
    },
    "alternate_data_streams": {
        "category": "F",
        "type": "STATIC",
        "comparator_mode": 1,
        "module": "collectors.filesystem",
        "func":   "collect_alternate_data_streams",
    },
    "dll_hijack_paths": {
        "category": "F",
        "type": "SEMI-STATIC",
        "comparator_mode": 2,
        "module": "collectors.filesystem",
        "func":   "collect_dll_hijack_paths",
    },

    # ── Category G — Kernel/Boot (3) — MIXED ─────────────────────────
    "lsa_protection": {
        "category": "G",
        "type": "STATIC",
        "comparator_mode": 1,
        "module": "collectors.kernel",
        "func":   "collect_lsa_protection",
    },
    "secure_boot_state": {
        "category": "G",
        "type": "STATIC",
        "comparator_mode": 1,
        "module": "collectors.kernel",
        "func":   "collect_secure_boot_state",
    },
    "loaded_drivers": {
        "category": "G",
        "type": "DYNAMIC",
        "comparator_mode": 3,
        "filter": "unsigned_or_unknown_publisher",
        "module": "collectors.kernel",
        "func":   "collect_loaded_drivers",
    },

    # ── Category H — Audit/Logging (3) — SEMI-STATIC ─────────────────
    "event_log_cleared": {
        "category": "H",
        "type": "STATIC",
        "comparator_mode": 1,
        "module": "collectors.audit",
        "func":   "collect_event_log_cleared",
    },
    "defender_status": {
        "category": "H",
        "type": "SEMI-STATIC",
        "comparator_mode": 2,
        "module": "collectors.audit",
        "func":   "collect_defender_status",
    },
    "defender_exclusions": {
        "category": "H",
        "type": "SEMI-STATIC",
        "comparator_mode": 2,
        "module": "collectors.audit",
        "func":   "collect_defender_exclusions",
    },
}

# ── UNIVERSAL GATE — artefacts that bypass suppression always ─────
CRITICAL_ARTEFACTS = [
    "wmi_subscriptions",
    "run_keys_hklm",
    "run_keys_hkcu",
    "lsa_protection",
    "winlogon_keys",
    "event_log_cleared",
]

# ── CRITICAL BINARIES — hashed by filesystem.py ──────────────────
CRITICAL_BINARIES = [
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\lsass.exe",
    r"C:\Windows\explorer.exe",
]

# ── GOLDEN BASELINE ────────────────────────────────────────────────
GOLDEN_BASELINE_DIR = PROJECT_ROOT / "golden_baseline"
GOLDEN_BASELINE_DIR.mkdir(exist_ok=True)
DEEP_AUDIT_INTERVAL_DAYS = 30