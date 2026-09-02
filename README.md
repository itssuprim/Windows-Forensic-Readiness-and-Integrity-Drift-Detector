# WFRIDD — Windows Forensic Readiness and Integrity Drift Detector

A forensic readiness and integrity drift detection framework for Windows 11
endpoints. Collects 25 system artefacts across 8 categories, detects
configuration drift between collection cycles, scores findings against MITRE
ATT&CK, suppresses known-benign churn, and produces signed, ACL-locked
evidence-grade snapshots with a full Chain of Custody log.

---

## Requirements

| Requirement | Notes |
|---|---|
| **Windows 11** (build 22000+) | Required — uses WMI, winreg, Windows ACL APIs |
| **Python 3.11+** | Tested on Anaconda Python 3.12 and 3.14 |
| **Elevated PowerShell** | All collection and signing operations require admin rights |
| **MongoDB 6.0+** | Local or remote; default URI `mongodb://localhost:27017/` |
| **pywin32** | Required for ACL/CoC operations; installed by `setup_env.py` |

---

## Installation

### 1. Clone the repository

```powershell
git clone https://github.com/<your-username>/WFRIDD.git
cd WFRIDD
```

### 2. Run the environment setup script (elevated PowerShell)

```powershell
python setup_env.py
```

This will:
- Verify platform (Windows) and Python version
- Install all Python dependencies from `requirements.txt`
- Run the pywin32 post-install step (required separately from pip)
- Verify every required import individually

### 3. Install via PowerShell script (optional — sets up Scheduled Task)

```powershell
.\install.ps1
```

This will additionally:
- Create required output directories
- Register a Windows Scheduled Task to run collection on a schedule
- Install MongoDB if not already present (via `winget`)

---

## Usage

### Single collection cycle (collect, compare, report, store)

```powershell
python run.py --now
```

On first run, establishes a baseline snapshot. On subsequent runs, compares
against the most recent baseline and generates a PDF + JSON drift report.

### Daemon mode (repeating on a schedule)

```powershell
python run.py --interval 60
```

Runs a full collection + comparison cycle every 60 minutes (default). Press
`Ctrl+C` to stop.

### Launch the monitoring dashboard

```powershell
python dashboard.py
```

Opens at `http://127.0.0.1:5001`. Provides:
- **Overview** — latest scan status, severity counts, artefact coverage grid
- **Alerts** — recent findings with MITRE ATT&CK attribution
- **Reports** — scan history with per-cycle severity summary
- **Suppression** — suppression audit per cycle (which SR rules fired)
- **Rules** — full severity rule browser (windows_rules.yaml)
- **Downloads** — PDF and JSON report download

---

## What gets collected

| Category | Artefacts | Type |
|---|---|---|
| A — Identity | local_users, local_groups, password_policy | STATIC |
| B — Access | rdp_config, uac_settings | STATIC |
| C — Persistence | run_keys_hklm, run_keys_hkcu, winlogon_keys, startup_folder_system, wmi_subscriptions, services, scheduled_tasks | STATIC / SEMI-STATIC / DYNAMIC |
| D — Software | installed_software_64 | SEMI-STATIC |
| E — Network | hosts_file, firewall_rules, listening_ports | STATIC / SEMI-STATIC / DYNAMIC |
| F — Filesystem | critical_binary_hashes, alternate_data_streams, dll_hijack_paths | SEMI-STATIC / STATIC |
| G — Kernel/Boot | lsa_protection, secure_boot_state, loaded_drivers | STATIC / DYNAMIC |
| H — Audit | event_log_cleared, defender_status, defender_exclusions | STATIC / SEMI-STATIC |

---

## Output files

All output is written to subdirectories of the project root:

| Directory | Contents |
|---|---|
| `snapshots/` | Signed, ACL-locked JSON snapshots (`snapshot_YYYYMMDDTHHMMSSZ.json`) |
| `reports/` | Signed, ACL-locked PDF and JSON drift reports |
| `coc_log/` | `chain_of_custody.json` — append-only ledger of all signed files and suppression events |
| `logs/` | Application log (`forensic_tool.log`) and per-run logs |

---

## Suppression rules

Nine suppression rules (SR-001 through SR-009) handle known-benign churn so
that routine OS activity does not flood alerts:

| Rule | Covers |
|---|---|
| SR-001 | Service state churn (Windows Update, per-user session instances, known high-churn services) |
| SR-002 | Critical binary hash changes when Windows Update is confirmed (Event ID 19) |
| SR-003 | Installed software minor version increments (same publisher, no downgrade) |
| SR-004 | Firewall Allow rule re-enabled (Enabled: False → True, same Action) |
| SR-005 | Defender signature version and timestamp updates |
| SR-006 | Defender exclusion list reductions (fewer exclusions = wider scan coverage) |
| SR-007 | Machine PATH directory additions where writable_by_users=False |
| SR-008 | SoftLanding scheduled task GUID rotation |
| SR-009 | Port 135 (RPC Endpoint Mapper) svchost PID rotation between boots |

Every suppression is logged to `chain_of_custody.json` as a `change_suppressed`
event and rendered in the PDF report's Suppression Audit section.

---

## Severity scoring

Findings are scored against `rules/windows_rules.yaml` (54 rules) using MITRE
ATT&CK technique attribution. Severity levels: **CRITICAL**, **HIGH**,
**MEDIUM**, **LOW**. Unmatched findings appear separately for analyst review.

---

## Chain of Custody

Every snapshot and report is:
1. SHA-256 hashed
2. ACL-locked (Deny write/delete to Everyone including Administrators)
3. Recorded in `coc_log/chain_of_custody.json` with timestamp, agent ID, and hash

The CoC log itself is re-locked after every append. Any modification attempt
fires Security Event IDs 4670 and 4663 via an audit SACL.

To verify a file manually:

```powershell
python -c "from coc_manager import hash_file; print(hash_file(r'snapshots\snapshot_YYYYMMDDTHHMMSSZ.json'))"
```

---

## Environment variable

| Variable | Default | Purpose |
|---|---|---|
| `WFRIDD_MONGO_URI` | `mongodb://localhost:27017/` | MongoDB connection URI |

---

## Uninstall

```powershell
.\uninstall.ps1          # Remove Scheduled Task and stop services; keep evidence
.\uninstall.ps1 -Purge   # Also delete snapshots, reports, CoC log
```
