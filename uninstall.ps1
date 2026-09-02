# =============================================================================
# uninstall.ps1 - Clean Removal
# Windows Forensic Readiness and Integrity Drift Detector
#
#     .\uninstall.ps1            # removes scheduled tasks + clears MongoDB
#     .\uninstall.ps1 -Purge     # also wipes local snapshots, reports, coc_log
#
# MongoDB is always cleared on uninstall so a fresh reinstall starts clean.
# Local evidence directories are left in place unless -Purge is passed.
# =============================================================================

#Requires -RunAsAdministrator

param(
    [switch]$Purge
)

function Write-Pass    ($msg) { Write-Host "[PASS] $msg" -ForegroundColor Green  }
function Write-Info    ($msg) { Write-Host "[INFO] $msg" -ForegroundColor Cyan   }
function Write-WarnMsg ($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }

$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectDir

Write-Host ""
Write-Host "Uninstalling Windows Forensic Readiness and Integrity Drift Detector..." -ForegroundColor White
Write-Host ""

# -- Remove Scheduled Tasks ---------------------------------------------------
$tasks = @("ForensicDriftDetector", "ForensicDriftDetectorDashboard")
foreach ($taskName in $tasks) {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Pass "Scheduled task removed: $taskName"
    } else {
        Write-Info "No scheduled task found: $taskName - skipping"
    }
}

# -- MongoDB reset (always) ---------------------------------------------------
Write-Host ""
Write-Host "-- Clearing MongoDB --" -ForegroundColor White

$pyScript = @"
import sys
try:
    from pymongo import MongoClient
    client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=5000)
    client.server_info()
    db = client['wfridd']
    for col in ['snapshots', 'drift_reports', 'alerts']:
        db[col].delete_many({})
    print('OK')
except Exception as e:
    print('ERR:' + str(e))
"@
$result = python -c $pyScript 2>$null
if ($result -eq 'OK') {
    Write-Pass "MongoDB forensic_drift cleared"
} else {
    Write-WarnMsg "MongoDB not cleared: $result"
    Write-Info "Ensure MongoDB service is running, then re-run this script."
}

# -- Local evidence directories (only with -Purge) ----------------------------
if ($Purge) {
    Write-Host ""
    Write-WarnMsg "-Purge specified: wiping local evidence directories."
    Write-Host ""

    # Files locked via deny-write ACL (coc_manager.py, Day 7+) need the ACL
    # cleared before deletion - icacls /reset handles that; no-op otherwise.
    $evidenceDirs = @("snapshots", "reports", "coc_log")
    foreach ($d in $evidenceDirs) {
        $path = Join-Path $ProjectDir $d
        if (Test-Path $path) {
            icacls $path /reset /T /C *>$null
            Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Pass "$d\ purged"
        }
    }

    Write-Host ""
    Write-Pass "Local evidence directories purged"
}
if (-not $Purge) {
    Write-Info "Local evidence (snapshots, reports, coc_log) left in place."
    Write-Info "To wipe them too, run:  .\uninstall.ps1 -Purge"
}

Write-Host ""
Write-Host "Uninstall complete." -ForegroundColor Green
Write-Info "The project folder and Python environment remain; delete manually if desired."
