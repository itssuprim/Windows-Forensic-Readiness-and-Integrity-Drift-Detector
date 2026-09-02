# =============================================================================
# install.ps1 - One-Click Installer
# Windows Forensic Readiness and Integrity Drift Detector
#
# Run from an elevated PowerShell prompt, inside the project folder:
#
#     .\install.ps1                          # scan daily at 11:00 (default)
#     .\install.ps1 -ScanTime "03:30"        # scan daily at 03:30
#     .\install.ps1 -ScanTime "22:00"        # scan daily at 22:00
#
# -ScanTime accepts "HH:MM" (24-hour clock). The scan runs run.py --now
# (single cycle, exits cleanly) at logon AND at the daily scheduled time.
# The dashboard task fires at logon and stays running as a background process.
# =============================================================================

#Requires -RunAsAdministrator

param(
    [string]$ScanTime = ""
)

$ErrorActionPreference = "Stop"

function Write-Pass    ($msg) { Write-Host "[PASS] $msg" -ForegroundColor Green  }
function Write-Info    ($msg) { Write-Host "[INFO] $msg" -ForegroundColor Cyan   }
function Write-WarnMsg ($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-FailMsg ($msg) { Write-Host "[FAIL] $msg" -ForegroundColor Red    }

Write-Host ""
Write-Host "================================================================" -ForegroundColor White
Write-Host "   Windows Forensic Readiness and Integrity Drift Detector"      -ForegroundColor White
Write-Host "   One-Click Installer"                                           -ForegroundColor White
Write-Host "================================================================" -ForegroundColor White
Write-Host ""

# =============================================================================
# STEP 0 - Prompt for scan time if not supplied, validate, check elevation
# =============================================================================
if ($ScanTime -eq "") {
    Write-Host "Enter the daily scan time in 24-hour HH:MM format." -ForegroundColor White
    Write-Host "Press Enter to accept the default [11:00]: " -ForegroundColor White -NoNewline
    $raw = Read-Host
    if ($raw -eq "") { $ScanTime = "11:00" } else { $ScanTime = $raw.Trim() }
}

if ($ScanTime -notmatch '^\d{2}:\d{2}$') {
    Write-FailMsg "-ScanTime must be HH:MM (e.g. '02:00'). Got: '$ScanTime'"
    exit 1
}
$scanHour   = [int]$ScanTime.Split(':')[0]
$scanMinute = [int]$ScanTime.Split(':')[1]
if ($scanHour -gt 23 -or $scanMinute -gt 59) {
    Write-FailMsg "-ScanTime '$ScanTime' is not valid. Use 24-hour HH:MM (00:00-23:59)."
    exit 1
}

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-FailMsg "This installer must run elevated. Re-open PowerShell as Administrator."
    exit 1
}
Write-Pass "Running elevated"
Write-Info "Scan schedule: at logon + daily at $ScanTime"

# =============================================================================
# STEP 1 - Project directory + sanity check
# =============================================================================
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Info "Project dir: $ProjectDir"
Set-Location $ProjectDir

$CoreFiles = @("config.py", "run.py", "collection_agent.py", "setup_env.py", "requirements.txt", "dashboard.py")
$missing = @()
foreach ($f in $CoreFiles) {
    if (-not (Test-Path (Join-Path $ProjectDir $f))) { $missing += $f }
}
if ($missing.Count -gt 0) {
    Write-FailMsg "Missing required file(s): $($missing -join ', ')"
    Write-Info "Run this installer from inside the project folder."
    exit 1
}
Write-Pass "Core project files found"

# =============================================================================
# STEP 2 - Python dependencies via setup_env.py
# =============================================================================
Write-Host ""
Write-Host "-- Installing Python dependencies --" -ForegroundColor White
python setup_env.py
if ($LASTEXITCODE -ne 0) {
    Write-FailMsg "setup_env.py reported failures. Resolve them before continuing."
    exit 1
}
Write-Pass "Python environment ready"

# =============================================================================
# STEP 3 - MongoDB check / install
# =============================================================================
Write-Host ""
Write-Host "-- Checking MongoDB --" -ForegroundColor White

$mongoService = Get-Service -Name "MongoDB" -ErrorAction SilentlyContinue
if ($mongoService) {
    Write-Info "MongoDB service already present (status: $($mongoService.Status))"
    if ($mongoService.Status -ne "Running") {
        Start-Service -Name "MongoDB"
        Write-Pass "MongoDB service started"
    }
} else {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Info "MongoDB not found - installing via winget..."
        winget install --id MongoDB.Server --silent --accept-package-agreements --accept-source-agreements
        Write-WarnMsg "Installed via winget - verify the MongoDB service is registered (Get-Service MongoDB)."
    } else {
        Write-WarnMsg "winget not available and MongoDB not found."
        Write-Info "Install manually from https://www.mongodb.com/try/download/community, then re-run this installer."
    }
}

# =============================================================================
# STEP 4 - Initialise directories
# =============================================================================
Write-Host ""
Write-Host "-- Initialising project directories --" -ForegroundColor White

$dirs = @("snapshots", "reports", "coc_log", "logs", "rules")
foreach ($d in $dirs) {
    $path = Join-Path $ProjectDir $d
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path | Out-Null
    }
}
Write-Pass "Directories ready: $($dirs -join ', ')"

# =============================================================================
# STEP 5 - Scheduled Tasks
#
# Task 1: ForensicDriftDetector
#   Triggers: (a) at every logon, (b) daily at -ScanTime.
#   Action  : python run.py --now  (single cycle, exits cleanly).
#   Mirrors the Linux cron job - one scan per trigger, not a looping daemon.
#   MultipleInstances=IgnoreNew prevents stacking if both triggers overlap.
#
# Task 2: ForensicDriftDetectorDashboard
#   Trigger : at logon (stays alive as background process).
#   Dashboard available at http://localhost:5001 as soon as you log in.
#
# Python path resolved via sys.executable (avoids the Windows Store stub at
# WindowsApps\python.exe, which is a redirect shim that can fail in tasks).
# Principal omitted intentionally - Register-ScheduledTask defaults to the
# current user, avoiding the Access Denied that occurs when combining
# -RunLevel Highest with -LogonType Interactive in a custom Principal block.
# =============================================================================
Write-Host ""
Write-Host "-- Registering Scheduled Tasks --" -ForegroundColor White

# Resolve real python via sys.executable, not Get-Command (avoids Store stub)
$pythonPath = python -c "import sys; print(sys.executable)" 2>$null
if (-not $pythonPath -or -not (Test-Path $pythonPath)) {
    Write-WarnMsg "Cannot resolve python.exe - scheduled tasks will be skipped."
    Write-Info "Ensure Python is installed and on PATH, then re-run this installer."
} else {
    Write-Info "Python: $pythonPath"

    # pythonw.exe is the windowless interpreter - no console window on launch.
    # It lives alongside python.exe in the same Scripts/install directory.
    # Fall back to python.exe only if pythonw.exe is somehow absent.
    $pythonwPath = $pythonPath -replace 'python\.exe$', 'pythonw.exe'
    if (-not (Test-Path $pythonwPath)) {
        Write-WarnMsg "pythonw.exe not found at $pythonwPath - falling back to python.exe (console window will appear)"
        $pythonwPath = $pythonPath
    } else {
        Write-Info "Using pythonw.exe for silent background execution: $pythonwPath"
    }

    $userAccount = "$env:USERDOMAIN\$env:USERNAME"

    # ---- Task 1: ForensicDriftDetector (scan at logon + daily) -------------
    $scanTaskName = "ForensicDriftDetector"
    $existingScan = Get-ScheduledTask -TaskName $scanTaskName -ErrorAction SilentlyContinue
    if ($existingScan) {
        Write-Info "$scanTaskName already registered - replacing."
        Unregister-ScheduledTask -TaskName $scanTaskName -Confirm:$false
    }

    $scanAction = New-ScheduledTaskAction `
        -Execute          $pythonwPath `
        -Argument         "run.py --now" `
        -WorkingDirectory $ProjectDir

    $scanTriggers = @(
        (New-ScheduledTaskTrigger -AtLogOn -User $userAccount),
        (New-ScheduledTaskTrigger -Daily   -At   $ScanTime)
    )

    $scanSettings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Hours 0) `
        -MultipleInstances  IgnoreNew `
        -Hidden

    Register-ScheduledTask `
        -TaskName    $scanTaskName `
        -Action      $scanAction `
        -Trigger     $scanTriggers `
        -Settings    $scanSettings `
        -RunLevel    Highest `
        -Description "WFRIDD - daily drift scan (run.py --now) at logon and $ScanTime" | Out-Null

    Write-Pass "$scanTaskName registered (at logon + daily at $ScanTime)"

    # ---- Task 2: ForensicDriftDetectorDashboard (at logon) -----------------
    $dashTaskName = "ForensicDriftDetectorDashboard"
    $existingDash = Get-ScheduledTask -TaskName $dashTaskName -ErrorAction SilentlyContinue
    if ($existingDash) {
        Write-Info "$dashTaskName already registered - replacing."
        Unregister-ScheduledTask -TaskName $dashTaskName -Confirm:$false
    }

    $dashAction = New-ScheduledTaskAction `
        -Execute          $pythonwPath `
        -Argument         "dashboard.py" `
        -WorkingDirectory $ProjectDir

    $dashTrigger = New-ScheduledTaskTrigger -AtLogOn -User $userAccount

    $dashSettings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Hours 0) `
        -MultipleInstances  IgnoreNew `
        -Hidden

    Register-ScheduledTask `
        -TaskName    $dashTaskName `
        -Action      $dashAction `
        -Trigger     $dashTrigger `
        -Settings    $dashSettings `
        -RunLevel    Highest `
        -Description "WFRIDD - Flask dashboard (dashboard.py on port 5001)" | Out-Null

    Write-Pass "$dashTaskName registered (at logon)"
}

# =============================================================================
# STEP 6 - Create golden baseline + first daily snapshot
# =============================================================================
Write-Host ""
Write-Host "-- Creating golden baseline and first daily snapshot --" -ForegroundColor White
Write-Info "Running run.py --now  (this may take up to a minute)..."
python run.py --now
if ($LASTEXITCODE -ne 0) {
    Write-WarnMsg "First run returned a non-zero exit code. Check logs\wfridd.log for details."
} else {
    Write-Pass "Golden baseline ACL-locked and first daily snapshot stored"
}

# =============================================================================
# DONE
# =============================================================================
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Setup complete" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Info "Baseline : golden baseline ACL-locked + first daily snapshot stored"
Write-Info "Scan     : runs at every logon + daily at $ScanTime"
Write-Info "           To change the time: re-run .\install.ps1 -ScanTime HH:MM"
Write-Info "Dashboard: starts at every logon - http://localhost:5001"
Write-Host ""
Write-Info "To open the dashboard right now:"
Write-Host "   Start-ScheduledTask -TaskName ForensicDriftDetectorDashboard" -ForegroundColor White
Write-Host ""
$logsPath    = Join-Path $ProjectDir "logs\wfridd.log"
$reportsPath = Join-Path $ProjectDir "reports"
Write-Info "Logs    : $logsPath"
Write-Info "Reports : $reportsPath"
