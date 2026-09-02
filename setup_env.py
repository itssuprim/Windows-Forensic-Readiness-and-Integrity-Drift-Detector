# setup_env.py
# Installs and verifies the environment for the Windows Forensic Drift
# Detector. Run this once before collection_agent.py.
#
# What this does that a bare `pip install -r requirements.txt` doesn't:
#   - refuses to run on non-Windows (most of this tool's stdlib deps,
#     winreg/ctypes.windll, don't exist elsewhere — fail here, not
#     three collectors deep into Day 1 testing)
#   - checks Python version before wasting time on a pip run doomed to
#     half-fail on an old interpreter
#   - runs pywin32's post-install step, which pip alone does not do,
#     and which is a known source of "import win32security works in
#     one shell but not another" confusion
#   - reports pass/fail per package instead of one wall of pip output

import platform
import subprocess
import sys

MIN_PYTHON = (3, 9)


def check_platform() -> bool:
    if platform.system() != "Windows":
        print(f"[FAIL] This tool targets Windows. Detected: {platform.system()}")
        return False
    print(f"[OK] Platform: Windows ({platform.version()})")
    return True


def check_python_version() -> bool:
    if sys.version_info < MIN_PYTHON:
        print(
            f"[FAIL] Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ required, "
            f"found {sys.version_info.major}.{sys.version_info.minor}"
        )
        return False
    print(f"[OK] Python {sys.version_info.major}.{sys.version_info.minor}")
    return True


def check_admin() -> bool:
    """Warn, don't block — setup itself doesn't need admin, but the tool
    will refuse to collect without it (see collectors/_shared.require_admin),
    so surfacing this now saves a round trip."""
    try:
        import ctypes
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        is_admin = False

    if is_admin:
        print("[OK] Running elevated")
    else:
        print(
            "[WARN] Not running elevated. Setup will proceed, but "
            "collection_agent.py requires admin rights to run — "
            "re-open this shell as Administrator before Day 1 testing."
        )
    return True


def install_requirements() -> bool:
    print("[..] Installing requirements.txt")
    # Do NOT use capture_output=True here — pip produces enough output to
    # fill the Windows pipe buffer and deadlock the stdout reader thread.
    # Stream directly to the terminal so output is visible in real time.
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
    )
    if result.returncode != 0:
        print("[FAIL] pip install failed — see output above")
        return False
    print("[OK] requirements.txt installed")
    return True


def run_pywin32_postinstall() -> bool:
    """pip installing pywin32 does not register its COM/DLL hooks — the
    package ships its own postinstall script for that. Skipping this step
    is the single most common cause of `win32security` importing in one
    environment and not another."""
    print("[..] Running pywin32 post-install")
    try:
        # Stream output directly — same deadlock risk as pip if captured.
        result = subprocess.run(
            [sys.executable, "-m", "pywin32_postinstall", "-install"],
        )
        if result.returncode != 0:
            print("[WARN] pywin32 post-install returned non-zero — check output above")
            return False
        print("[OK] pywin32 post-install complete")
        return True
    except FileNotFoundError:
        print(
            "[WARN] pywin32_postinstall module not found — pywin32 may not "
            "be installed yet, or this needs to be run again after install."
        )
        return False


def verify_imports() -> dict:
    """Per-package pass/fail, not one pip wall of text."""
    packages = {
        "win32security": "pywin32",
        "win32com.client": "pywin32",
        "wmi": "WMI",
        "yaml": "pyyaml",
        "reportlab": "reportlab",
        "flask": "flask",
        "pymongo": "pymongo",
        "schedule": "schedule",
        "winreg": "stdlib",
    }
    results = {}
    for module_name, package_name in packages.items():
        try:
            __import__(module_name)
            results[module_name] = "OK"
        except ImportError as e:
            results[module_name] = f"FAIL — {e}"

    print("\n--- Import verification ---")
    for module_name, status in results.items():
        marker = "[OK]" if status == "OK" else "[FAIL]"
        print(f"{marker} {module_name:20s} {status if status != 'OK' else ''}")

    return results


def main() -> int:
    print("=== Windows Forensic Drift Detector — Environment Setup ===\n")

    if not check_platform():
        return 1
    if not check_python_version():
        return 1
    check_admin()

    if not install_requirements():
        return 1
    run_pywin32_postinstall()

    results = verify_imports()
    failures = [k for k, v in results.items() if v != "OK"]

    print()
    if failures:
        print(f"[FAIL] {len(failures)} package(s) failed to import: {failures}")
        print("Resolve these before running collection_agent.py.")
        return 1

    print("[OK] Environment ready.")
    return 0


if __name__ == "__main__":
    sys.exit(main())