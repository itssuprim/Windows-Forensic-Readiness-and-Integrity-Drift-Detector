# collectors/software.py
# Category D — Software (1 artefact, SEMI-STATIC)
#   installed_software_64  SEMI-STATIC  (mode 2)

import logging

import config as cfg

logger = logging.getLogger(__name__)

UNINSTALL_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

# Registry value name -> output field name
_SW_FIELDS = [
    ("display_name",     "DisplayName"),
    ("version",          "DisplayVersion"),
    ("publisher",        "Publisher"),
    ("install_date",     "InstallDate"),
    ("uninstall_string", "UninstallString"),
]


def collect_installed_software_64() -> dict:
    """64-bit installed software from HKLM\\...\\Uninstall.

    Opens with KEY_WOW64_64KEY explicitly — this collector owns the 64-bit
    hive view. The 32-bit view (WOW6432Node) is a separate artefact if
    needed; mixing both into one collector would conflate two distinct
    registry surfaces.

    read_registry_value() from _shared.py does not accept access flags, so
    winreg is called directly here — but follows the same status+data return
    contract (never raises on missing key/value).

    Keyed by registry subkey name (GUID or product string) for stable
    comparator identity across snapshots. Entries with no DisplayName are
    skipped — they are uninstalled remnants with no forensic value.
    """
    import winreg

    try:
        access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY, 0, access) as root:
            data = {}
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(root, i)
                    i += 1
                except OSError:
                    break

                try:
                    with winreg.OpenKey(root, subkey_name, 0, access) as sk:
                        entry = {}
                        for field, reg_name in _SW_FIELDS:
                            try:
                                value, _ = winreg.QueryValueEx(sk, reg_name)
                                entry[field] = value
                            except OSError:
                                entry[field] = None

                        if not entry.get("display_name"):
                            continue

                        data[subkey_name] = entry

                except PermissionError:
                    logger.warning(
                        f"installed_software_64: access denied on subkey {subkey_name}"
                    )
                except OSError as e:
                    logger.warning(
                        f"installed_software_64: error reading subkey {subkey_name}: {e}"
                    )

        return {"status": "ok", "data": data}

    except FileNotFoundError:
        return {"status": "not_found", "data": {}}
    except PermissionError:
        return {"status": "access_denied", "data": {}}
    except OSError as e:
        logger.error(f"installed_software_64 failed: {e}")
        return {"status": "error", "data": {}, "error": str(e)}
