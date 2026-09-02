import logging
logging.basicConfig(level=logging.INFO)

from comparator import Finding
import severity_engine as se

print(f"Rules loaded: {len(se._RULES)}")
assert len(se._RULES) > 0, "YAML did not load"

# CRITICAL: run key added
f1 = Finding("run_keys_hklm", "added", "HKLM\\...\\malware.exe",
             baseline_value=None, current_value="C:\\malware.exe")
sf1 = se.score_finding(f1)
print(f"run_keys_hklm added -> {sf1.severity}, {sf1.rule_id}, {sf1.mitre_technique}")
assert sf1.severity == "CRITICAL", sf1.severity
assert sf1.mitre_technique == "T1547.001", sf1.mitre_technique

# CRITICAL: RDP enabled
f2 = Finding("rdp_config", "modified", "rdp_enabled",
             baseline_value=False, current_value=True)
sf2 = se.score_finding(f2)
print(f"rdp_config rdp_enabled=True -> {sf2.severity}, {sf2.rule_id}")
assert sf2.severity == "CRITICAL", sf2.severity

# HIGH: RDP port change (no key_equals match on rdp_enabled) -> W-B002
f3 = Finding("rdp_config", "modified", "port",
             baseline_value=3389, current_value=3390)
sf3 = se.score_finding(f3)
print(f"rdp_config port changed -> {sf3.severity}, {sf3.rule_id}")
assert sf3.severity == "HIGH", sf3.severity

# CRITICAL: UAC disabled (enable_lua -> 0)
f4 = Finding("uac_settings", "modified", "enable_lua",
             baseline_value=1, current_value=0)
sf4 = se.score_finding(f4)
print(f"uac_settings enable_lua=0 -> {sf4.severity}, {sf4.rule_id}")
assert sf4.severity == "CRITICAL", sf4.severity

# HIGH: UAC other field (no key_equals match) -> W-B004
f5 = Finding("uac_settings", "modified", "consent_prompt_behavior_admin",
             baseline_value=5, current_value=0)
sf5 = se.score_finding(f5)
print(f"uac_settings consent_prompt changed -> {sf5.severity}, {sf5.rule_id}")
assert sf5.severity == "HIGH", sf5.severity

# CRITICAL: lsa_protection RunAsPPL changed
f6 = Finding("lsa_protection", "modified", "RunAsPPL",
             baseline_value=2, current_value=0)
sf6 = se.score_finding(f6)
print(f"lsa_protection RunAsPPL -> {sf6.severity}, {sf6.rule_id}")
assert sf6.severity == "CRITICAL", sf6.severity

# CRITICAL: defender antivirus disabled
f7 = Finding("defender_status", "modified", "antivirus_enabled",
             baseline_value=True, current_value=False)
sf7 = se.score_finding(f7)
print(f"defender antivirus_enabled=False -> {sf7.severity}, {sf7.rule_id}")
assert sf7.severity == "CRITICAL", sf7.severity

# LOW: defender signature_version changes
f8 = Finding("defender_status", "modified", "signature_version",
             baseline_value="1.400.0.0", current_value="1.401.0.0")
sf8 = se.score_finding(f8)
print(f"defender signature_version -> {sf8.severity}, {sf8.rule_id}")
assert sf8.severity == "LOW", sf8.severity

# HIGH: dll_hijack_paths writable
f9 = Finding("dll_hijack_paths", "modified", "C:\\SomeDir",
             baseline_value={"exists": True, "writable_by_users": False},
             current_value={"exists": True, "writable_by_users": True})
sf9 = se.score_finding(f9)
print(f"dll_hijack_paths writable=True -> {sf9.severity}, {sf9.rule_id}")
assert sf9.severity == "HIGH", sf9.severity

# LOW: dll_hijack_paths added but NOT writable -> W-F004
f10 = Finding("dll_hijack_paths", "added", "C:\\NewDir",
              baseline_value=None,
              current_value={"exists": True, "writable_by_users": False})
sf10 = se.score_finding(f10)
print(f"dll_hijack_paths added not-writable -> {sf10.severity}, {sf10.rule_id}")
assert sf10.severity == "LOW", sf10.severity

# HIGH: services unsigned added
f11 = Finding("services", "added", "EvilSvc",
              baseline_value=None,
              current_value={"display_name": "Evil Service", "signing_status": "NotSigned",
                             "binary_path": "C:\\evil.exe", "start_type": "Auto",
                             "run_as": "LocalSystem", "state": "Running"})
sf11 = se.score_finding(f11)
print(f"services unsigned added -> {sf11.severity}, {sf11.rule_id}")
assert sf11.severity == "HIGH", sf11.severity

# MEDIUM: services signed added
f12 = Finding("services", "added", "LegitSvc",
              baseline_value=None,
              current_value={"signing_status": "Valid", "binary_path": "C:\\legit.exe",
                             "display_name": "Legit", "start_type": "Auto",
                             "run_as": "LocalSystem", "state": "Running"})
sf12 = se.score_finding(f12)
print(f"services signed added -> {sf12.severity}, {sf12.rule_id}")
assert sf12.severity == "MEDIUM", sf12.severity

# score_findings batch test
result = se.score_findings([f1, f2, f6, f7])
print(f"Batch: top_severity={result['top_severity']}, counts={result['severity_counts']}")
assert result["top_severity"] == "CRITICAL"
assert result["severity_counts"]["CRITICAL"] == 4

print("\nALL SEVERITY ENGINE TESTS PASS")
