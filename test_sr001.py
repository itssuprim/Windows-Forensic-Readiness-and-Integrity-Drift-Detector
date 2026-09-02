import re, sys
sys.path.insert(0, r"C:\Users\supri\OneDrive\Desktop\WFRIDD")
from suppression import suppress_services

class _C:
    def __init__(self, ct, key, bv=None, cv=None):
        self.change_type = ct
        self.key = key
        self.baseline_value = bv or {}
        self.current_value = cv or {}

CASES = [
    # (label, change, expected)
    ("known base added Valid (5 hex)",      _C("added",   "OneSyncSvc_40be3",      cv={"signing_status": "Valid"}),    True),
    ("known base added Valid (5 hex) #2",   _C("added",   "WpnUserService_59d25",  cv={"signing_status": "Valid"}),    True),
    ("known base added unsigned",           _C("added",   "OneSyncSvc_40be3",      cv={"signing_status": "Unknown"}),  False),
    ("known base removed (no signing req)", _C("removed", "WpnUserService_59d25",  bv={"signing_status": "Valid"}),    True),
    ("known base removed unsigned bv",      _C("removed", "CDPUserSvc_aabbcc",     bv={"signing_status": "Unknown"}),  True),   # removed: no signing check
    ("unknown base added Valid",            _C("added",   "EvilSvc_1a2b3c",        cv={"signing_status": "Valid"}),    False),
    ("unknown base removed",               _C("removed",  "EvilSvc_1a2b3c",        bv={"signing_status": "Valid"}),    False),
    ("suffix 4 hex (too short)",            _C("added",   "CDPUserSvc_ab12",       cv={"signing_status": "Valid"}),    False),
    ("suffix 5 hex (lower bound)",          _C("added",   "CDPUserSvc_ab12c",      cv={"signing_status": "Valid"}),    True),
    ("suffix 6 hex",                        _C("added",   "CDPUserSvc_ab12cd",     cv={"signing_status": "Valid"}),    True),
    ("suffix 8 hex (upper bound)",          _C("added",   "CDPUserSvc_ab12cdef",   cv={"signing_status": "Valid"}),    True),
    ("suffix 9 hex (too long)",             _C("added",   "CDPUserSvc_ab12cdefe",  cv={"signing_status": "Valid"}),    False),
    ("no hex suffix at all",                _C("added",   "OneSyncSvc",            cv={"signing_status": "Valid"}),    False),
    ("modified still uses category 1 path", _C("modified","WpnUserService_59d25",
                                               bv={"signing_status":"Valid","state":"Running","start_type":"Auto"},
                                               cv={"signing_status":"Valid","state":"Stopped","start_type":"Auto"}),   False),  # WU not confirmed
]

passed = failed = 0
for label, change, expected in CASES:
    got = suppress_services(change)
    ok = got == expected
    print(f"{'OK  ' if ok else 'FAIL'} {label}: got={got} expected={expected}")
    if ok: passed += 1
    else:  failed += 1

print(f"\n{passed}/{passed+failed} passed", "— all good" if not failed else "— FAILURES above")