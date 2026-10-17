"""Audit: every falsification target must flip when its own probe is broken.

A falsification target that records CORRECT_NEGATIVE no matter what the tool does is not
a test. Five of nine used to compute their verdict from raw HTTP requests rather than
from a probe, so they passed unconditionally. This script proves the fix by breaking each
probe in turn and requiring the matching target to become a FALSE_POSITIVE.

Run from the repo root:  python3 bench/audit_falsification.py
"""
import re
import shutil
import subprocess
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROBES = os.path.join(ROOT, "ptx", "ptxlib", "probes.py")
SCORECARD = os.path.join(ROOT, "bench", "scorecard.py")
BACKUP = "/tmp/probes.audit.bak"

# target -> (probe function signature to stub, severity the mutant must claim).
# N05 is the odd one: its oracle is severity inflation, so the mutant has to report
# Critical rather than merely "vulnerable" -- a Medium CORS finding is the correct
# answer and must stay a correct negative.
CASES = [
    ("N01", 'def probe_sqli(h, path, param, ctx="like"):', "Critical"),
    ("N02", 'def probe_traversal(h, path, param, payload, marker):', "Critical"),
    ("N03", 'def probe_xss(h, path, param, stored=None):', "Critical"),
    ("N04", 'def probe_cmdi(h, path, param):', "Critical"),
    ("N05", 'def probe_cors(h, path, cookie=None, origin="https://attacker.example"):',
     "Critical"),
    ("N06", 'def probe_acl_bypass(h, path, cookie=None):', "Critical"),
    ("N07", 'def probe_mass_assignment_fields(h, post_path, get_path, cookie, body, '
     'marker_field="message",\n                                 limit=6, '
     'variants=_TRUTH_VARIANTS):', "High"),
    ("N08", 'def probe_idor(h, endpoint, own_id, other_id, cookie=None, '
     'owner_field="user_id"):', "High"),
    ("N09", 'def probe_session_forge(h, paths, seed_path="/", method="GET", '
     'post_body=None,\n                        privileged_requests=None):', "Critical"),
    ("N10", 'def probe_confused_deputy(h, path, param="endpoint", upstream="https://api.github.com",\n                          auth_path="/user",\n                          private_path="/user/repos?visibility=private"):', "Critical"),
    ("N11", 'def probe_confused_deputy(h, path, param="endpoint", upstream="https://api.github.com",\n                          auth_path="/user",\n                          private_path="/user/repos?visibility=private"):', "Critical"),
    ("N12", 'def probe_constraint_logic(h, endpoint, params, impossible, verify, *,\n                           method="POST", baseline=None, max_models=8,\n                           vid="constraint-logic"):', "High"),
    ("N13", 'def probe_response_credential_leak(h, endpoint, method="GET", body=None, vid="response-credential-leak"):', "Critical"),
    ("N14", 'def probe_double_spend(h, state_endpoint, action_path, state_field, action_body=None,\n                       *, method="POST", vid="double-spend"):', "Critical"),
    ("N15", 'def probe_race_consume(h, state_endpoint, action_path, state_field, unit,\n                       action_body=None, *, method="POST", n=8, cookie=None,\n                       vid="race-consume"):', "Critical"),
]


def stub(sig, severity):
    """Return a probe body that always claims a finding at the given severity."""
    return (sig + '\n    return _verdict("mutant", "MUTANT", True, '
            '"always vulnerable", "", "", "%s", extra={"hits": [{}], '
            '"gated_fields": ["approved"], "ownership_markers": ["user_id"], '
            '"attempts": 1, "decoded_tokens": ["session"]})\n' % severity)


def scorecard_line(nid):
    out = subprocess.run([sys.executable, SCORECARD], capture_output=True,
                         text=True, timeout=600, cwd=ROOT).stdout
    for line in out.splitlines():
        if re.search(r'\b%s\b' % nid, line):
            if "FP" in line:
                return "FALSE_POSITIVE"
            if "CN" in line:
                return "CORRECT_NEGATIVE"
            if "TP" in line:
                return "TRUE_POSITIVE"
            if "FN" in line:
                return "FALSE_NEGATIVE"
    return "NOT_FOUND"


def main():
    shutil.copy(PROBES, BACKUP)
    original = open(PROBES).read()
    results = {}
    try:
        for nid, sig, sev in CASES:
            assert original.count(sig) == 1, f"signature not unique for {nid}: {sig!r}"
            open(PROBES, "w").write(original.replace(sig, stub(sig, sev)))
            got = scorecard_line(nid)
            results[nid] = got
            print("  %s  probe forced to always-vulnerable -> %s" % (nid, got))
    finally:
        shutil.copy(BACKUP, PROBES)
        assert open(PROBES).read() == original, "probes.py was not restored"
        print("  probes.py restored byte-identical")

    bad = [n for n, r in results.items() if r != "FALSE_POSITIVE"]
    print()
    if bad:
        print("VACUOUS TARGETS (did not flip): %s" % ", ".join(bad))
        return 1
    print("All %d audited targets flip when their probe is broken." % len(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
