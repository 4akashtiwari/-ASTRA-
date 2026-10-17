"""Audit: every planted vulnerability must be MISSED when its own probe is disabled.

The mirror of audit_falsification.py. The scorecard used to compute each planted verdict
from raw HTTP requests against the target, so 25 of 28 recorded TRUE_POSITIVE without the
tool ever running -- "28/28 detection rate" was 3 tool detections and 25 assertions about
the target. This script breaks each probe in turn and requires its target to flip to
FALSE_NEGATIVE, which is only possible if the tool is genuinely on the path.

Run from the repo root:  python3 bench/audit_detection.py
"""
import re
import shutil
import subprocess
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROBES = os.path.join(ROOT, "ptx", "ptxlib", "probes.py")
SCORECARD = os.path.join(ROOT, "bench", "scorecard.py")
BACKUP = "/tmp/probes.detection.bak"

# target -> the probe whose verdict decides it
CASES = [
    ("V01", "probe_idor"), ("V02", "probe_sqli"), ("V03", "probe_xss"),
    ("V04", "probe_cmdi"), ("V05", "probe_exposure"), ("V06", "probe_exposure"),
    ("V07", "probe_privilege"), ("V08", "probe_race"),
    ("V09", "probe_stored_xss"), ("V10", "probe_ssrf"),
    ("V11", "probe_traversal"), ("V12", "probe_jwt_none"),
    ("V13", "probe_redirect"), ("V14", "probe_mass_assignment"),
    ("V15", "probe_exposure"), ("V16", "probe_user_enum"),
    ("V17", "probe_method_tamper"), ("V18", "probe_ssti"),
    ("V19", "probe_negative_quantity"), ("V20", "probe_price_tamper"),
    ("V21", "probe_refund_abuse"), ("V22", "probe_workflow_bypass"),
    ("V23", "probe_csrf"), ("V24", "probe_acl_bypass"),
    ("V25", "probe_user_enum"), ("V26", "probe_mass_assignment_fields"),
    ("V27", "probe_idor"), ("V28", "probe_session_forge"),
    ("V29", "probe_confused_deputy"),
    ("V30", "probe_constraint_logic"),
    ("V31", "probe_response_credential_leak"),
    ("V32", "probe_double_spend"),
    ("V33", "probe_race_consume"),
]


def disable(src, fn):
    """Make one probe always report clean, leaving every other probe intact."""
    pat = re.compile(r'^(def %s\(.*?\):)' % re.escape(fn), re.M | re.S)
    m = pat.search(src)
    if not m:
        raise AssertionError("cannot find %s" % fn)
    return src.replace(m.group(1), m.group(1) +
                       '\n    return _verdict("%s", "mutant", False, "probe disabled by '
                       'audit_detection", "", "", None)' % fn, 1)


def verdict(vid):
    out = subprocess.run([sys.executable, SCORECARD], capture_output=True,
                         text=True, timeout=600, cwd=ROOT).stdout
    for line in out.splitlines():
        if re.search(r'\b%s\b' % vid, line):
            for tag, name in (("FN", "FALSE_NEGATIVE"), ("TP", "TRUE_POSITIVE")):
                if tag in line:
                    return name
    return "RUN_FAILED"


def main():
    original = open(PROBES).read()
    shutil.copy(PROBES, BACKUP)
    # one probe can back several targets (probe_exposure backs V05/V06/V15), so disable
    # each distinct probe once and check every target that depends on it.
    by_probe = {}
    for vid, fn in CASES:
        by_probe.setdefault(fn, []).append(vid)

    results = {}
    try:
        for fn, vids in sorted(by_probe.items()):
            open(PROBES, "w").write(disable(original, fn))
            got = {v: verdict(v) for v in vids}
            results.update(got)
            print("  %-28s disabled -> %s" % (fn, ", ".join(
                "%s=%s" % (v, got[v]) for v in vids)))
    finally:
        shutil.copy(BACKUP, PROBES)
        assert open(PROBES).read() == original, "probes.py was not restored"
        print("  probes.py restored byte-identical")

    bad = [v for v, r in results.items() if r != "FALSE_NEGATIVE"]
    print()
    if bad:
        print("NOT TOOL-COUPLED (did not flip to FN): %s" % ", ".join(sorted(bad)))
        return 1
    print("All %d planted targets flip to FALSE_NEGATIVE when their probe is disabled."
          % len(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
