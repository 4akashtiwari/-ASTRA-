"""
Findings — validated records, not free text.

A finding without evidence cannot enter a report. The report generator refuses it and
says which one and why. This is the rule that makes the evidence discipline enforceable
rather than advisory.

Severity inflation is the other failure this guards: any Critical or High whose impact
statement is under two sentences triggers a warning, because a padded report gets skimmed
and the real Critical gets missed.
"""
import json, os, re, time

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _dir(engagement):
    d = os.path.join(engagement, "findings")
    os.makedirs(d, exist_ok=True)
    return d


def next_id(engagement):
    """Highest existing index + 1.

    An earlier version used len(existing)+1, which collides with an existing finding
    whenever one has been deleted: with PTX-001 removed and PTX-002 present, it returns
    PTX-002 and silently overwrites the surviving finding.
    """
    highest = 0
    for f in os.listdir(_dir(engagement)):
        m = re.match(r"PTX-(\d+)\.json$", f)
        if m:
            highest = max(highest, int(m.group(1)))
    return f"PTX-{highest + 1:03d}"


def find_duplicate(engagement, probe_result):
    """A re-run probe must not create a second finding for the same vulnerability.

    Without this, iterating on a probe inflates the finding count — and a report with
    the same issue listed twice loses the reader's trust in every other number in it.
    """
    for rec in all_findings(engagement):
        if rec.get("class") == probe_result.get("id") and rec.get("title") == probe_result.get("name"):
            return rec
    return None


def from_probe(engagement, probe_result, artifacts=None, impact=None, repro=None):
    """Create a finding record from a probe verdict. Only confirmed probes become findings.

    Returns (record, created). If an identical finding already exists it is updated in
    place rather than duplicated.
    """
    if not probe_result.get("vulnerable"):
        return None, False
    dup = find_duplicate(engagement, probe_result)
    if dup:
        dup["evidence"] = probe_result.get("evidence", dup.get("evidence"))
        dup["teaching"] = probe_result.get("teaching", dup.get("teaching"))
        dup["reconfirmed_at"] = _now()
        with open(os.path.join(_dir(engagement), f"{dup['id']}.json"), "w") as f:
            json.dump(dup, f, indent=2)
        return dup, False
    fid = next_id(engagement)
    rec = {
        "id": fid,
        "title": probe_result["name"],
        "class": probe_result["id"],
        # Where the fault was confirmed, so a later variant sweep (`--from-finding`) or a
        # retest can find the location without re-deriving it from prose. Absent on
        # findings recorded before this field existed, and on parameterless probes.
        "endpoint": probe_result.get("endpoint"),
        "param": probe_result.get("param"),
        "severity": probe_result.get("severity") or "Medium",
        "status": "confirmed",
        "summary": probe_result.get("mechanism", ""),
        "impact": impact or "",
        "reproduction": repro or probe_result.get("evidence", ""),
        "evidence": probe_result.get("evidence", ""),
        "artifacts": artifacts or [],
        "secrets_found": probe_result.get("secrets_found") or [],
        "teaching": probe_result.get("teaching", ""),
        # Every probe writes its fix as the sixth positional argument to _verdict, which
        # lands in `teaching`. This line used to hardcode "" regardless, so the report
        # printed "#### Remediation / _not recorded_" on every finding while the very next
        # section carried the actual remediation under the heading "Teaching note". A
        # pentest report whose remediation column is always blank reads as though the tool
        # had nothing to say, when it had said it one line lower.
        "remediation": probe_result.get("remediation")
                       or probe_result.get("teaching", ""),
        "confirmed_at": _now(),
    }
    # Sealed at creation. Evidence that can be edited silently after the fact is
    # self-report, and self-report is not evidence.
    try:
        from . import integrity
        rec["seal"] = integrity.seal(engagement, rec)
    except Exception:
        pass
    with open(os.path.join(_dir(engagement), f"{fid}.json"), "w") as f:
        json.dump(rec, f, indent=2)
    return rec, True


def all_findings(engagement):
    out = []
    for fn in sorted(os.listdir(_dir(engagement))):
        if fn.endswith(".json"):
            with open(os.path.join(_dir(engagement), fn)) as f:
                out.append(json.load(f))
    return out


def get(engagement, fid):
    """One finding by id (e.g. 'PTX-003'), or None if it does not exist. The file is the id."""
    p = os.path.join(_dir(engagement), f"{fid}.json")
    if not os.path.exists(p):
        return None
    with open(p) as f:
        return json.load(f)


def validate(rec):
    """Returns (ok, problems). The report generator refuses findings that fail this."""
    problems = []
    if not rec.get("title"):
        problems.append("no title")
    if not rec.get("evidence"):
        problems.append("NO EVIDENCE — a finding without evidence is a suspicion")
    if not rec.get("reproduction"):
        problems.append("NO REPRODUCTION — a developer cannot fix what they cannot trigger")
    if rec.get("severity") not in SEVERITIES:
        problems.append(f"invalid severity {rec.get('severity')!r}")
    if not rec.get("impact"):
        problems.append("NO IMPACT STATEMENT — what does this let an attacker actually do?")
    if rec.get("artifacts") is not None and not rec.get("artifacts"):
        problems.append("no artifact references")

    sev = rec.get("severity")
    impact = rec.get("impact", "")
    if sev in ("Critical", "High"):
        sentences = [s for s in re.split(r"[.!?]+", impact) if s.strip()]
        if len(sentences) < 2:
            problems.append(
                f"{sev} finding with a {len(sentences)}-sentence impact statement — "
                f"state the business consequence in plain terms or downgrade the severity")
    return (not problems), problems


def validate_all(engagement):
    out = []
    for rec in all_findings(engagement):
        ok, problems = validate(rec)
        out.append({"id": rec["id"], "title": rec.get("title"), "valid": ok,
                    "problems": problems})
    return out
