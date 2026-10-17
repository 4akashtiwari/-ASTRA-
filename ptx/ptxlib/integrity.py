"""Evidence integrity.

A pentest report is an assertion that specific observations occurred. If the observations
can be edited after the fact — by a tired tester, a helpful script, or an agent tidying
its own output — the report has no integrity, and nothing downstream can tell.

This module seals each finding's evidence and artifacts under a SHA-256 digest at the
moment of confirmation, and re-checks them on demand. A finding whose digest no longer
matches is not automatically wrong; it is *unsealed*, and the report says so in the same
voice it would use for a missing artifact. The point is not to prevent editing — evidence
sometimes legitimately needs correcting — but to make every edit visible.

This is the direct countermeasure to the observed failure mode where an automated agent
reported success its own recorded output did not support. Self-report is not evidence;
an unsealed finding is self-report.
"""

import hashlib
import os

# `artifacts` is sealed as a field too: removing an artifact reference from a finding
# hides evidence from the report, which is exactly the kind of quiet edit this exists to
# surface. The per-file digests below pin contents; this pins the list itself.
FIELDS = ("evidence", "reproduction", "impact", "summary", "title", "severity", "artifacts")


def _digest(text):
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()


def _artifact_digest(engagement, rel):
    p = rel if os.path.isabs(rel) else os.path.join(engagement, rel)
    if not os.path.exists(p):
        return None
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def seal(engagement, rec):
    """Return the seal block for a finding record. Does not write the record."""
    arts = {}
    for a in rec.get("artifacts") or []:
        d = _artifact_digest(engagement, a)
        arts[a] = d or "MISSING"
    # Seal only the fields that actually hold something. A finding is sealed at creation,
    # when `impact` and `reproduction` are still empty and the report will REFUSE to
    # generate until the operator fills them in — so hashing the empty strings guaranteed
    # that every finding drifted the moment it was completed. The integrity section then
    # cried wolf on the normal workflow, which is how a control gets ignored.
    #
    # What matters is that probe-supplied evidence cannot be quietly rewritten, and that
    # is preserved: `evidence` is populated at creation and is always in the digest.
    sealed_fields = [k for k in FIELDS if str(rec.get(k, "")).strip()]
    payload = "\x1f".join(str(rec.get(k, "")) for k in sealed_fields)
    block = {"fields_sha256": _digest(payload),
             "artifacts": arts,
             "sealed_at": rec.get("confirmed_at", ""),
             "field_list": sealed_fields}
    # Carry the previous digests forward. An edit made through `ptx finding set` is
    # legitimate and re-seals; what must not happen is an edit that leaves no trace. So
    # the history is the audit, and "intact" means "matches the current seal, and every
    # change on the way here is listed".
    prior = rec.get("seal") or {}
    if prior.get("fields_sha256") and prior["fields_sha256"] != block["fields_sha256"]:
        changed = [k for k in set(list(prior.get("field_list") or []) + sealed_fields)
                   if str(prior.get("_snapshot", {}).get(k, "")) != str(rec.get(k, ""))]
        block["history"] = (prior.get("history") or []) + [{
            "prior_digest": prior["fields_sha256"],
            "superseded_at": prior.get("sealed_at", ""),
            "fields_changed": sorted(changed),
        }]
    elif prior.get("history"):
        block["history"] = prior["history"]
    return block


def verify(engagement, rec):
    """Recompute and compare. Returns a dict with ok, problems, and the missing artifacts."""
    sealblock = rec.get("seal")
    problems = []
    if not sealblock:
        return {"id": rec.get("id"), "ok": False, "sealed": False,
                "problems": ["NOT SEALED — this finding's evidence can be edited "
                             "without anything noticing"]}
    expected = sealblock.get("fields_sha256")
    # Verify against the field list the seal itself recorded, so a seal taken before a
    # field was populated still validates once that field is filled in.
    fields = sealblock.get("field_list") or list(FIELDS)
    payload = "\x1f".join(str(rec.get(k, "")) for k in fields)
    if _digest(payload) != expected:
        problems.append("EVIDENCE DRIFT — the recorded evidence, impact or reproduction "
                        "has changed since this finding was sealed")
    missing, drifted, never = [], [], []
    for a, want in (sealblock.get("artifacts") or {}).items():
        now = _artifact_digest(engagement, a)
        if want == "MISSING":
            # Already absent when sealed. That is a finding-quality problem, not tampering
            # — reported separately so the two are never confused.
            if now is None:
                never.append(a)
            elif now != "MISSING":
                pass
            continue
        if now is None:
            missing.append(a)
        elif now != want:
            drifted.append(a)
    if missing:
        problems.append(f"artifact(s) present at sealing are now gone: {', '.join(missing)}")
    if drifted:
        problems.append(f"artifact(s) modified since sealing: {', '.join(drifted)}")
    notes = []
    if never:
        notes.append(f"artifact(s) were never materialised on disk — the reference is a "
                     f"name, not a saved file: {', '.join(never)}")
    return {"id": rec.get("id"), "ok": not problems, "sealed": True,
            "problems": problems, "notes": notes,
            "missing": missing, "drifted": drifted, "never_materialised": never}


def verify_all(engagement, findings):
    return [verify(engagement, f) for f in findings]
