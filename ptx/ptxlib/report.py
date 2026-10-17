"""
Report generation.

Refuses to generate while any finding is invalid — that refusal is the point. It also
emits a "what was NOT tested" section derived from real logged coverage gaps, because
that section is what makes the rest of the report believable.
"""
import json, os, time

from . import findings as F

ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _coverage_gaps(engagement):
    """Pull coverage gaps out of the action log and the OSINT artefacts."""
    gaps = []
    lp = os.path.join(engagement, "log.md")
    if os.path.exists(lp):
        with open(lp) as f:
            for line in f:
                if "COVERAGE GAP" in line or "coverage gap" in line or "SOURCE UNAVAILABLE" in line:
                    gaps.append(line.strip().lstrip("#").strip())
    # Both passive-collection artefacts and recon artefacts carry coverage_gaps. Recon
    # only started being persisted after a bug: its gaps were printed once, counted in the
    # action log, and then lost — so "scan intercepted, SCAN INVALID" never reached a
    # report. Anything that can report a gap must be written somewhere this reads.
    for od in (os.path.join(engagement, "osint"), os.path.join(engagement, "recon")):
        if not os.path.isdir(od):
            continue
        for fn in sorted(os.listdir(od)):
            if not fn.endswith(".json"):
                continue
            try:
                with open(os.path.join(od, fn)) as f:
                    d = json.load(f)
                for g in d.get("coverage_gaps", []) or []:
                    gaps.append(f"{fn}: {g}")
                if d.get("enumerated") is False:
                    gaps.append(f"{fn}: source unavailable — enumeration did not run")
            except Exception:
                pass
    return sorted(set(gaps))


def _suspicion_stats(engagement):
    sp = os.path.join(engagement, "state.json")
    if not os.path.exists(sp):
        return {}
    with open(sp) as f:
        st = json.load(f)
    counts = {}
    for s in st.get("suspicions", []):
        counts[s["state"]] = counts.get(s["state"], 0) + 1
    return counts


def _all(engagement):
    from . import findings as _f
    return _f.all_findings(engagement)


def build(engagement, outdir=None):
    outdir = outdir or os.path.join(engagement, "report")
    os.makedirs(outdir, exist_ok=True)

    recs = F.all_findings(engagement)
    validation = F.validate_all(engagement)
    invalid = [v for v in validation if not v["valid"]]
    if invalid:
        lines = ["REPORT BLOCKED — invalid findings present:", ""]
        for v in invalid:
            lines.append(f"  {v['id']}  {v['title']}")
            for p in v["problems"]:
                lines.append(f"      - {p}")
        lines.append("")
        lines.append("Fix these before generating. A finding without evidence is a")
        lines.append("suspicion; a Critical without a stated business impact is inflation.")
        return None, lines

    recs.sort(key=lambda r: ORDER.get(r.get("severity"), 9))
    gaps = _coverage_gaps(engagement)
    susp = _suspicion_stats(engagement)
    scope = {}
    scp = os.path.join(engagement, "scope.yaml")
    if os.path.exists(scp):
        with open(scp) as f:
            scope = {"raw": f.read()}

    sev_counts = {}
    for r in recs:
        sev_counts[r["severity"]] = sev_counts.get(r["severity"], 0) + 1

    # --- executive summary ---
    ex = ["# Executive Summary", "",
          f"Assessment completed {time.strftime('%Y-%m-%d', time.gmtime())}.",
          f"**{len(recs)} confirmed findings**: " +
          (", ".join(f"{sev_counts[s]} {s}" for s in ORDER if s in sev_counts) or "none") + ".",
          ""]
    top = [r for r in recs if r["severity"] in ("Critical", "High")][:3]
    if top:
        ex.append("## The three issues that matter most")
        ex.append("")
        for r in top:
            ex.append(f"**{r['id']} — {r['title']} ({r['severity']})**")
            ex.append("")
            ex.append(r.get("impact") or r.get("summary", ""))
            ex.append("")
    else:
        ex.append("No Critical or High findings were confirmed.")
        ex.append("")
    ex += ["## What this report does not cover", "",
           "See the coverage gaps section. Absence of a finding is not evidence of "
           "security — it is evidence about what was tested.", ""]

    # --- technical report ---
    t = ["# Technical Report", "",
         "## Scope and methodology", "",
         "```", scope.get("raw", "scope.yaml not found").strip(), "```", "",
         f"Requests made and artefacts are indexed in the engagement directory. "
         f"{susp.get('falsified', 0)} suspicions were tested and falsified; "
         f"{susp.get('confirmed', 0)} were confirmed and became the findings below.", "",
         "## Findings", ""]
    for r in recs:
        t += [f"### {r['id']} — {r['title']}", "",
              f"**Severity:** {r['severity']}  ",
              f"**Class:** {r.get('class', '')}  ",
              f"**Status:** {r.get('status', 'confirmed')}  ",
              f"**Confirmed:** {r.get('confirmed_at', '')}", "",
              "#### Mechanism", "", r.get("summary") or "_not recorded_", "",
              "#### Impact", "", r.get("impact") or "_not recorded_", "",
              "#### Proof", "", "```", r.get("evidence", ""), "```", "",
              "#### Reproduction", "", r.get("reproduction") or "_not recorded_", "",
              "#### Remediation", "", r.get("remediation") or "_not recorded_", ""]
        # The teaching note and the remediation are the same string unless somebody wrote a
        # separate one, so printing both repeated every finding's advice under two headings.
        teach = r.get("teaching") or ""
        if teach and teach != (r.get("remediation") or ""):
            t += ["#### Teaching note", "", teach, ""]
        t += ["#### Evidence artefacts", "",
              *(f"- `{a}`" for a in (r.get("artifacts") or ["_none recorded_"])),
              "", "---", ""]

    t += ["## What was NOT tested", ""]
    if gaps:
        for g in gaps:
            t.append(f"- {g}")
    else:
        # This section reports gaps logged by the OSINT and recon phases. It used to say
        # "No coverage gaps were logged" while the Coverage section twenty lines below
        # listed nineteen probe classes that had never run — a report contradicting itself
        # on the page. Say which kind of gap is meant, and point at the section that does
        # have something to report.
        t.append("- No OSINT or recon coverage gaps were logged. Note that this is not the "
                 "same as test coverage: probe classes never invoked are listed under "
                 "*Coverage* below, and an engagement that ran no OSINT at all has a gap "
                 "here even when this list is empty.")
    t += ["", "## Suspicion ledger", "",
          "| State | Count |", "|---|---|"]
    for k in ("confirmed", "falsified", "substantiated", "probing", "suspected"):
        if susp.get(k):
            t.append(f"| {k} | {susp[k]} |")
    t += ["", "A falsified suspicion is evidence of coverage: it was tested and the "
          "hypothesis was disproven.", ""]

    # --- coverage accounting, from the structured action log ---
    try:
        from . import coverage as _cov
        t.append(_cov.render(_cov.summarise(engagement, recs))); t.append("")
    except Exception as e:
        # Was an HTML comment, which renders as nothing. The report then shipped with no
        # coverage accounting at all and looked complete — a reader cannot miss a section
        # that was never there, and the one line that knew about it was invisible. A missing
        # section must be as loud as a bad finding.
        t += ["## Coverage — SECTION FAILED TO GENERATE", "",
              f"> **This section could not be produced:** `{e}`",
              "",
              "Nothing below this line was measured. Do not read the absence of a coverage "
              "table as complete coverage — re-run `ptx coverage` and treat the engagement "
              "as unassessed until it produces output.", ""]

    # --- attack chains, probe reliability, evidence integrity ---
    try:
        from . import chains as _ch, reliability as _rl, integrity as _ig
        from . import state as _st
        ch, de = _ch.analyse(recs)
        t.append(_ch.render(ch, de)); t.append("")
        data = _rl.sync_from_engagement(engagement, findings=recs,
                                        suspicions=_st.suspicions(engagement))
        t.append(_rl.render(data)); t.append("")
        vres = _ig.verify_all(engagement, recs)
        broken = [v for v in vres if not v["ok"]]
        noted = [v for v in vres if v.get("notes")]
        t += ["## Evidence integrity", ""]
        if not recs:
            t.append("_No findings recorded._")
        elif not broken:
            t.append(f"All {len(vres)} findings sealed and intact. Each finding's evidence, "
                     f"impact and artifacts are pinned under a SHA-256 digest taken at "
                     f"confirmation, so any later edit is visible rather than silent.")
        else:
            t.append(f"**{len(broken)} of {len(vres)} findings are not intact:**")
            t.append("")
            for v in broken:
                for pr in v["problems"]:
                    t.append(f"- {v['id']}: {pr}")
            t += ["", "An unsealed or drifted finding is self-report. Re-confirm it or "
                      "re-seal it deliberately — the requirement is that the edit is "
                      "visible, not that editing is forbidden."]
        if noted:
            t += ["", f"{len(noted)} finding(s) reference artifacts that were never written "
                      f"to disk. The reference is a name, not a saved file, and cannot be "
                      f"independently checked."]
        t.append("")
    except Exception as e:
        # Same failure, worse consequences: this block covers the attack chains, the probe
        # reliability ledger AND the evidence-integrity check. Swallowing it silently meant
        # a report could ship with no integrity verification and nothing to say so — which
        # is precisely the assurance the section exists to give.
        t += ["## Chains, reliability and integrity — SECTIONS FAILED TO GENERATE", "",
              f"> **These sections could not be produced:** `{e}`",
              "",
              "The findings above have **not** been checked for evidence integrity, and no "
              "attack-chain or probe-reliability analysis was performed. Do not treat this "
              "report as verified. Re-run `ptx verify`, `ptx chain` and `ptx reliability`.",
              ""]

    rp = os.path.join(outdir, "report.md")
    ep = os.path.join(outdir, "exec-summary.md")
    with open(rp, "w") as f:
        f.write("\n".join(t))
    with open(ep, "w") as f:
        f.write("\n".join(ex))
    return {"report": rp, "exec": ep, "findings": len(recs), "severity_counts": sev_counts,
            "coverage_gaps": len(gaps)}, [
        f"report      -> {rp}",
        f"exec summary-> {ep}",
        f"findings    : {len(recs)} " +
        (", ".join(f"{sev_counts[s]} {s}" for s in ORDER if s in sev_counts) or ""),
        f"coverage gaps recorded: {len(gaps)}"]
