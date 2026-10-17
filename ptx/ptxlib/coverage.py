"""Coverage accounting — what was actually tested, and what was not.

A pentest report that lists findings is half a report. The other half is the statement of
what was NOT examined, because a reader cannot tell an absence of findings from an absence
of testing. Scanners do not produce this; they emit results and let silence imply safety.

This module derives coverage from the structured action log rather than from anyone's
memory or prose. It answers three questions:

  * which (probe class, endpoint) pairs were exercised
  * which endpoints were discovered but never probed at all
  * which probe classes never ran against anything

The third is the one that catches a quietly aborted engagement: every probe reports a
result, so a run that stopped after two probes still looks like a completed run unless
something counts what is missing.
"""

import re

# Probe classes that need no parameters, so their absence is unambiguous.
PARAMETERLESS = {"exposure", "headers"}

# Endpoints that take no user input, so suggesting an injection probe against them is
# noise. A coverage list a reader has to filter mentally gets skimmed and then ignored,
# which is worse than a shorter list they trust.
STATIC_EXT = re.compile(
    r"\.(?:env|json|js|css|png|jpe?g|gif|svg|ico|txt|xml|map|woff2?|ttf|lock|sql|"
    r"config|md|yml|yaml|zip|gz|pdf|csv)(?:$|[?#])", re.I)

# Probes that only make sense against an endpoint taking user input.
INPUT_PROBES = {"sqli", "xss", "cmdi", "ssrf", "traversal", "redirect", "ssti"}

# Probe classes that require a specific endpoint or parameter to mean anything.
TARGETED = {"idor", "sqli", "xss", "stored-xss", "cmdi", "ssrf", "traversal",
            "jwt-none", "redirect", "method-tamper", "ssti", "race", "mass-assignment",
            # Business logic. These are targeted too — they need the specific endpoint
            # that mutates state — but they were missing from this set entirely, so an
            # engagement that never ran them reported "never run at all (13)" and listed
            # none of the four. A coverage report that omits a whole class of testing is
            # worse than no coverage report, because it reads as complete.
            "negative-qty", "price-tamper", "refund-abuse", "workflow-bypass",
            "constraint-logic", "response-credential-leak", "double-spend", "race-consume",
            "csrf",
            # Read-only and needs a specific protected route, so targeted rather than
            # parameterless — it establishes a denial baseline on that route first.
            "acl-bypass", "user-enum", "cors", "privilege", "session-forge",
            "confused-deputy", "git-history-leak"}


# Classes whose evidence comes from passive collection rather than from a probe against the
# target. `known_classes()` includes them so the coverage report accounts for them, and the
# registry test documents them as an exception rather than waving them through — the same
# discipline that caught four business-logic probes missing from this file.
PASSIVE = {"subdomain takeover"}

# Classes whose severity assumes a second principal, not merely an authenticated one.
# Derived from what chains.REQUIRES actually says about each class rather than guessed:
# IDOR "assumes an attacker can hold two authenticated identities", and CSRF "assumes a
# logged-in victim who visits attacker-controlled content". The other six need only one
# account able to perform an action, which a single greybox credential supplies.
SECOND_IDENTITY = {"idor", "csrf", "privilege"}


def known_classes():
    """Every probe class this tool knows how to report coverage for.

    Single source of truth, cross-checked against the CLI's probe choices by the test
    suite. Adding a probe means adding it here too — and if that is forgotten the test
    fails rather than the coverage report quietly shrinking.
    """
    return PARAMETERLESS | TARGETED | PASSIVE


# Endpoints are scraped out of finding titles and evidence, which is prose. A bare
# "/anything" regex pulled `/3.1.8` and `/3.13.14` out of the banner
# "server=Werkzeug/3.1.8 Python/3.13.14" and the coverage report then told the operator to
# run IDOR against them. Noise in a coverage list is not harmless: the list is long, and a
# reader who sees nonsense in it stops reading the rest.
_ROUTE = re.compile(r"^/(?:[A-Za-z_.<>{}]|$)")


def _looks_like_route(cand):
    """A route starts with a letter, an underscore, or a path-parameter bracket.

    A segment starting with a digit is almost always a version, a port, or a fragment of
    one scraped out of a banner or a stack trace — never an endpoint anyone can request.
    """
    if not cand or len(cand) < 2:
        return False
    if not _ROUTE.match(cand):
        return False
    # A path whose only content is punctuation is not a route either.
    if not re.search(r"[A-Za-z_<>{}]", cand):
        return False
    return True


def summarise(engagement, findings=None, assessment_type=None):
    """`assessment_type` was written to scope.yaml and printed by `ptx status`, but
    nothing ever read it — the third time this codebase shipped a control with no reader.

    It matters for one thing that a coverage report gets wrong otherwise. In a blackbox
    engagement the operator has no credentials, so every class that assumes an
    authenticated identity *cannot* be run. Listing those under "never run at all" tells
    the operator they forgot something they were never able to do, and a gap list that
    contains items you could not have closed gets skimmed — which hides the ones you
    could.
    """
    from . import state
    acts = state.actions(engagement)
    findings = findings if findings is not None else []

    tested = set()
    verdicts = {}
    for a in acts:
        if a.get("probe"):
            key = (a["probe"], a.get("endpoint") or "/")
            tested.add(key)
            verdicts[key] = a.get("verdict")

    # Endpoints the engagement knows about: probed endpoints plus any named in findings.
    endpoints = {ep for _, ep in tested}
    for f in findings:
        for m in re.finditer(r"(/[A-Za-z0-9_./<>{}\-]+)", str(f.get("title", ""))):
            if _looks_like_route(m.group(1)):
                endpoints.add(m.group(1))
        ev = str(f.get("evidence", ""))
        for m in re.finditer(r"(/[A-Za-z0-9_./\-]{2,})", ev):
            # A path fragment inside prose is not necessarily an endpoint. Require it to
            # look like a route rather than a version, a port, or a filename in passing.
            if _looks_like_route(m.group(1)):
                endpoints.add(m.group(1))
    endpoints = {e for e in endpoints if e and len(e) > 1}
    # Normalise: an endpoint's identity is its path. A probe recorded against
    # "/search?q" and one against "/search" are the same target examined twice.
    normalised = set()
    for e in endpoints:
        path = e.split("?")[0]
        # "/api/invoices/<id>" and "/api/invoices" are the same target; a finding title
        # writes the placeholder, the probe records the base path.
        path = re.sub(r"/<[^>]+>/?$", "", path) or path
        path = path.rstrip("/") or "/"
        if len(path) > 1:
            normalised.add(path)
    endpoints = normalised

    probes_used = {p for p, _ in tested}
    all_missing = sorted((PARAMETERLESS | TARGETED | PASSIVE) - probes_used)
    # chains.REQUIRES is the single source of truth for "this class assumes a capability
    # the operator may not have". Reading it here keeps the two files from drifting, which
    # is the failure this codebase has already paid for twice.
    from . import chains as _chains
    needs_identity = set(_chains.REQUIRES)
    at = (assessment_type or "").strip().lower()
    # A single test account does not make every identity-requiring class runnable. Two of
    # them need a SECOND principal, which one credential cannot supply: IDOR is only
    # demonstrable by comparing what two different accounts can each see, and CSRF needs a
    # victim who is logged in somewhere else. Marking those runnable in a greybox test
    # would put them back on the "you forgot this" list, which is the exact problem the
    # blackbox split was added to solve.
    if at == "blackbox":
        # The union, not just REQUIRES. A class that needs a SECOND identity needs an
        # identity, so it is out of reach with no credentials at all too. Listing it
        # separately would let the same class be "out of reach" for greybox and
        # "you forgot it" for blackbox, which is the contradiction this split exists to
        # prevent. The relationship is monotonic by construction: blackbox blocks a
        # superset of what greybox blocks.
        blocked = sorted(set(all_missing) & (needs_identity | SECOND_IDENTITY))
    elif at == "greybox":
        blocked = sorted(set(all_missing) & SECOND_IDENTITY)
    else:
        # whitebox, or unspecified: nothing is out of reach on access grounds.
        blocked = []
    never_run = sorted(set(all_missing) - set(blocked))

    # A class whose every verdict is inconclusive was attempted but never measured. It is
    # not coverage. Before the probes carried a real flag, the log recorded these as
    # "negative", so `ptx coverage` reported a clean, complete engagement for a run where
    # several classes never observed their own effect — the report said "tested" and meant
    # "contacted".
    inconclusive_only = sorted(
        cls for cls in probes_used
        if cls not in {p for p, _ in tested if verdicts[(p, _)] != "inconclusive"}
        and any(v == "inconclusive" for (p, _), v in verdicts.items() if p == cls))

    # Parameterless probes should have run exactly once; their absence is a plain gap.
    missing_parameterless = sorted(PARAMETERLESS - probes_used)

    # Targeted probes against endpoints that were never examined by them. This is a
    # suggestion list, not an accusation: not every endpoint takes every parameter.
    untested_pairs = []
    for cls in sorted(TARGETED & probes_used):
        # Lower-cased on both sides. The acl-bypass probe's evidence names the variant it
        # succeeded with — /ADMIN/PANEL for /admin/panel — and the endpoint scraper added
        # that to the inventory, so the report advised running the ACL bypass probe against
        # the very URL it had just used to bypass. HTTP paths are case-sensitive, but for a
        # checklist of "which routes have you tried this class on" they are one route.
        hit = {(ep or "").split("?")[0].lower() for p, ep in tested if p == cls}
        for ep in sorted(endpoints):
            if (ep or "").split("?")[0].lower() in hit:
                continue
            # No targeted probe is meaningful against a static file — an .env cannot have
            # an IDOR, a race condition, or a method-tampering bypass. Suggesting one is
            # noise, and noise is what gets a coverage list skimmed and then ignored.
            if STATIC_EXT.search(ep):
                continue
            untested_pairs.append({"probe": cls, "endpoint": ep})

    return {
        "actions_recorded": len(acts),
        "probes_exercised": sorted(probes_used),
        "endpoint_probe_pairs_tested": sorted(f"{p} {e}" for p, e in tested),
        "endpoints_known": sorted(endpoints),
        "probe_classes_never_run": never_run,
        "probe_classes_blocked_by_access": blocked,
        "assessment_type": at or None,
        "inconclusive_only": inconclusive_only,
        "parameterless_never_run": missing_parameterless,
        "untested_pairs": untested_pairs[:80],
        "untested_pair_count": len(untested_pairs),
        "verdicts": {f"{p} {e}": v for (p, e), v in sorted(verdicts.items())},
    }


def render(cov):
    L = ["## Coverage — what was and was not tested", ""]
    if not cov["actions_recorded"]:
        # Keep the warning, but do NOT return here. The early return skipped every gap
        # section, so a brand-new engagement — the moment the operator most needs the list
        # of what has not been tested — got one sentence instead of it. "Nothing can be
        # said about coverage" is also not quite true: what has not been run is known
        # exactly, and that is most of the report.
        L.append("_No structured actions recorded yet. An empty finding list must not be "
                 "read as a clean result. Everything below is still outstanding._")
        L.append("")
    L.append(f"- {cov['actions_recorded']} recorded action(s)")
    L.append(f"- probe classes exercised: {', '.join(cov['probes_exercised']) or 'none'}")
    L.append(f"- endpoints known to this engagement: {len(cov['endpoints_known'])}")
    L.append(f"- (probe, endpoint) pairs tested: {len(cov['endpoint_probe_pairs_tested'])}")
    L.append("")
    if cov.get("inconclusive_only"):
        L.append(f"### Attempted but never measured ({len(cov['inconclusive_only'])})")
        L.append("")
        L.append("Every verdict for these classes was inconclusive: the request went out, "
                 "but the effect could not be observed, so no conclusion is recorded. "
                 "**Treat these as gaps, not as clean results.**")
        L.append("")
        L.append("`" + "`, `".join(cov["inconclusive_only"]) + "`")
        L.append("")
    if cov.get("probe_classes_blocked_by_access"):
        L.append(f"### Not runnable without credentials "
                 f"({len(cov['probe_classes_blocked_by_access'])})")
        L.append("")
        L.append("`" + "`, `".join(cov["probe_classes_blocked_by_access"]) + "`")
        L.append("")
        L.append("This engagement is declared `assessment_type: blackbox`, so no "
                 "authenticated identity was available. These classes assume one. They "
                 "are listed apart from the gaps below on purpose: they are **out of "
                 "reach**, not forgotten. A greybox or whitebox pass with one test "
                 "account would cover them.")
        L.append("")
    if cov["probe_classes_never_run"]:
        L.append(f"### Never run at all ({len(cov['probe_classes_never_run'])})")
        L.append("")
        L.append("`" + "`, `".join(cov["probe_classes_never_run"]) + "`")
        L.append("")
        L.append("These probe classes produced no result because they were never invoked. "
                 "That is a gap in this engagement, not evidence of an absence of "
                 "vulnerabilities.")
        L.append("")
    if cov["parameterless_never_run"]:
        L.append(f"**Unambiguous gaps:** `{'`, `'.join(cov['parameterless_never_run'])}` need "
                 f"no parameters and should always run.")
        L.append("")
    if cov["untested_pairs"]:
        L.append(f"### Endpoint/probe combinations not exercised "
                 f"({cov['untested_pair_count']})")
        L.append("")
        L.append("A probe was run somewhere, but not against these endpoints. Not every "
                 "endpoint accepts every parameter, so this is a checklist to reason "
                 "through, not a list of failures.")
        L.append("")
        L.append("| probe | endpoint not tested |")
        L.append("|---|---|")
        for p in cov["untested_pairs"][:40]:
            L.append(f"| `{p['probe']}` | `{p['endpoint']}` |")
        if cov["untested_pair_count"] > 40:
            L.append(f"| … | {cov['untested_pair_count'] - 40} more |")
        L.append("")
    return "\n".join(L)
