"""
CVE reachability assessment.

This is the step that separates a useful report from scanner noise. A CVE in a library
the application never calls is not a finding — reporting it as Critical destroys
credibility and wastes a developer's week.

BLACK-BOX HONESTY: without source access you cannot prove reachability. This module
therefore produces a VERDICT WITH CONFIDENCE and states what would be needed to confirm.
It never claims certainty it does not have. The four verdicts:

  EXPOSED      the vulnerable component is directly reachable over HTTP, observed
  LIKELY       the component is server-side and the app's behaviour implies use
  UNDETERMINED cannot tell from outside — says exactly what would resolve it
  NOT_PRESENT  the component is client-side only or absent from the served application
"""
import json, re, urllib.request


def _get(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": "ptx-reachability/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except Exception:
        return None


# Components that only ever run in the browser. A server-side CVE here is not reachable
# through the web application at all — it is a supply-chain risk to *users*, which is a
# different finding with different severity.
CLIENT_SIDE_HINTS = re.compile(
    r"^(react|vue|angular|jquery|lodash-es|moment|chart\.js|d3|axios|bootstrap|"
    r"tailwind|@angular/|@vue/|@types/)", re.I)

# Components that ARE the HTTP request-handling layer. If the app serves HTTP and depends
# on one, the vulnerable code path is exercised by ordinary traffic.
HTTP_LAYER_PACKAGES = {"express", "koa", "fastify", "hapi", "@hapi/hapi", "connect",
                       "restify", "polka", "fastify-v3"}

# Advisory text indicating the flaw lives in request handling rather than an optional
# feature. Deliberately NARROW: an earlier version included "prototype pollution", which
# matched lodash and minimist advisories and marked both EXPOSED. Prototype pollution is
# a vulnerability CLASS reachable from many places — it says nothing about whether the
# request path reaches it. Over-broad heuristics here manufacture false positives, which
# is precisely the failure this module exists to prevent.
HTTP_LAYER_SIGNALS = re.compile(
    r"(request smuggling|malformed http request|http request smuggling|"
    r"open redirect in (res|express)|query string parser|url parsing)", re.I)


def _fingerprint(package, served):
    """Return why the served response fingerprints this package, or None.

    The previous version was `re.search(re.escape(package), served, re.I)` — a bare
    substring test. The npm packages `is`, `ms` and `has` all matched ordinary English
    prose, so a CVE in `is` came back **LIKELY / medium confidence** because the page
    contained the word "is". That is a false positive manufactured by the one module whose
    entire purpose is to stop false positives, and it is worse than no fingerprint at all
    because the operator sees it listed as evidence.

    Two rules now apply. The name must appear at a word boundary, and a short name (three
    characters or fewer, where an accidental collision with prose is likely) is only
    accepted in a structural position — a script src, a URL path segment, a package.json
    key, or next to a version number.
    """
    if not package or not served:
        return None
    esc = re.escape(package)
    boundary = r"(?<![A-Za-z0-9_.@/-])" + esc + r"(?![A-Za-z0-9_-])"
    # Structural positions: a script src, a URL path segment, a quoted JSON key, a
    # filename carrying an extension, or a name immediately followed by @version.
    Q = r"""["']"""
    parts = [
        r'src=' + Q + r'[^"\']*' + esc + r'[^"\']*' + Q,
        r'/' + esc + r'(?:[/.?]|$)',
        Q + esc + Q + r'\s*:',
        r'/' + esc + r'\.[A-Za-z]{1,5}\b',
        esc + r'@[0-9]',
    ]
    structural = re.compile("|".join("(?:" + p + ")" for p in parts), re.I)
    if len(package) <= 3:
        m = structural.search(served)
        if m:
            return (f"`{package}` appears in a structural position (script src, path "
                    f"segment, package key or version reference)")
        return None
    m = re.search(boundary, served, re.I)
    if m:
        return f"`{package}` appears as a distinct token in the served response"
    return None


def _advisory_is_request_path(cves, text):
    return bool(text) and bool(HTTP_LAYER_SIGNALS.search(text))


def _dependency_kind(lockdata, package):
    """Classify how the package is declared. A devDependency never ships to production,
    so a CVE in one is a build-time risk, not a runtime one — a distinction the raw
    version match completely ignores."""
    if not lockdata:
        return "unknown"
    pkgs = lockdata.get("packages") or {}
    root = "node_modules/" + package

    def _kind(v):
        if v.get("dev"):
            return "dev"
        if v.get("peer"):
            return "peer"
        if v.get("optional"):
            return "optional"
        return "production"

    # The ROOT install decides. A lockfile can contain the same package twice — hoisted at
    # the top level and again nested under another dependency — and those copies can differ
    # in kind. Scanning in dict order returned whichever came first, so a top-level
    # production lodash was classified "dev" when a nested devDependency copy happened to
    # be listed earlier. assess() then returned NOT_PRESENT and told the operator not to
    # report a runtime vulnerability that was in fact reachable. When a build-time and a
    # runtime copy coexist, the runtime one is the one that matters.
    if root in pkgs:
        return _kind(pkgs[root])
    for k, v in pkgs.items():
        if k.endswith("/" + root) or k.endswith(root):
            return _kind(v)
    deps = lockdata.get("dependencies") or {}
    if package in deps:
        return "production"
    if package in (lockdata.get("devDependencies") or {}):
        return "dev"
    return "unknown"


def assess(package, version, cves, http, timeout=15, lockdata=None, advisory_text=""):
    """http is a probes.Http instance for the live target (may be None).
    advisory_text is the concatenated advisory summary/details, used to judge whether the
    flaw sits on the request path."""
    evidence = []
    kind = _dependency_kind(lockdata, package)
    if kind == "dev":
        return {
            "package": package, "version": version, "cves": cves,
            "verdict": "NOT_PRESENT",
            "confidence": "high",
            "reasoning": f"{package} is declared as a devDependency. It is a build-time tool "
                         f"and does not ship to production, so it is not reachable by an "
                         f"attacker through the running application.",
            "evidence": ["declared dev:true in the lockfile"],
            "to_confirm": "Check the build pipeline — a dev dependency CAN matter if it "
                          "generates shipped artefacts (bundlers, template compilers) or if "
                          "the build environment itself is in scope.",
            "severity_guidance": "Build-time / supply-chain risk only. Do not report as a "
                                 "runtime vulnerability.",
        }
    if kind == "production":
        evidence.append("declared as a production dependency in the lockfile")

    if CLIENT_SIDE_HINTS.match(package):
        return {
            "package": package, "version": version, "cves": cves,
            "verdict": "NOT_PRESENT",
            "confidence": "medium",
            "reasoning": f"{package} is a browser-side dependency. A server-side CVE in it "
                         f"is not reachable through the application; it is a supply-chain "
                         f"risk to end users and should be scored as such.",
            "evidence": evidence,
            "to_confirm": "Check whether the package is also required in server code — a "
                          "package can appear in both bundles.",
            "severity_guidance": "Score as supply-chain/user-side risk, not as a server "
                                 "vulnerability. Do not report as Critical.",
        }

    if http is not None:
        # Look for the component's fingerprint in what the application actually serves.
        root = http.req("/")
        served = (root.get("body") or "") + json.dumps(root.get("headers") or {})
        why = _fingerprint(package, served)
        if why:
            evidence.append(f"{why} — observed in the response from {http.base}/")

        lock = http.req("/package-lock.json")
        if lock.get("code") == 200 and package in (lock.get("body") or ""):
            evidence.append("listed in the publicly served package-lock.json")

    # Package identity is the strong signal. Advisory wording is only consulted for
    # packages that are NOT themselves the HTTP layer, and only when it is unambiguous.
    if package.lower() in HTTP_LAYER_PACKAGES:
        evidence.append(f"{package} IS the HTTP request-handling layer, so the vulnerable "
                        f"code path is exercised by ordinary traffic")
    elif _advisory_is_request_path(cves, advisory_text):
        evidence.append("the advisory describes a flaw in HTTP request handling itself")
    if evidence and any("HTTP request-handling" in e or "request handling itself" in e
                        for e in evidence):
        return {
            "package": package, "version": version, "cves": cves,
            "verdict": "EXPOSED", "confidence": "high",
            "reasoning": "The vulnerable component is the HTTP request-handling layer "
                         "itself, and the application demonstrably serves HTTP. The "
                         "vulnerable code path is exercised by ordinary traffic.",
            "evidence": evidence,
            "to_confirm": "Confirm the specific advisory's preconditions (configuration, "
                          "TLS termination, proxy setup) before assigning severity.",
            "severity_guidance": "Reachability is established. Severity now depends on the "
                                 "advisory's impact and preconditions, not on reachability.",
        }

    if evidence:
        return {
            "package": package, "version": version, "cves": cves,
            "verdict": "LIKELY", "confidence": "medium",
            "reasoning": "The component is present in the served application's dependency "
                         "set, so it is server-side and loaded — but whether the vulnerable "
                         "function is called with attacker-controlled input cannot be "
                         "determined from outside.",
            "evidence": evidence,
            "to_confirm": "Source review or grey-box testing: find the call sites for the "
                          "advisory's vulnerable function and check whether user input "
                          "reaches them.",
            "severity_guidance": "Cap severity at what is defensible for an unverified call "
                                 "path, and say so in the report. Do not report as Critical "
                                 "on version match alone.",
        }

    return {
        "package": package, "version": version, "cves": cves,
        "verdict": "UNDETERMINED", "confidence": "low",
        "reasoning": "No evidence either way from outside the application. The component "
                     "may be a server dependency that is never called, a dev dependency "
                     "that never ships, or used in a code path no request reaches.",
        "evidence": evidence,
        "to_confirm": "Requires source access or a dependency-usage analysis. Check "
                      "devDependencies vs dependencies first — a dev-only package never "
                      "ships to production.",
        "severity_guidance": "Report as informational with the reachability question stated "
                             "explicitly. Never escalate on version match alone.",
    }


def assess_audit(audit_result, http=None, timeout=15, lockdata=None):
    """Assess every affected package from a cve.audit_lockfile() result."""
    out = []
    for a in audit_result.get("affected", []):
        out.append(assess(a["package"], a["version"], a.get("cves", []), http,
                          timeout, lockdata=lockdata,
                          advisory_text=a.get("advisory_text", "")))
    counts = {}
    for r in out:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    lines = [f"reachability assessment — {len(out)} affected packages"]
    for r in sorted(out, key=lambda x: {"EXPOSED": 0, "LIKELY": 1,
                                        "UNDETERMINED": 2, "NOT_PRESENT": 3}[x["verdict"]]):
        lines.append(f"  [{r['verdict']:12s}] {r['package']}@{r['version']} "
                     f"(confidence: {r['confidence']})")
        lines.append(f"                 {r['reasoning'][:100]}")
        lines.append(f"                 to confirm: {r['to_confirm'][:100]}")
    lines.append("")
    lines.append("  Reachability drives severity. A version match is a lead; a reachable")
    lines.append("  vulnerable call path is a finding. Do not conflate them.")
    return {"assessments": out, "counts": counts, "summary_lines": lines}
