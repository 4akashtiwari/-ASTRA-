"""Attack-chain synthesis.

The central claim: **severity is not a property of a finding, it is a property of what
the finding enables.** A scanner ranks a leaked .env as Informational and a JWT alg:none
bug as Medium, and reports them apart. Together they are account takeover.

Two design constraints, both learned by producing the wrong answer first.

1. NO TRANSITIVE CAPABILITY ALGEBRA. The first version propagated capabilities forward
   (`secret -> identity -> read -> secret`), which formed a cycle granting every
   capability to every finding and escalated 7 of 13 findings to Critical, including a
   reflected XSS. Capability algebra is generative: it manufactures chains that look
   rigorous. A link here exists only when one finding's demonstrated output satisfies
   another finding's stated assumption, and at most one hop.

2. NEVER INFER A SECRET FROM NARRATIVE PROSE. The second version keyword-matched the
   finding's own text, so an impact statement saying "may contain secrets" was read as
   secrets being leaked, and a traversal of a file named `secret.txt` was credited with
   credential disclosure. Only the probe that retrieved the body may declare what the
   body held.
"""

import re

# What a finding's OWN evidence demonstrates. No inference: if the class grants it, the
# probe proved it by construction.
GRANTS = {
    "exposure":        ["read"],
    "traversal":       ["read"],
    "idor":            ["read"],
    "sqli":            ["read"],
    "cmdi":            ["exec"],
    "ssti":            ["exec"],
    "xss":             ["session"],
    "stored-xss":      ["session"],
    "jwt-none":        ["identity"],
    "mass-assignment": ["identity"],
    "method-tamper":   ["identity"],
    "ssrf":            ["read"],
    "race":            ["logic"],
    # Business logic. Same shape as race: abuse of intended functionality rather than a
    # broken control. They were absent from this table entirely, so a confirmed
    # refund-abuse or negative-quantity finding could never take part in a chain at all.
    "negative-qty":    ["logic"],
    "price-tamper":    ["logic"],
    "refund-abuse":    ["logic"],
    "workflow-bypass": ["logic"],
    "constraint-logic": ["logic"],
    "response-credential-leak": ["identity"],
    # Replaying a one-time effect is abuse of intended functionality, the same shape as
    # race and the other business-logic classes: it grants `logic`.
    "double-spend":      ["logic"],
    "race-consume":      ["logic"],
    "csrf":            ["phish"],
    "redirect":        ["phish"],
    # A claimed subdomain lets the attacker serve content from inside the target's own
    # namespace. `phish` is unconditional. `session` is listed because cookies scoped to a
    # parent domain are sent to the claimed host and can be read back — that is the usual
    # reason a dangling CNAME is High rather than informational. It is NOT a grant of
    # `identity` on its own: harvesting credentials still needs a victim to submit them.
    "subdomain takeover": ["phish", "session"],
    # Reaching a route the access control was meant to block is identity in the only sense
    # that matters here: the request is served as though the check had passed. No further
    # precondition is assumed, so this belongs in GRANTS and not REQUIRES.
    "acl-bypass":      ["identity"],
    # Enumeration hands over a validated username list. That is not an identity on its own
    # — nobody is logged in — but it is the input that makes a password attack a one-unknown
    # problem, so it belongs in the ladder rather than being dropped.
    "user-enum":       ["read"],
    # A credentialed cross-origin read reaches whatever the victim's session can reach, so
    # it is a session capability — but only once a victim loads attacker content, which is
    # exactly why the probe rates the finding Medium rather than Critical.
    "cors":            ["session"],
    # Serving a privileged route to an unprivileged session is identity by definition:
    # the request was handled as though the caller held the role it does not.
    "privilege":       ["identity"],
    # Rewriting the role claim inside a session token is identity in the fullest sense:
    # the server now treats the request as coming from whoever the attacker named.
    "session-forge":   ["identity"],
    # An open proxy that spends a server-side credential hands the attacker both the
    # deputy's identity and whatever that credential reads. Over-scoped, it is full read
    # access to private source -- read and identity in one finding.
    "confused-deputy": ["read", "identity"],
    # History is part of the object store: a committed-then-removed credential is simply
    # recovered. That is a grant of `secret`, the same capability ONE_HOP escalates.
    "git-history-leak": ["secret"],
    "headers":         [],
}

# Findings that retrieve a file body and can therefore leak what it contains.
FILE_READERS = {"exposure", "traversal", "ssrf"}

# A single, non-transitive, well-grounded upgrade. Each is a step a tester confirms in
# minutes, not a chain of abstractions. At most one hop; the table cannot point back at
# itself, so no cycle is reachable.
ONE_HOP = {
    ("exposure", "secret"):  ("identity", "the leaked file contains credentials that "
                                          "authenticate to this application"),
    ("traversal", "secret"): ("identity", "the traversed file contains credentials"),
    ("cmdi", "exec"):        ("secret", "code execution on the host exposes its "
                                        "configuration and secrets"),
    ("ssti", "exec"):        ("secret", "template execution on the host exposes its "
                                        "configuration and secrets"),
    # A claimed subdomain is the one phish that does not look like phish: it is served from
    # inside the target's own namespace, over a certificate for the target's domain. The
    # harvested credentials are real and authenticate to this application, so this is a
    # genuine hop to identity and not an assumption about user gullibility.
    ("subdomain takeover", "phish"):
                             ("identity", "the claimed host is inside the target's own "
                                          "namespace and serves a convincing credential "
                                          "page under the target's domain"),
}

# What a finding's severity ASSUMES. Only assumptions the probe does not itself
# demonstrate belong here — an earlier version listed stored-xss as requiring a write
# capability, but the stored-XSS probe posts the content as part of its own test, so it
# demonstrates that precondition by construction and the de-escalation was simply wrong.
REQUIRES = {
    "idor":            ("identity", "reads another user's object, which assumes an "
                                    "attacker can hold two authenticated identities"),
    "race":            ("identity", "assumes an authenticated account able to redeem"),
    "mass-assignment": ("identity", "assumes an authenticated account able to self-promote"),
    # Verified, not assumed: all four return HTTP 401 with no session. Their severity is
    # a claim about what an authenticated attacker can do, so if that identity was never
    # demonstrated the escalation has to come back down. That is what REQUIRES is for.
    "negative-qty":    ("identity", "assumes an authenticated account able to add to a cart"),
    "price-tamper":    ("identity", "assumes an authenticated account able to check out"),
    "refund-abuse":    ("identity", "assumes an authenticated account able to request a refund"),
    "workflow-bypass": ("identity", "assumes an authenticated account able to reach the step"),
    # CSRF needs a victim, not just an attacker: the forged request only fires if someone
    # logged in visits a page the attacker controls. That is a real precondition and the
    # severity overstates the risk if nobody demonstrated it.
    "csrf":            ("identity", "assumes a logged-in victim who visits attacker-controlled content"),
    "privilege":       ("identity", "acts as two stored sessions and compares what each is "
                                    "served, so it assumes at least two test accounts"),
}

TERMINAL = {"exec": "remote code execution",
            "identity": "a usable identity, including administrative",
            "secret": "harvested credentials or signing keys"}

# The escalation ladder, ASCENDING. Two separate bugs lived here.
#
# 1. It said "Informational" while findings.SEVERITIES says "Info", so _bump("Info")
#    hit the ValueError branch and returned "Info" unchanged — an Info finding that
#    unlocked three others silently never escalated, with no error anywhere.
# 2. Importing findings.SEVERITIES directly to fix that INVERTED the ladder, because
#    that tuple is ordered for display (Critical first). _bump("High") then returned
#    "Medium", so every chain "escalation" in the tool was quietly a de-escalation.
#
# So: same vocabulary as findings, explicit ascending direction, and a test that pins
# the direction so neither bug can return.
from .findings import SEVERITIES as _SEV
SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]
assert set(SEVERITY_ORDER) == set(_SEV), (
    f"severity vocabulary drifted from findings.SEVERITIES: "
    f"{set(SEVERITY_ORDER) ^ set(_SEV)}")

# Fallback for findings recorded before probes carried `secrets_found`. Scans ONLY the
# evidence string, never `impact`/`summary`/`teaching`.
SECRET_ASSIGNMENT = re.compile(
    r"(?<![.\w])(?:api[_-]?key|apikey|secret[_-]?key|password|passwd|db[_-]?pass|"
    r"jwt[_-]?secret|signing[_-]?key|token)\W{0,3}[:=]\W{0,2}\S{8,}"
    r"|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I)

# Evidence that the probe itself authenticated. If present, the identity assumption is
# demonstrated by this finding and it must not be de-escalated for lacking it.
AUTH_MARKERS = ("cookie:", "sid=", "session", "bearer ", "authorization:", "logged in",
                "authenticated as", "token=")


def _bump(sev, levels=1):
    try:
        i = SEVERITY_ORDER.index(sev)
    except ValueError:
        return sev
    return SEVERITY_ORDER[max(0, min(i + levels, len(SEVERITY_ORDER) - 1))]


def _evidence(f):
    """The observed data. Secret detection may only ever look here."""
    return " ".join(str(f.get(k, "")) for k in ("evidence", "reproduction"))


def _shows_auth(f):
    low = _evidence(f).lower()
    return any(m in low for m in AUTH_MARKERS)


def demonstrated(f):
    """Capabilities this finding's own evidence proves."""
    cls = f.get("class", "")
    caps = set(GRANTS.get(cls, []))
    if not caps:
        return caps
    ev = _evidence(f)
    # The probe that held the body is the only authority on what the body contained.
    if f.get("secrets_found"):
        caps.add("secret")
    elif cls in FILE_READERS and SECRET_ASSIGNMENT.search(ev):
        caps.add("secret")
    if cls == "ssrf" and ("169.254.169.254" in ev or "metadata" in ev.lower()):
        caps.add("secret")
    # Consult ONE_HOP for every capability this finding actually grants, in a fixed
    # priority order. It used to build the key as (cls, "secret") or (cls, "exec") and
    # nothing else, so any table entry keyed on a different capability was unreachable —
    # it could be added, reviewed and tested for presence in the table, and still never
    # fire. That is the same failure as a config control nobody reads, one level down: a
    # table row no code path can select.
    for capability in ("secret", "exec", "phish", "session", "read", "logic", "identity"):
        key = (cls, capability)
        if capability in caps and key in ONE_HOP:
            caps.add(ONE_HOP[key][0])
    if cls in ("jwt-none", "mass-assignment") and ("/admin" in ev or "role" in ev.lower()):
        caps.add("admin")
    return caps


def analyse(findings):
    """Return (chains, de_escalations).

    chains — an entry finding and the specific further findings its demonstrated output
    unlocks. de_escalations — findings whose severity assumes a capability that nothing
    in this engagement demonstrated.
    """
    demo = [f for f in findings if f.get("status") == "confirmed" and f.get("evidence")]
    caps = {f["id"]: demonstrated(f) for f in demo}

    chains = []
    for f in demo:
        mine = caps[f["id"]]
        if not mine:
            continue
        unlocked = []
        for other in demo:
            if other["id"] == f["id"]:
                continue
            need = REQUIRES.get(other.get("class"))
            if not need:
                continue
            cap, why = need
            if cap in mine and cap not in caps[other["id"]] and not _shows_auth(other):
                unlocked.append({"id": other["id"], "title": other.get("title"),
                                 "granted": cap, "why": why})
        term = [TERMINAL[t] for t in sorted(mine & set(TERMINAL))]
        if not unlocked and not term:
            continue
        base = f.get("severity", "Medium")
        eff = _bump(base, 1) if unlocked else base
        chains.append({"entry": f["id"], "entry_title": f.get("title"),
                       "entry_severity": base, "chain_severity": eff,
                       "escalated": eff != base, "capabilities": sorted(mine),
                       "terminal": term, "unlocks": unlocked,
                       "fully_demonstrated": True})

    de = []
    for f in demo:
        need = REQUIRES.get(f.get("class"))
        if not need:
            continue
        cap, why = need
        if cap in caps[f["id"]] or _shows_auth(f):
            continue
        if any(cap in c for i, c in caps.items() if i != f["id"]):
            continue
        de.append({"id": f["id"], "title": f.get("title"),
                   "severity": f.get("severity"), "missing": cap, "assumption": why})

    chains.sort(key=lambda c: (SEVERITY_ORDER.index(c["chain_severity"])
                               if c["chain_severity"] in SEVERITY_ORDER else 0,
                               len(c["unlocks"])), reverse=True)
    return chains, de


def render(chains, de_escalations):
    if not chains and not de_escalations:
        return ("## Attack chains\n\n_No confirmed finding unlocks another, and no "
                "severity rests on an undemonstrated assumption._")
    L = ["## Attack chains", ""]
    if chains:
        L.append("Severity is a property of what a finding enables, not of the finding "
                 "itself. Every link below is a demonstrated finding, not an inference.")
        L.append("")
        for c in chains:
            L.append(f"### {c['entry']} — {c['entry_title']}")
            sev = f"- {c['entry_severity']}"
            if c["escalated"]:
                sev += (f" → **{c['chain_severity']}** — escalates because it unlocks "
                        f"{len(c['unlocks'])} further finding(s)")
            L.append(sev)
            L.append(f"- demonstrated: `{', '.join(c['capabilities'])}`")
            if c["terminal"]:
                L.append(f"- terminus: {'; '.join(c['terminal'])}")
            for u in c["unlocks"]:
                L.append(f"  - unlocks **{u['id']}** ({u['title']}) — grants "
                         f"`{u['granted']}`: {u['why']}")
            L.append("")
    if de_escalations:
        L.append("## Severities that assume more than was proven")
        L.append("")
        L.append("Not downgrades — the report naming which of its own numbers rest on an "
                 "assumption nobody tested. A Medium that cannot be reached overstates "
                 "risk exactly as much as a false positive does.")
        L.append("")
        for d in de_escalations:
            L.append(f"- **{d['id']}** {d['title']} ({d['severity']}) — requires "
                     f"`{d['missing']}`: {d['assumption']}")
        L.append("")
    return "\n".join(L)
