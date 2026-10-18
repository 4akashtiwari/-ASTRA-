"""
Probes — active tests, each returning a verdict with evidence.

Two rules that came from real failures in this project:

1. A boolean differential needs THREE distinguishable states (baseline, true, false).
   If true == false, the payload is a syntax error, not proof of safety. This produced
   a false negative during the dry run.

2. A shell metacharacter being accepted is not a vulnerability. `;` worked on the
   benchmark target and `&&` did not — because ping fails without raw sockets, so the
   chained command never fired. Report only what you demonstrate.
"""
import base64, hashlib, json, math, re, threading, time, urllib.error, urllib.parse, urllib.request
import http.cookiejar

CANARY_N = [0]


def _mask_secret(s):
    """A credential is evidence by its SHAPE, never by its value.

    Session cookies and forged tokens end up in a verdict's `extra`, which `--json`
    serialises and a report may embed. Printing the raw value hands a live credential to
    whoever reads the output — the exact thing the tool's own rules forbid. Show the length
    and a short digest instead: enough to tell two tokens apart and to match one across
    runs, with nothing reusable leaked.
    """
    if not isinstance(s, str) or not s:
        return s
    return f"<masked {len(s)}b sha256:{hashlib.sha256(s.encode()).hexdigest()[:12]}>"


def canary(tag):
    CANARY_N[0] += 1
    return f"ptx{tag}{CANARY_N[0]}x9q"


class Http:
    """Minimal client. Every call has a timeout; nothing blocks on stdin."""

    def __init__(self, base, rps=None, timeout=15):
        self.base = base.rstrip("/")
        self.timeout = timeout
        if rps is not None:
            try:
                rps = float(rps)
            except (TypeError, ValueError) as e:
                raise ValueError("rps must be a non-negative finite number") from e
            if not math.isfinite(rps) or rps < 0:
                raise ValueError("rps must be a non-negative finite number")
        self.min_interval = (1.0 / rps) if rps else 0
        self._last = 0.0
        self.jar = http.cookiejar.CookieJar()
        self._throttle_lock = threading.Lock()
        # Requests that never completed. A probe that concludes "not vulnerable" after its
        # request failed has not measured anything, and if that happens across an
        # engagement the coverage report reads "everything tested, all clean" for a target
        # that was never reached.
        self.transport_failures = 0

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            """Return 3xx with its headers instead of following it.

            Following a redirect destroys the evidence an open-redirect probe needs:
            the Location header is the finding, and chasing it to a host that does not
            resolve loses the response entirely.
            """
            def redirect_request(self, *a, **k):
                return None

        self.opener = urllib.request.build_opener(
            NoRedirect, urllib.request.HTTPCookieProcessor(self.jar))
        self._NoRedirect = NoRedirect
        # Built on demand. A request that must go out with no cookies at all cannot use
        # the shared opener: the jar is cumulative, so by the time a session probe runs
        # the client usually already holds the very session it is trying to observe being
        # issued -- and the server, seeing a valid session, sets no new one.
        self._bare_opener = None
        self.request_count = 0

    def _throttle(self):
        """Space requests to the configured ceiling. Thread-safe.

        Without the lock this was not a rate limit under concurrency: ten threads all read
        the same `self._last`, all computed the same wait, all slept the same interval and
        then all fired together. Measured against a 5 req/s ceiling, ten parallel requests
        went out in 203 ms — 48 req/s, roughly ten times the limit the operator had set.

        The lock makes the ceiling real. `probe_race` opts out deliberately, because a
        race-condition test is *defined* by concurrent requests; spacing them would close
        the window it is trying to hit and the probe would report no race on a racy target.
        That opt-out is a bounded burst on one probe, not a client-wide exemption.
        """
        if not self.min_interval:
            return
        with self._throttle_lock:
            wait = self.min_interval - (time.time() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()

    def req(self, path, method="GET", data=None, headers=None, raw=None, ctype=None,
            throttle=True, no_cookies=False):
        if throttle:
            self._throttle()
        hdrs = {"User-Agent": "ptx-probe/1.0 (authorized assessment)"}
        if headers:
            hdrs.update(headers)
        body = None
        if raw is not None:
            body = raw.encode()
            if ctype:
                hdrs["Content-Type"] = ctype
        elif data is not None:
            body = json.dumps(data).encode()
            hdrs.setdefault("Content-Type", "application/json")
        r = urllib.request.Request(self.base + path, data=body, headers=hdrs, method=method)
        self.request_count += 1
        opener = self.opener
        if no_cookies:
            if self._bare_opener is None:
                self._bare_opener = urllib.request.build_opener(self._NoRedirect)
            opener = self._bare_opener
        try:
            with opener.open(r, timeout=self.timeout) as resp:
                return {"code": resp.status, "body": resp.read().decode("utf-8", "replace"),
                        "headers": dict(resp.headers), "error": None}
        except urllib.error.HTTPError as e:
            return {"code": e.code, "body": e.read().decode("utf-8", "replace"),
                    "headers": dict(e.headers), "error": None}
        except Exception as e:
            self.transport_failures += 1
            return {"code": 0, "body": "", "headers": {}, "error": str(e)}


# A secret is only claimed on a concrete assignment of a plausible value. Narrative
# prose ("this file may contain secrets") must never count, or every finding that
# discusses credentials is credited with leaking them.
# A secret is claimed only on a concrete assignment of a plausible value. Narrative prose
# ("this file may contain secrets") must never count, or every finding that discusses
# credentials is credited with leaking them.
#
# Two independent signals, because either alone misses real cases. NAME-based matching
# catches anything assigned to a secret-shaped variable; VALUE-based matching catches
# provider tokens whose variable name gives nothing away. Both require enough entropy to
# be a value rather than a placeholder word.
SECRET_NAME = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Za-z0-9]+_)*(?:SECRET|SECRETS|KEY|KEYS|TOKEN|TOKENS|PASS|"
    r"PASSWORD|PASSWD|PWD|CREDENTIAL|CREDENTIALS|APIKEY|PRIVATE_KEY)(?:_[A-Za-z0-9]+)*"
    r"\s*[:=]\s*[\"']?([^\s\"';,]{8,})", re.I)

# Provider tokens and structured credentials, recognised by shape.
SECRET_VALUES = [
    (r"\b(AKIA[0-9A-Z]{16})\b", "AWS access key ID"),
    (r"\b(sk_live_[A-Za-z0-9]{8,})\b", "Stripe LIVE secret key"),
    (r"\b(sk_test_[A-Za-z0-9]{8,})\b", "Stripe test secret key"),
    (r"\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b", "GitHub token"),
    (r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b", "Slack token"),
    (r"\b(AIza[0-9A-Za-z_\-]{20,})\b", "Google API key"),
    (r"\b(ya29\.[A-Za-z0-9_\-]{20,})\b", "Google OAuth token"),
    (r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)", "private key"),
    (r"\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]*)\b",
     "JSON web token"),
    (r"\b([a-z][a-z0-9+.-]{1,15}://[^:/\s@]{1,64}:[^@\s/]{4,}@[\w.\-]{3,})\b",
     "connection string with embedded credentials"),
]

# Assignments that look secret-shaped but are not credentials. Kept explicit rather than
# guessed: a false "credentials found" claim is as damaging as a missed one.
NOT_A_SECRET_VALUE = re.compile(
    r"^(?:changeme|example|placeholder|your[_-]?\w+|xxx+|none|null|true|false|todo|"
    r"redacted|dummy|sample|test|localhost|[\w.\-]+\.(?:com|net|org|io|test|internal|"
    r"local|example)|\d+)$", re.I)


def detect_secrets(body):
    """Return the kinds of credential material actually present in a retrieved body.

    Computed by the probe, which is the only component holding the body. Returns [] when
    the body holds nothing concrete — a filename containing the word "secret" does not
    qualify, and neither does the report's own description of the file.
    """
    found = []
    body = body or ""
    # Line-scoped so a specific provider match suppresses the generic label for the same
    # assignment. Running both detectors over the whole body reported AWS twice.
    for line in body.splitlines():
        specific = [label for pat, label in SECRET_VALUES if re.search(pat, line)]
        if specific:
            for lab in specific:
                if lab not in found:
                    found.append(lab)
            continue
        found += _name_based(line, found)
    return found


def _name_based(line, already):
    out = []
    for m in SECRET_NAME.finditer(line):
        name, value = m.group(0).split(":")[0].split("=")[0].strip(), m.group(1)
        if NOT_A_SECRET_VALUE.match(value):
            continue
        # A URL host or a bare path is configuration, not a credential.
        if re.match(r"^[\w.\-]+\.[a-z]{2,}$", value, re.I) and "/" not in value:
            if not re.search(r"(SECRET|PASS|PWD|TOKEN|KEY)", name, re.I) or                re.search(r"(HOST|URL|DOMAIN|ENDPOINT|NAME)$", name, re.I):
                continue
        kind = "credential"
        n = name.upper()
        if re.search(r"(AWS|S3)", n): kind = "AWS credential"
        elif re.search(r"(STRIPE)", n): kind = "Stripe key"
        elif re.search(r"(DB|DATABASE|POSTGRES|MYSQL|MONGO|SQL)", n): kind = "database credential"
        elif re.search(r"(JWT|SIGNING)", n): kind = "JWT signing key"
        elif re.search(r"(TOKEN)", n): kind = "bearer token"
        elif re.search(r"(PRIVATE)", n): kind = "private key"
        elif re.search(r"(API|SECRET|KEY)", n): kind = "API key / secret"
        if kind not in already and kind not in out:
            out.append(kind)
    return out

def _unreachable(*responses):
    """True if any of these responses never happened.

    `Http.req` returns code 0 with an empty body and no headers when the connection fails.
    That is not a response with no security headers — it is no response at all, and the
    difference matters: `probe_headers` read the empty header set as "every header is
    missing" and reported a vulnerability against a host that was not even listening. It
    is the most-run probe in the tool, it runs on every engagement, and a false positive
    here is the single most expensive thing this tool can emit.
    """
    return any((r or {}).get("code") == 0 for r in responses)


def _verdict(vid, name, vulnerable, evidence, mechanism="", teaching="", severity=None, extra=None):
    out = {"id": vid, "name": name, "vulnerable": vulnerable, "evidence": evidence,
            "mechanism": mechanism, "teaching": teaching, "severity": severity,
            "tested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    out.update(extra or {})
    return out


def mark_unmeasured(verdict, client, failures_before):
    """Downgrade a clean verdict to inconclusive if the probe's requests never completed.

    Applied centrally in the CLI rather than inside each probe, so a probe added later
    inherits it. Without this, pointing the tool at the wrong port produced a full set of
    conclusive negatives and a coverage report that read "every class tested, all clean" —
    for a target that was never reached. A false negative across a whole engagement is
    worse than a crash, because it is silent.
    """
    if verdict.get("vulnerable") or verdict.get("inconclusive"):
        return verdict
    if getattr(client, "transport_failures", 0) > failures_before:
        verdict["inconclusive"] = True
        verdict["inconclusive_reason"] = (
            "one or more requests did not complete, so the absence of a finding is not "
            "evidence that the control works")
    return verdict


# --- probes ------------------------------------------------------------------
# --- IDOR: discover the ownership marker instead of guessing one field name -----
#
# The old probe decided the verdict with `ok and owner is not None`, where `owner`
# came from one hardcoded field name ("user_id"). An object that carried `author_id`,
# `owner`, `uid` or `created_by` instead was reported CLEAN -- a false negative
# produced entirely by a guess. Same fault as the mass-assignment probe: the answer
# was embedded in the question.
#
# The marker is now found by diffing our own object against someone else's. A field
# whose value differs between the two and whose name looks like an identity is the
# ownership marker. Nothing is required to be called user_id.
_IDENTITY_HINTS = ("user_id", "userid", "user", "username", "owner_id", "ownerid",
                   "owner", "author_id", "authorid", "author", "uid", "created_by",
                   "createdby", "account_id", "accountid", "account", "customer_id",
                   "customerid", "email", "member_id", "tenant_id", "org_id")


def _flat_scalars(obj, prefix=""):
    """Flatten JSON to {dotted.path: scalar} so a nested ownership marker still counts."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}{k}"
            if isinstance(v, (dict, list)):
                out.update(_flat_scalars(v, key + "."))
            elif v is not None:
                out[key] = v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.update(_flat_scalars(v, f"{prefix}{i}."))
    return out


def _ownership_markers(own, other, hint=None):
    """Diff two records and return the fields that look like they name the owner.

    Returns [(path, our_value, their_value)]. The hint is only a tie-breaker for
    ordering -- an absent hint no longer means "no ownership, therefore clean".
    """
    a, b = _flat_scalars(own), _flat_scalars(other)
    found = []
    for path in sorted(set(a) & set(b)):
        if a[path] == b[path]:
            continue
        leaf = path.rsplit(".", 1)[-1].lower()
        if leaf in _IDENTITY_HINTS or leaf.endswith("_id") or leaf.endswith("_by"):
            found.append((path, a[path], b[path]))
    if hint:
        found.sort(key=lambda m: 0 if m[0].rsplit(".", 1)[-1] == hint else 1)
    return found


def probe_idor(h, endpoint, own_id, other_id, cookie=None, owner_field="user_id"):
    """Read an object owned by someone else. Needs two identities to mean anything.

    Three requests, because two cannot tell an IDOR from an object that is simply
    public. `own` establishes that our session can read its own record. `other` is the
    test. `other` again *without* the cookie is the control: if an anonymous caller can
    read it too, the object was never access-controlled and calling that an IDOR is a
    false positive.

    The verdict never rests on a guessed field name.
    """
    hdr = {"Cookie": cookie} if cookie else {}
    a = h.req(f"{endpoint}/{own_id}", headers=hdr)
    b = h.req(f"{endpoint}/{other_id}", headers=hdr)
    c = h.req(f"{endpoint}/{other_id}")          # control: no cookie at all

    def _inconclusive(reason):
        return _verdict(
            "idor", f"IDOR on {endpoint}/<id>", False,
            f"own object {own_id} -> HTTP {a['code']}; other user's object {other_id} "
            f"-> HTTP {b['code']}; anonymous control -> HTTP {c['code']}. {reason}",
            "The request could not be completed or interpreted, so no measurement was made.",
            "An unreadable or unreachable response is not a clean result. Re-run with the "
            "object IDs the engagement actually supplies.",
            None, extra={"inconclusive": True, "inconclusive_reason": reason})

    failed = a.get("error") or b.get("error") or c.get("error")
    if failed:
        return _inconclusive("a request did not complete: %s" % failed)
    if b["code"] != 200:
        return _verdict(
            "idor", f"IDOR on {endpoint}/<id>", False,
            f"own object {own_id} -> HTTP {a['code']}; other user's object {other_id} "
            f"-> HTTP {b['code']} (refused)",
            "The handler does not return another principal's object.",
            "Keep the ownership predicate in the query and return 404 rather than 403 on "
            "mismatch, so object existence is not leaked either.",
            None)
    if a["code"] != 200:
        return _inconclusive(f"our own object {own_id} came back HTTP {a['code']}, so the "
                             "baseline for comparison could not be established")

    # A 200 whose body we cannot read is unmeasured, not clean. Checked before any
    # comparison, because an unparseable body makes every later conclusion unsafe.
    own = other = None
    try:
        own, other = json.loads(a["body"]), json.loads(b["body"])
    except Exception:
        return _inconclusive("the other user's object came back HTTP 200 but the body was "
                             "not parseable, so its contents could not be compared")
    if not isinstance(own, (dict, list)) or not isinstance(other, (dict, list)):
        return _inconclusive("both responses parsed but neither was a JSON object, so "
                             "ownership could not be compared")

    if a["body"] == b["body"]:
        return _verdict(
            "idor", f"IDOR on {endpoint}/<id>", False,
            f"object {own_id} and object {other_id} returned byte-identical bodies, so "
            "the endpoint does not vary by ID",
            "The handler is not ID-scoped, so there is no other principal's object here.",
            "Not a finding. If the endpoint is meant to be ID-scoped, the identical "
            "response suggests it ignores the path parameter entirely -- worth reading "
            "the handler, but not an authorisation flaw.",
            None)

    markers = _ownership_markers(own, other, owner_field)

    # The anonymous control is the PRIMARY oracle, and the ownership marker only
    # corroborates it. An earlier draft treated "no field looks like an owner" as the
    # thing that decided a public object was public -- and then flagged one, because a
    # `category_id` that differs between two records satisfies any `*_id` heuristic.
    # A field name is a guess about the data model. Whether an unauthenticated caller
    # can read the object is not a guess at all.
    if c["code"] == 200 and c["body"] == b["body"]:
        return _verdict(
            "idor", f"IDOR on {endpoint}/<id>", False,
            f"object {other_id} is readable with no session at all (HTTP {c['code']}) and "
            "the anonymous body is byte-identical to the authenticated one, so it is a "
            "public object. No authorisation boundary was crossed.",
            "The object is public. Authentication is not the gate on it, so reading "
            "another user's ID is not an authorisation failure.",
            "Not a finding. If this object is supposed to be private, the missing control "
            "is on the endpoint as a whole rather than on cross-user access -- report it "
            "as missing authentication, not as an IDOR.",
            None)

    if not markers:
        return _inconclusive(
            f"object {other_id} was returned (HTTP {b['code']}) and differs from ours, but "
            "no field in either response names an owner, so it could not be established "
            "that it belongs to another principal. This is unmeasured, not clean -- read "
            "the handler or supply an object known to belong to a second account.")

    first = markers[0]
    anonymous_note = (
        " The object is also readable anonymously but the anonymous body DIFFERS, so the "
        "authenticated response exposes more than the public one."
        if c["code"] == 200 else "")
    return _verdict(
        "idor", f"IDOR on {endpoint}/<id>", True,
        f"own object {own_id} -> HTTP {a['code']}; other user's object {other_id} -> "
        f"HTTP {b['code']} with {first[0]}={first[2]} (ours: {first[1]}); anonymous "
        f"control -> HTTP {c['code']}. Ownership markers discovered by diffing the two "
        f"records, not assumed: {[m[0] for m in markers]}.{anonymous_note}",
        "The server resolves the object by ID and returns it without comparing the "
        "object's owner to the authenticated principal.",
        "Grep for handlers that take an ID from the path and query by it alone. The fix "
        "is an ownership predicate in the query itself, so a cross-user read is impossible "
        "by construction rather than prevented by a check. Return 404, not 403, on mismatch "
        "so existence isn't leaked.",
        "High", extra={"ownership_markers": [m[0] for m in markers]})


def probe_sqli(h, path, param, ctx="like"):
    """SQL injection, established by evidence rather than assumption.

    Three complementary signals, in order of strength:
      1. BOOLEAN DIFFERENTIAL — baseline, true-branch and false-branch counts must be
         three distinguishable states. Two payload variants per context, because the
         injectable string may sit inside LIKE '%...%' (trailing suffix present) or a
         plain quoted value (absent). Guessing wrong yields a syntax error, and a syntax
         error on both branches looks exactly like "not injectable".
      2. ERROR-BASED — an unbalanced quote makes a concatenated query fail. If a bare
         quote produces a server error or leaks SQL, the input is being concatenated.
      3. If neither fires, and the endpoint responds normally to a malformed quote, the
         query is parameterized and this is a CONCLUSIVE negative — not a shrug.

    A negative here is only reported when it is actually established.
    """
    def count(payload):
        r = h.req(f"{path}?{urllib.parse.urlencode({param: payload})}")
        try:
            return json.loads(r["body"]).get("count"), r
        except Exception:
            return None, r

    prefix = {"like": "%", "quote": "x", "num": "1"}[ctx]
    if ctx == "num":
        variants = [("1", "1 AND 1=1-- ", "1 AND 1=2-- ")]
    else:
        q = prefix + "'"
        variants = [(prefix, q + " AND '1'='1'-- ", q + " AND '1'='2'-- "),
                    (prefix, q + " AND '1'='1",     q + " AND '1'='2")]

    attempts, b, t, f, distinguished = [], None, None, None, False
    for bp, tp, fp in variants:
        b, _ = count(bp)
        t, _ = count(tp)
        f, _ = count(fp)
        attempts.append({"baseline": b, "true": t, "false": f})
        if None not in (b, t, f) and t != f:
            distinguished = True
            break

    teach = ("Parameterize; don't filter. Filtering is a denylist and denylists lose. An ORM "
             "is not a fix either if the code drops into raw query mode — which is exactly "
             "where these appear.")

    if distinguished:
        # The two payloads differ ONLY in tautology versus contradiction. If the result
        # set changed between them, the database evaluated the injected predicate, and
        # that is conclusive — no further condition is needed.
        #
        # The previous rule additionally required `t == b` (true-branch equals baseline),
        # on the assumption that a tautology returns what the unmodified query returned.
        # That holds when the baseline term matches something. It fails when the baseline
        # matches nothing: found by randomised differential testing against a generated
        # target where baseline=0, true-branch=5 (the entire table), false-branch=0 — a
        # textbook injection the probe reported as not vulnerable.
        vuln = (t != f)
        return _verdict(
            "sqli", f"SQL injection on {path}?{param}", vuln,
            f"boolean differential: baseline={b}, true-branch={t}, false-branch={f} "
            f"(distinguished on variant {len(attempts)}/{len(variants)}). The two payloads "
            f"differ only in tautology vs contradiction, so a changed result set means the "
            f"database evaluated the injected predicate."
            + ("" if b == t else
               f" Note the tautology returned a DIFFERENT set than the baseline "
               f"({b} -> {t}), which is the injected predicate overriding the query's own "
               f"filter rather than merely matching it."),
            "User input is concatenated into the SQL statement rather than bound as a "
            "parameter, so the query's structure can be changed by the caller.",
            teach, "Critical" if vuln else None)

    # No differential. Before concluding anything, check whether a malformed quote breaks
    # the query — that distinguishes "parameterized" from "payload never parsed".
    broken, r_err = count(prefix + "'")
    benign, r_ok = count(prefix)
    error_signalled = (
        r_err["code"] >= 500
        or re.search(r"(sqlite3|mysql|psycopg2|pg_query|ORA-\d{5}|SQLSTATE|syntax error|"
                     r"unclosed quotation|OperationalError|ProgrammingError)", r_err["body"], re.I)
        is not None)

    if error_signalled:
        return _verdict(
            "sqli", f"SQL injection on {path}?{param}", True,
            f"error-based: unbalanced quote produced HTTP {r_err['code']} and a database "
            f"error, while the benign input returned HTTP {r_ok['code']}. Attempts: "
            f"{json.dumps(attempts)}",
            "User input is concatenated into the query, so a malformed quote breaks the "
            "statement and the database error surfaces.",
            teach, "High")

    if broken is not None and broken == 0 and benign is not None:
        return _verdict(
            "sqli", f"SQL injection on {path}?{param}", False,
            f"CONCLUSIVE NEGATIVE — a malformed quote did not error (HTTP {r_err['code']}) "
            f"and no payload variant changed the result set ({len(variants)} variants "
            f"tried). The parameter is bound, not concatenated.",
            "", "No action. Recorded as tested-negative, which is a claim about what was "
            "tested, not a claim that the code is safe in every context.",
            None)

    return _verdict(
        "sqli", f"SQL injection on {path}?{param}", False,
        f"INCONCLUSIVE — no payload variant produced a distinguishable result and the "
        f"malformed-quote probe was uninterpretable (HTTP {r_err['code']}). Attempts: "
        f"{json.dumps(attempts)}. Try a different injection context before concluding.",
        "", "A negative here is NOT evidence of safety. Check whether the injection point "
        "sits inside LIKE '%...%', a quoted string, or a numeric context, and account for "
        "whatever the application appends after your input.",
        None)


def probe_xss(h, path, param, stored=None):
    c = canary("xss")
    payload = f"<svg onload=alert('{c}')>"
    r = h.req(f"{path}?{urllib.parse.urlencode({param: payload})}")
    echoed = c in r["body"] and "<svg onload=" in r["body"]
    # Reflected markup is only script if the browser parses it as markup. An application
    # that reflects into application/json is not vulnerable to XSS: the payload arrives as
    # data. Found by randomised differential testing against a generated target that used
    # a JSON encoder — the benchmark's JSON "trap" never actually reflected the payload,
    # so this case had never been exercised.
    ctype = (r["headers"].get("Content-Type") or "").lower()
    non_html = bool(ctype) and not any(t in ctype for t in ("text/html", "text/plain",
                                                            "application/xhtml", "text/xml"))
    reflected = echoed and not non_html
    if echoed and non_html:
        return _verdict(
            "xss", f"Reflected XSS on {path}?{param}", False,
            f"payload reflected verbatim but the response Content-Type is {ctype!r}, so a "
            f"browser parses it as data rather than markup. CONCLUSIVE NEGATIVE for this "
            f"endpoint — not a shrug: the sink was reached and the output boundary is "
            f"correct for this content type.",
            "", "No action for this endpoint. Worth checking whether the same parameter is "
                "reflected by any other route that does serve HTML, and whether a "
                "nosniff-absent text/plain response could be sniffed as HTML in old "
                "browsers.",
            None)
    if reflected:
        return _verdict(
            "xss", f"Reflected XSS on {path}?{param}", True,
            f"canary {c} reflected unescaped in an HTML response "
            f"(Content-Type: {ctype or 'not set'})",
            "User input is written into an HTML response without encoding, so the browser "
            "parses attacker markup as markup.",
            "Encode at the output boundary, not by filtering input. Context matters: HTML "
            "body, attribute, JavaScript, and URL contexts each need different encoding. "
            "A Content-Security-Policy is defence in depth, not a fix.",
            "Medium")
    return _verdict("xss", f"Reflected XSS on {path}?{param}", False,
                    f"canary not reflected unescaped (HTTP {r['code']})", "", "", None)


def probe_stored_xss(h, post_path, get_path, field, cookie=None):
    c = canary("sxss")
    payload = f"<img src=x onerror=alert('{c}')>"
    hdr = {"Cookie": cookie} if cookie else {}
    h.req(post_path, "POST", {field: payload}, headers=hdr)
    r = h.req(get_path, headers=hdr)
    vuln = c in r["body"] and "<img src=x onerror=" in r["body"]
    return _verdict(
        "stored-xss", f"Stored XSS on {post_path}", vuln,
        f"payload persisted and rendered unescaped on {get_path}: {vuln}",
        "Untrusted input is stored and later rendered into HTML without encoding, so it "
        "executes in every viewer's browser.",
        "Encode on output. Stored XSS is worse than reflected because it needs no "
        "interaction and hits every viewer — treat any user-generated content rendered as "
        "HTML as hostile by default.",
        "High" if vuln else None)


def probe_cmdi(h, path, param):
    """Demonstrate output, or don't report it. A metacharacter is not a vulnerability."""
    c = canary("cmdi")
    r = h.req(f"{path}?{urllib.parse.urlencode({param: f'127.0.0.1; echo {c}; id'})}")
    echoed = c in r["body"]
    uid = re.search(r"uid=\d+\([^)]*\)", r["body"])
    vuln = echoed and bool(uid)
    return _verdict(
        "cmdi", f"OS command injection on {path}?{param}", vuln,
        f"canary echoed={echoed}, identity={uid.group(0) if uid else 'not returned'}",
        "User input reaches a shell invocation, so the OS interprets attacker-supplied "
        "command separators.",
        "Never build a shell string from user input. Use an argument-vector exec with no "
        "shell, and validate against an allowlist of expected values. Note that `&&` may "
        "fail where `;` succeeds simply because the first command exits non-zero — absence "
        "of output is not absence of the flaw.",
        "Critical" if vuln else None)


def probe_ssrf(h, path, param, canary_url):
    """Point the target at a URL we control and look for our token in the response."""
    # Without a canary URL the probe built "None?name=<token>", asked the target to fetch
    # that, and reported "not vulnerable" when the token naturally did not come back. It
    # tested nothing and recorded a clean result — the same silence-as-clean failure that
    # has now been found in this codebase six times.
    if not canary_url:
        return _verdict(
            "ssrf", f"SSRF on {path}?{param}", False,
            "no --canary-url supplied, so there was no attacker-controlled endpoint to "
            "point the target at",
            "", "", None,
            extra={"inconclusive": True,
                   "inconclusive_reason":
                       "no --canary-url supplied. Start a listener you control and pass "
                       "its URL; SSRF is only demonstrable if the target fetches "
                       "something you can observe."})
    c = canary("ssrf")
    target = f"{canary_url}?{urllib.parse.urlencode({'name': c})}"
    r = h.req(f"{path}?{urllib.parse.urlencode({param: target})}")
    vuln = c in r["body"]
    return _verdict(
        "ssrf", f"SSRF on {path}?{param}", vuln,
        f"server fetched our canary URL and returned the token {c}: {vuln}",
        "The server performs an outbound request to a caller-supplied URL with no allowlist, "
        "so it can be aimed at internal services and cloud metadata endpoints.",
        "Allowlist by resolved IP, not hostname — DNS rebinding defeats hostname checks. "
        "Block RFC1918, link-local (169.254.169.254), and localhost. Deny non-HTTP schemes: "
        "file:// and gopher:// turn SSRF into local file read.",
        "High" if vuln else None)


def probe_traversal(h, path, param, payload, marker):
    # `marker` is how the probe decides, and the CLI leaves it None by default. The
    # previous line was `marker in r["body"]`, which raised
    # "TypeError: 'in <string>' requires string as left operand, not NoneType" on the
    # probe's own default invocation — a traceback instead of a verdict. A probe that
    # cannot decide must say so, not crash and not report clean.
    if not marker:
        return _verdict(
            "traversal", f"Path traversal on {path}?{param}", False,
            f"payload {payload!r} was sent but no --marker was supplied, so there is "
            "nothing to look for in the response",
            "", "", None,
            extra={"inconclusive": True,
                   "inconclusive_reason":
                       "no --marker supplied. Pass the exact string that appears in the "
                       "file the payload should read (for example --marker "
                       "PTX_TRAVERSAL_GOAL) — without it this probe cannot distinguish a "
                       "successful read from an ordinary response."})
    r = h.req(f"{path}?{urllib.parse.urlencode({param: payload})}")
    vuln = marker in r["body"]
    got = detect_secrets(r["body"]) if vuln else []
    return _verdict(
        "traversal", f"Path traversal on {path}?{param}", vuln,
        f"payload {payload!r} read outside the intended root: {vuln}"
        + (f"; the file read contains {', '.join(got)}" if got else ""),
        "A user-supplied filename is joined to a base directory without canonicalisation, so "
        "`../` escapes the intended root.",
        "Canonicalise with realpath and verify the result still starts with the intended "
        "base directory. Better: map user input to an allowlisted identifier and never let "
        "it name a path at all.",
        "High" if vuln else None,
        extra={"secrets_found": got})


def probe_jwt_none(h, path, claims=None):
    """Craft an unsigned token and see whether the signature is checked at all."""
    claims = claims or {"uid": 999, "role": "admin"}
    hdr = base64.urlsafe_b64encode(b'{"typ":"JWT","alg":"none"}').decode().rstrip("=")
    pl = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    tok = f"{hdr}.{pl}."
    r = h.req(path, headers={"Authorization": f"Bearer {tok}"})
    vuln = r["code"] == 200
    return _verdict(
        "jwt-none", f"JWT signature not verified on {path}", vuln,
        f"alg:none token with claims {claims} -> HTTP {r['code']}",
        "The token's algorithm is taken from the token itself, so an attacker can declare "
        "`none` and skip signing entirely.",
        "Pin the expected algorithm server-side and reject anything else — never read `alg` "
        "from the token. This is why library maintainers recommend explicit algorithm "
        "allowlists.",
        "High" if vuln else None)


def probe_redirect(h, path, param):
    r = h.req(f"{path}?{urllib.parse.urlencode({param: 'https://attacker.example/'})}")
    loc = r["headers"].get("Location", "")
    vuln = r["code"] in (301, 302, 303, 307, 308) and "attacker.example" in loc
    return _verdict(
        "redirect", f"Open redirect on {path}?{param}", vuln, f"Location: {loc or 'none'}",
        "A caller-supplied URL is used as a redirect target without validation.",
        "Allowlist destinations, or use indirect references (a key that maps to a URL "
        "server-side). Open redirects are the payload-delivery half of phishing and OAuth "
        "token theft.",
        "Medium" if vuln else None)


def probe_mass_assignment(h, path, cookie, verify_fn, fields=None):
    """Send privileged fields and check whether they actually took effect."""
    fields = fields or {"is_admin": 1, "credits": 99999}
    hdr = {"Cookie": cookie} if cookie else {}
    # The response is deliberately discarded. A handler that accepts a mass assignment
    # usually answers 200 whether or not the privileged fields were bound, so the status
    # code carries no signal here. The only evidence that counts is the effect, observed
    # separately by verify_fn. Do not "use" r — that would reintroduce a false positive.
    h.req(path, "POST", fields, headers=hdr)
    changed = verify_fn(h, hdr)
    return _verdict(
        "mass-assignment", f"Mass assignment on {path}", changed,
        f"POST sent with {list(fields)}; privileged fields ACTUALLY CHANGED: {changed} "
        f"(the response claiming success is not evidence — the effect is)",
        "The handler binds every key present in the request body onto the record instead of "
        "an explicit allowlist.",
        "Bind an explicit allowlist of assignable fields — never the whole body. DTOs or "
        "serializer field lists make the boundary structural. Denylist approaches fail "
        "because someone always forgets the new privileged column.",
        "High" if changed else None)


# --- mass assignment: discover the privileged fields instead of guessing them --
#
# The original probe_mass_assignment hardcoded the names "is_admin" and "credits"
# into both the request and the verification, so it could only ever find a bug
# that happened to use those exact keys. On a live target the privileged field was
# called "approved" -- and the server was returning it in every single response,
# including the response to the baseline POST. Guessing names is strictly worse
# than reading them.
#
# A field is worth trying to set when the server itself assigns it a restrictive
# default at creation time. False, 0, "pending", "draft" are gates: the server is
# telling us what it intends to control, and what an attacker wants to flip.
_GATE_DEFAULTS = {False, 0, "false", "no", "off", "pending", "draft", "unapproved",
                  "unverified", "unpublished", "inactive", "queued", "held", ""}

# A guard that tests a field's *value* rather than its *presence* only blocks the
# exact spelling it was written against. Every representation below means the same
# thing to a Python truthiness check, a string comparison, or a SQLite column.
_TRUTH_VARIANTS = (True, 1, "true", "yes", "1", "on")


def json_records(body):
    """Pull record dicts out of a JSON response, whatever wrapper shape it uses."""
    try:
        d = json.loads(body)
    except Exception:
        return []
    if isinstance(d, list):
        return [x for x in d if isinstance(x, dict)]
    if isinstance(d, dict):
        for v in d.values():
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                return v
        # a bare record, e.g. the {"note": {...}} shape echoed by a create handler
        for v in d.values():
            if isinstance(v, dict) and v:
                return [v]
        if d and all(isinstance(v, (str, int, float, bool)) or v is None for v in d.values()):
            return [d]
    return []


def _locate(recs, marker_field, marker):
    for r in recs:
        if str(r.get(marker_field, "")) == str(marker):
            return r
    return None


def discover_gated_fields(h, post_path, get_path, cookie, body, marker_field="message",
                          limit=6):
    """Create one baseline record and read back the fields the server added itself.

    Returns (gated, baseline_record, note). `gated` is a list of (field, default)
    pairs the server set to a restrictive value without being asked -- exactly the
    fields an attacker would want to flip, discovered rather than guessed.
    """
    hdr = {"Cookie": cookie} if cookie else {}
    marker = "ptx-ma-baseline-%d" % (int(time.time() * 1000) % 10**9)
    payload = dict(body)
    payload[marker_field] = marker
    r = h.req(post_path, "POST", payload, headers=hdr)
    if r["error"]:
        # A transport failure is not "no gated fields". Returning an empty list here
        # would let the caller render a clean result for a target it never reached.
        return [], None, "baseline POST did not complete: %s" % r["error"]
    baseline = _locate(json_records(r["body"]), marker_field, marker)
    if baseline is None and get_path:
        r2 = h.req(get_path, headers=hdr)
        if not r2["error"]:
            baseline = _locate(json_records(r2["body"]), marker_field, marker)
    if baseline is None:
        return [], None, ("could not read back the baseline record: the create handler "
                          "returned %s and the listing endpoint did not contain it"
                          % r["code"])
    sent = set(payload)
    gated = []
    for k, v in baseline.items():
        if k in sent or k == "id":
            continue
        if isinstance(v, str):
            low = v.strip().lower()
        else:
            low = v
        if low in _GATE_DEFAULTS:
            gated.append((k, v))
    # A non-gate default (role="user") is still worth one attempt, but lower priority.
    extra = [(k, v) for k, v in baseline.items()
             if k not in sent and k != "id" and (k, v) not in gated]
    return gated[:limit] or extra[:limit], baseline, ""


def probe_mass_assignment_fields(h, post_path, get_path, cookie, body, marker_field="message",
                                 limit=6, variants=_TRUTH_VARIANTS):
    """Discover gated fields from the server's own responses, then try to set each one.

    Guesses no field names. Each candidate is submitted in every type that means
    "true", because a guard written as `if body.get("approved") is True` blocks only
    that one spelling and lets 1, "true" and "yes" straight through.

    The verdict rests on the effect read back from the server, never on the response
    the create handler chose to send.
    """
    hdr = {"Cookie": cookie} if cookie else {}
    gated, baseline, note = discover_gated_fields(
        h, post_path, get_path, cookie, body, marker_field, limit)
    if not gated:
        return _verdict(
            "mass-assignment", f"Mass assignment on {post_path}", False,
            note or "the create handler exposed no server-assigned field worth targeting",
            mechanism="No privileged field could be discovered, so nothing was tested.",
            teaching="Discovery is not coverage. If the create handler does not echo the "
                     "record it stored, this probe measures nothing -- say so rather than "
                     "reporting a clean result.",
            extra={"inconclusive_reason": note} if note else None)
    hits, attempts, tag, unreadable = [], 0, int(time.time() * 1000) % 10**9, 0
    for field, default in gated:
        for variant in variants:
            tag += 1
            marker = "ptx-ma-%d-%s" % (tag, field)
            payload = dict(body)
            payload[marker_field] = marker
            payload[field] = variant
            attempts += 1
            posted = h.req(post_path, "POST", payload, headers=hdr)
            if posted["error"]:
                unreadable += 1
                continue
            # Prefer the create response: the listing may only expose records that
            # already passed the gate, which would hide the very field being tested.
            rec = _locate(json_records(posted["body"]), marker_field, marker)
            if rec is None and get_path:
                r2 = h.req(get_path, headers=hdr)
                if not r2["error"]:
                    rec = _locate(json_records(r2["body"]), marker_field, marker)
            if rec is None:
                unreadable += 1
                continue
            got = rec.get(field)
            if got != default and got not in (None, False, 0, "false", "pending"):
                hits.append({"field": field, "sent": variant, "stored": got,
                             "server_default": default, "marker": marker})
    if hits:
        first = hits[0]
        evidence = (
            "%d of %d submissions bound a server-controlled field. "
            "e.g. POST %s with %s=%r (sent %r) stored %s=%r where the server's own "
            "default is %r. Verified by reading the record back, not by trusting the "
            "create response." % (len(hits), attempts, post_path, first["field"],
                                  first["sent"], first["sent"], first["field"],
                                  first["stored"], first["server_default"]))
        return _verdict(
            "mass-assignment", f"Mass assignment on {post_path}", True, evidence,
            "The handler binds request-body keys onto the record instead of an explicit "
            "allowlist, and its guard (if any) tests the value rather than the presence "
            "of the key.",
            "Bind an explicit allowlist of assignable fields. Reject unknown keys outright "
            "instead of checking their values: a value check only blocks the spelling it "
            "was tested with. Set gated state server-side from a trusted source. Add a "
            "regression test that submits the field as true, 1, \"true\" and \"yes\" and "
            "asserts all four are refused.",
            "High", extra={"gated_fields": [f for f, _ in gated], "hits": hits,
                           "attempts": attempts})
    return _verdict(
        "mass-assignment", f"Mass assignment on {post_path}", False,
        "discovered %d server-assigned field(s) (%s); %d submissions across %d type "
        "variants bound none of them%s" % (
            len(gated), ", ".join(f for f, _ in gated), attempts, len(variants),
            "" if not unreadable else "; %d submissions could not be read back and "
            "were NOT verified" % unreadable),
        "The handler restricts which keys a guest may set.",
        "Bind an explicit allowlist and keep a regression test for every type spelling "
        "of a boolean gate -- the guard that passed today may be checking values, not keys.",
        None, extra={"gated_fields": [f for f, _ in gated], "attempts": attempts})


def probe_privilege(h, path, low_cookie, high_cookie, method="GET",
                    expect_role_gated=False):
    """Vertical privilege escalation, with the positive control that makes it mean anything.

    "A normal user got 200 on the admin endpoint" is not a finding on its own. The
    endpoint might be public, or broken for everyone, or return 200 with an empty body
    for any caller. So the privileged identity is asked first: if the admin cannot reach
    it either, there is no privilege boundary here to cross, and the honest answer is
    inconclusive rather than vulnerable.

    Both identities are real sessions supplied by the engagement. This probe cannot be
    run with one cookie, and that is the point -- access control is a comparison.

    `expect_role_gated` is the caller asserting that this route is *meant* to be
    role-restricted. Without it, an endpoint that serves every authenticated caller but
    refuses anonymous ones is genuinely undecidable: that is what a correctly-public
    endpoint looks like too, and guessing from the URL path would mean reporting every
    `/admin/...` as a finding. Intent is a fact about the system under test that
    behaviour cannot reveal, so the caller supplies it -- the same way scope.yaml
    declares what is in scope. With it asserted, "authenticated but not authorised by
    role" becomes a finding rather than an open question.
    """
    if not low_cookie or not high_cookie:
        return _verdict(
            "privilege", f"Privilege escalation on {path}", False,
            "both a low-privilege and a high-privilege session are required",
            "", "", None,
            extra={"inconclusive": True,
                   "inconclusive_reason":
                       "two identities are required. Store them with `ptx session login` "
                       "and pass --as for each; a single session cannot test access "
                       "control because there is nothing to compare it against."})

    hi = h.req(path, method, headers={"Cookie": high_cookie})
    lo = h.req(path, method, headers={"Cookie": low_cookie})
    if hi.get("error") or lo.get("error"):
        return _verdict(
            "privilege", f"Privilege escalation on {path}", False,
            "a request did not complete: %s" % (hi.get("error") or lo.get("error")),
            "", "", None,
            extra={"inconclusive": True,
                   "inconclusive_reason": "a request failed, so nothing was measured"})

    hi_ok = hi["code"] in (200, 201, 204)
    lo_ok = lo["code"] in (200, 201, 204)

    if not hi_ok:
        # No positive control. The privileged user was refused too, so this endpoint
        # is not gated on privilege at all and there is nothing to escalate.
        return _verdict(
            "privilege", f"Privilege escalation on {path}", False,
            f"the high-privilege identity was also refused (HTTP {hi['code']}), so this "
            f"endpoint is not privilege-gated. Low-privilege got HTTP {lo['code']}.",
            "No privilege boundary was observed on this endpoint.",
            "Not a finding. If this endpoint is meant to be privileged, the control is "
            "missing for everyone -- report that as missing authentication instead.",
            None,
            extra={"inconclusive": True,
                   "inconclusive_reason":
                       f"the privileged identity got HTTP {hi['code']}, so the endpoint's "
                       "intended restriction could not be established. Supply an identity "
                       "that is actually permitted here."})

    if lo_ok:
        # Whether the two bodies match is NOT a signal, in either direction. Two users
        # legitimately see different data on an endpoint scoped to the caller -- a
        # per-user balance differs per user, and calling that privilege escalation is a
        # false positive. Conversely an endpoint that returns the same privileged
        # record to everyone matches byte-for-byte, and calling that clean hides a real
        # missing authorisation check. Both mistakes were made here and both were wrong.
        #
        # What can be established is narrower: the endpoint requires *a* session but
        # not *this* role. Whether that is a flaw depends on what the endpoint is for,
        # and behaviour alone cannot answer that -- so this is inconclusive, with the
        # observation stated plainly, not a clean result.
        anon = h.req(path, method)
        anon_ok = anon["code"] in (200, 201, 204)
        if anon_ok:
            return _verdict(
                "privilege", f"Privilege escalation on {path}", False,
                f"both identities got HTTP {hi['code']} and so did an anonymous caller "
                f"(HTTP {anon['code']}), so the endpoint is public. No privilege boundary "
                "was crossed.",
                "The endpoint is not access-controlled at all.",
                "Not a finding. If this content should be restricted, report it as "
                "missing authentication, which applies to every caller.",
                None)
        # The bodies do not decide the verdict, but they do say how much triage this
        # needs. Identical output for two different callers means the response is not
        # scoped to the caller at all -- the worrying case. Output that differs per
        # caller is what a correctly scoped endpoint looks like, though it is not proof.
        scoping = ("the two identities received BYTE-IDENTICAL responses, so nothing in "
                   "the output is scoped to the caller"
                   if lo["body"] == hi["body"] else
                   "the responses differ per caller, which is what correct scoping looks "
                   "like but does not prove it")
        if expect_role_gated:
            return _verdict(
                "privilege", f"Missing function-level authorisation on {path}", True,
                f"anonymous -> HTTP {anon['code']} (refused), so the route IS "
                f"access-controlled, yet the low-privilege identity was served HTTP "
                f"{lo['code']} alongside the high-privilege one (HTTP {hi['code']}, "
                f"{len(lo['body'])}b vs {len(hi['body'])}b); {scoping}. The caller "
                f"asserted this route is role-restricted, so serving an unprivileged "
                f"caller crosses that boundary.",
                "The handler checks that a session exists but never compares the "
                "caller's role against what the route is for.",
                "Enforce the role inside the handler, not in the router or the client, "
                "and deny by default. A session check answers 'who are you'; this route "
                "needed 'are you allowed'.",
                "High",
                extra={"anonymous_code": anon["code"], "low_code": lo["code"],
                       "high_code": hi["code"], "identical_bodies": lo["body"] == hi["body"],
                       "role_gated_expected": True})
        return _verdict(
            "privilege", f"Privilege escalation on {path}", False,
            f"anonymous -> HTTP {anon['code']} (refused), but BOTH the low-privilege "
            f"(HTTP {lo['code']}) and high-privilege (HTTP {hi['code']}) identities were "
            f"served ({len(lo['body'])}b vs {len(hi['body'])}b); {scoping}. The endpoint "
            f"authenticates without authorising by role.",
            "The handler checks that a session exists but never compares the caller's "
            "role against what the route is for.",
            "Decide whether this endpoint is meant to be role-restricted; behaviour "
            "cannot settle that. If it is, add a role check in the handler and make it "
            "structural (decorator or middleware) so a new route inherits it. Hiding the "
            "link in the UI is not a control.",
            None,
            extra={"inconclusive": True,
                   "inconclusive_reason":
                       "the endpoint authenticates but performs no role check, so any "
                       "authenticated user is served. Whether that is a flaw depends on "
                       "the endpoint's intended audience, which cannot be determined "
                       "from its responses -- confirm against the specification. "
                       + scoping.capitalize() + "."})

    return _verdict(
        "privilege", f"Privilege escalation on {path}", False,
        f"high-privilege identity -> HTTP {hi['code']}; low-privilege identity -> "
        f"HTTP {lo['code']} (refused). The role check held.",
        "The handler compares the caller's role against what the route requires.",
        "Working as intended. Keep the check structural so new routes inherit it, and "
        "return 404 rather than 403 where existence itself is sensitive.",
        None)


# --- session tokens a client can rewrite --------------------------------------
#
# probe_jwt_none only ever sent a JWT-shaped token as `Authorization: Bearer`. On a
# live target (2026-09-11) the session was `session=eyJ1c2VyX2lkIjogMywgInJvbGUiOiAi
# AiZ3Vlc3QifQ==` -- plain base64 JSON in a cookie, no dots, no Bearer header -- and the
# probe could not see it. That is the more common case in the wild: hand-rolled session
# cookies vastly outnumber JWTs, and "the token is just encoded JSON" is a complete
# break of every authorisation decision the application makes.
_ROLE_FIELDS = ("role", "roles", "is_admin", "admin", "isadmin", "privilege", "privileges",
                "group", "groups", "scope", "scopes", "permission", "permissions",
                "level", "tier", "access", "authorities", "claims")
_ID_FIELDS = ("user_id", "userid", "uid", "sub", "id", "user", "username", "account_id",
              "accountid", "member_id", "principal")
_ADMIN_WORDS = ("admin", "administrator", "root", "superuser", "owner", "staff", "moderator")


def decode_token(value):
    """Try to read a session token as encoded JSON. Returns (obj, kind) or (None, None).

    Handles the three shapes seen in practice: a JWT (header.payload.signature), plain
    base64 JSON, and url-safe base64 with the padding stripped -- which is what makes a
    token *look* opaque while carrying no secret at all.
    """
    if not value or not isinstance(value, str):
        return None, None
    v = value.strip().strip('"')
    # JWT: take the payload segment.
    if v.count(".") >= 1 and v.split(".")[0]:
        parts = v.split(".")
        if len(parts) >= 2 and parts[1]:
            obj = _b64_json(parts[1])
            if obj is not None:
                return obj, "jwt"
    obj = _b64_json(v)
    if obj is not None:
        return obj, "base64-json"
    return None, None


def _b64_json(s):
    """Decode base64 (either alphabet, padding optional) and parse JSON. None on failure."""
    for alphabet in (base64.b64decode, base64.urlsafe_b64decode):
        for pad in ("", "=", "==", "==="):
            try:
                raw = alphabet(s + pad)
            except Exception:
                continue
            try:
                obj = json.loads(raw.decode("utf-8"))
            except Exception:
                continue
            if isinstance(obj, dict):
                return obj
    return None


def _encode_like(obj, original):
    """Re-encode a forged payload using the same alphabet and padding as the original,
    because a server that url-safe-decodes will reject standard base64 and vice versa."""
    raw = json.dumps(obj).encode()
    urlsafe = "-" in original or "_" in original
    enc = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    out = enc(raw).decode()
    return out if original.endswith("=") else out.rstrip("=")


def forge_claims(obj):
    """Return a list of (description, forged_object) claiming more privilege than `obj`.

    Only fields that already exist, or that plainly belong to the same schema, are
    touched. Inventing unrelated keys would make the server reject the token for a
    reason that has nothing to do with authorisation, and the probe would report a
    forgery that did not actually happen.
    """
    out = []
    lowered = {str(k).lower(): k for k in obj}
    for rf in _ROLE_FIELDS:
        if rf in lowered:
            key = lowered[rf]
            cur = obj[key]
            if isinstance(cur, str):
                out.append((f"{key} -> admin", dict(obj, **{key: "admin"})))
                out.append((f"{key} -> administrator", dict(obj, **{key: "administrator"})))
            elif isinstance(cur, bool):
                out.append((f"{key} -> true", dict(obj, **{key: True})))
            elif isinstance(cur, list):
                out.append((f"{key} -> ['admin']", dict(obj, **{key: ["admin"]})))
    for idf in _ID_FIELDS:
        if idf in lowered:
            key = lowered[idf]
            cur = obj[key]
            if isinstance(cur, int):
                other = 1 if cur != 1 else 2
                out.append((f"{key} -> {other}", dict(obj, **{key: other})))
    return out


def probe_session_forge(h, paths, seed_path="/", method="GET", post_body=None,
                        privileged_requests=None):
    """Find a session token the client can rewrite, and prove the server acts on it.

    Two steps, and the second is the one that matters. Decoding a token as JSON shows it
    carries no secret -- but a server might ignore the contents entirely, and calling
    that a privilege escalation would be a guess. So each forgery is replayed against the
    same requests and compared with the response the genuine token produced. A difference
    is the server reading a value the attacker chose.

    `privileged_requests` is the part that makes this work in practice, and getting it
    wrong is why the first version found nothing on a target that was demonstrably
    broken. A role check usually bites on a WRITE, not a read: GET /api/notes returns
    the same bytes to a guest and an admin, so replaying only reads proves nothing. The
    caller supplies the state-changing requests worth replaying -- typically the ones
    carrying a field the server normally refuses to let a guest set, which is what
    `discover_gated_fields` is for. The two probes compose.
    """
    # Cookie-free on purpose. If the client already holds a session, the server will not
    # issue a new one and there is nothing to test -- which made this probe silently
    # report "no cookie" whenever anything else had run against the target first.
    seed = h.req(seed_path, method, data=post_body, no_cookies=True)
    set_cookie = (seed.get("headers") or {}).get("Set-Cookie") or ""
    if not set_cookie:
        return _verdict(
            "session-forge", "Session token forgeability", False,
            f"{seed_path} set no cookie, so there is no session token to test",
            "", "", None,
            extra={"inconclusive": True,
                   "inconclusive_reason":
                       "no Set-Cookie was returned. Point --seed-path at the request that "
                       "actually establishes a session (often a login POST)."})

    tokens = {}
    for chunk in set_cookie.split(","):
        piece = chunk.split(";")[0].strip()
        if "=" in piece:
            k, v = piece.split("=", 1)
            tokens[k.strip()] = v.strip()
    if not tokens:
        return _verdict("session-forge", "Session token forgeability", False,
                        "Set-Cookie was present but no name=value pair could be read",
                        "", "", None,
                        extra={"inconclusive": True,
                               "inconclusive_reason": "the Set-Cookie header was unparseable"})

    genuine = "; ".join(f"{k}={v}" for k, v in tokens.items())
    decoded = {}
    for k, v in tokens.items():
        obj, kind = decode_token(v)
        if obj is not None:
            decoded[k] = (v, obj, kind)

    if not decoded:
        return _verdict(
            "session-forge", "Session token forgeability", False,
            f"cookies issued: {sorted(tokens)}; none decoded as JSON, so the token is "
            "opaque to the client. That is the correct design.",
            "The session token does not expose its contents.",
            "Working as intended. Keep the token opaque and look the session up "
            "server-side -- an opaque random ID cannot be edited into a different role.",
            None)

    # The replay set: every read path, plus the privileged writes the caller named.
    # Keyed so a GET and a POST to the same path do not collide.
    replay = [("GET", p, None) for p in paths]
    for pr in (privileged_requests or []):
        replay.append(("POST", pr["path"], pr.get("body")))

    # Baseline: what each request does for the genuine token.
    baseline = {}
    for m, p, b in replay:
        r = h.req(p, m, data=b, headers={"Cookie": genuine})
        baseline[(m, p, json.dumps(b, sort_keys=True))] = (r["code"], r["body"])

    hits, attempts = [], 0
    for name, (raw, obj, kind) in decoded.items():
        for desc, forged_obj in forge_claims(obj):
            attempts += 1
            forged_cookie = "; ".join(
                f"{k}={_encode_like(forged_obj, raw) if k == name else v}"
                for k, v in tokens.items())
            for m, p, b in replay:
                key = (m, p, json.dumps(b, sort_keys=True))
                r = h.req(p, m, data=b, headers={"Cookie": forged_cookie})
                b_code, b_body = baseline[key]
                if r.get("error"):
                    continue
                if (r["code"], r["body"]) != (b_code, b_body):
                    hits.append({
                        "cookie": name, "token_kind": kind, "forged": desc,
                        "endpoint": f"{m} {p}", "genuine_code": b_code,
                        "forged_code": r["code"],
                        "genuine_len": len(b_body), "forged_len": len(r["body"]),
                        "genuine_cookie": _mask_secret(genuine),
                        "forged_cookie": _mask_secret(forged_cookie),
                    })
                    break
            if hits:
                break
        if hits:
            break

    if hits:
        first = hits[0]
        return _verdict(
            "session-forge", "Session token forgeability", True,
            f"the `{first['cookie']}` cookie is {_describe_kind(first['token_kind'])} with "
            f"no signature. Editing {first['forged']} changed the server's response on "
            f"{first['endpoint']}: HTTP {first['genuine_code']} "
            f"({first['genuine_len']}b) -> HTTP {first['forged_code']} "
            f"({first['forged_len']}b). The application trusts a value the client writes. "
            f"{attempts} forgery variant(s) attempted.",
            "The session token is encoded rather than signed, so its contents are readable "
            "and writable by anyone. Every authorisation decision derived from it is "
            "attacker-controlled.",
            "Sign the token with a server-held secret and verify the signature on every "
            "request, or drop self-describing tokens and store an opaque random session ID "
            "with the role looked up server-side. Never derive an authorisation decision "
            "from a client-supplied value. HttpOnly does not help here: it stops JavaScript "
            "reading the cookie, not an attacker composing the request.",
            "Critical", extra={"hits": hits, "decoded_tokens": list(decoded),
                               "attempts": attempts})

    return _verdict(
        "session-forge", "Session token forgeability", False,
        f"{len(decoded)} token(s) decoded as JSON ({', '.join(decoded)}) and "
        f"{attempts} forgery variant(s) were replayed against {len(replay)} request(s), "
        "but none changed the server's response. The token exposes its contents, which is "
        "still poor practice, but no privilege change was demonstrated on the requests "
        "replayed.",
        "The token's contents are readable, but these endpoints did not act on the fields "
        "that were edited.",
        "Not demonstrated as exploitable on the endpoints tested -- which is not the same "
        "as safe. A token whose claims a client can read and rewrite should still be "
        "signed, and other endpoints may well act on those claims.",
        None, extra={"decoded_tokens": list(decoded), "attempts": attempts,
                     "inconclusive": True,
                     "inconclusive_reason":
                         "the token is client-writable but no tested endpoint acted on the "
                         "edited claims. Test again against endpoints that make an "
                         "authorisation decision."})


def _describe_kind(kind):
    return {"jwt": "a JWT whose signature is not required",
            "base64-json": "plain base64-encoded JSON"}.get(kind, kind)


def probe_race(h, path, data, cookie, n=10, success_marker="credited"):
    """Fire parallel requests at a single-use operation and count successes."""
    hdr = {"Cookie": cookie} if cookie else {}
    results = []

    def one():
        r = h.req(path, "POST", data, headers=hdr, throttle=False)
        results.append(success_marker in r["body"])

    ts = [threading.Thread(target=one) for _ in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    hits = sum(results)
    vuln = hits > 1
    return _verdict(
        "race", f"Race condition on {path}", vuln,
        f"{hits}/{n} parallel requests succeeded (correct behaviour: exactly 1)",
        "The check-then-act sequence is not atomic, so concurrent requests all pass the "
        "check before any of them commits the state change.",
        "Make the operation atomic — a conditional UPDATE with the guard in the WHERE "
        "clause, a unique constraint, or a transaction with row locking. Application-level "
        "locks don't survive multiple workers. This class is invisible to scanners and is "
        "where money leaks.",
        "High" if vuln else None)


# Path-normalisation variants. Each exists because a front end (reverse proxy, WAF, load
# balancer, CDN) and the application behind it disagree about what the same URL means.
# The proxy matches "/admin" against its deny rule; the app receives something else.
#
# Kept as data rather than inline so the list is reviewable and a variant can be added
# without touching the decision logic.
_ACL_VARIANTS = [
    ("{p}/..;/",        "path parameter segment (Tomcat / Spring)"),
    ("{p}/.;/",         "dot segment with path parameter"),
    ("{p}%2f",          "encoded trailing slash"),
    ("{p}/%2e",         "encoded dot segment"),
    ("{p};/",           "trailing path parameter"),
    ("{p}//",           "double slash"),
    ("{p}/./",          "explicit current directory"),
    ("{p}/../{last}",   "dot-dot returning to the same segment"),
    ("/..;/{last}",     "leading path parameter segment"),
    ("/%2e/{last}",     "leading encoded dot segment"),
    ("{P}",             "upper-cased path"),
    ("{C}",             "leading character of the last segment re-cased"),
    ("{p}%20",          "trailing encoded space"),
    ("{p}%09",          "trailing encoded tab"),
    ("{p}.",            "trailing dot"),
]

_DENIAL_WORDS = ("forbidden", "access denied", "not authorized", "unauthorised",
                 "unauthorized", "permission denied", "login required", "sign in")


def _looks_denied(code, body):
    """Is this response a refusal rather than the protected content?"""
    if code in (401, 403):
        return True
    low = (body or "").lower()
    return code == 404 or any(w in low for w in _DENIAL_WORDS)


def probe_cors(h, path, cookie=None, origin="https://attacker.example"):
    """Cross-origin read misconfiguration.

    The severity discipline here is the point. A reflected origin with credentials allowed
    is a real misconfiguration, but exploiting it needs a victim browser to visit a page the
    attacker controls — it is not an unauthenticated remote read. Calling it Critical is the
    single most common severity inflation in web reports, and this codebase planted it as a
    falsification target for exactly that reason.

    What is NOT a finding:
      * `Access-Control-Allow-Origin: *` on its own. Browsers refuse to send credentials on
        a wildcard response, so there is no credentialed cross-origin read. Reporting it is
        noise that costs the report its credibility.
      * A reflected origin without `Access-Control-Allow-Credentials: true`. The response is
        readable cross-origin but carries no session, so nothing privileged crosses.
    """
    hdr = {"Origin": origin}
    if cookie:
        hdr["Cookie"] = cookie
    r = h.req(path, headers=hdr)
    if r["code"] == 0:
        return _verdict("cors", f"CORS misconfiguration on {path}", False,
                        f"the request to {path} did not complete", "", "", None,
                        extra={"inconclusive": True,
                               "inconclusive_reason":
                                   "the request never completed, so the response headers "
                                   "were never read"})

    acao = (r["headers"].get("Access-Control-Allow-Origin") or "").strip()
    acac = (r["headers"].get("Access-Control-Allow-Credentials") or "").strip().lower()
    acah = (r["headers"].get("Access-Control-Expose-Headers") or "").strip()
    reflected = acao.lower() == origin.lower() or acao == "*"
    credentialed = acac == "true"

    if not reflected:
        return _verdict(
            "cors", f"CORS misconfiguration on {path}", False,
            f"Origin: {origin} was not reflected (Access-Control-Allow-Origin: "
            f"{acao or 'absent'})",
            "The server does not echo an arbitrary origin back, so a cross-origin page "
            "cannot read this response.", "", None)

    if acao == "*" and not credentialed:
        return _verdict(
            "cors", f"CORS misconfiguration on {path}", False,
            "Access-Control-Allow-Origin: * without credentials allowed",
            "A wildcard origin cannot be combined with credentials — browsers refuse to "
            "send them — so no authenticated cross-origin read is possible. This is a "
            "deliberate public-API posture, not a vulnerability.", "", None,
            extra={"acao": acao, "acac": acac})

    # Reflected (or wildcard-with-credentials) AND credentials allowed: a real
    # misconfiguration. Still Medium: it needs a victim browser.
    vuln = reflected and credentialed
    return _verdict(
        "cors", f"CORS misconfiguration on {path}", vuln,
        f"Origin: {origin} reflected as Access-Control-Allow-Origin: {acao} with "
        f"Access-Control-Allow-Credentials: {acac or 'absent'}"
        + (f"; exposes {acah}" if acah else ""),
        "The server reflects an arbitrary Origin and permits credentials, so a page on any "
        "domain can read this endpoint's response with the victim's session attached.",
        "Reflect nothing. Allowlist exact origins on the server, and never combine a "
        "reflected origin with Access-Control-Allow-Credentials: true. If the endpoint "
        "really is public, use * without credentials instead — the browser then refuses to "
        "attach a session and the read carries nothing privileged.",
        # Medium, deliberately. It requires a victim to visit attacker-controlled content,
        # which makes it strictly weaker than an unauthenticated read of the same data.
        "Medium" if vuln else None,
        extra={"acao": acao, "acac": acac, "origin_tested": origin,
               "severity_rationale":
                   "Medium, not Critical: exploitation requires a victim browser to load "
                   "attacker-controlled content. A standalone CORS finding is not an "
                   "unauthenticated remote read."})


def probe_user_enum(h, path, known_user, field="username", pwfield="password",
                    samples=2, ctype="json"):
    """Account enumeration through the login endpoint.

    The comparison is against a control username that cannot exist, sampled more than once.
    Three things make this easy to get wrong and all three are handled here:

      * The response often echoes the submitted username back. Comparing bodies raw would
        make every login form "vulnerable", because the two bodies differ by the string we
        ourselves sent. The candidate and control names are scrubbed out before comparison.
      * One sample each proves nothing. A load balancer, a WAF, or an intermittent 500
        produces a difference that is not a signal, so both sides are sampled and the
        difference has to be consistent.
      * A difference is only evidence if it distinguishes *existence*. If both usernames are
        rejected identically the endpoint is doing the right thing and this reports clean.
    """
    if not known_user:
        return _verdict("user-enum", f"Account enumeration on {path}", False,
                        "no --user supplied, so there is no candidate to compare against",
                        "", "", None,
                        extra={"inconclusive": True,
                               "inconclusive_reason":
                                   "no --user supplied. Pass a username you believe exists "
                                   "(from OSINT, a leak, or a guess); the probe needs it to "
                                   "compare against a control that cannot exist."})

    control = "ptxctl" + str(int(time.time() * 1000))[-9:] + "zq"

    def _post(user):
        payload = {field: user, pwfield: "ptxWrongPw!" + str(int(time.time()))[-5:]}
        if ctype == "json":
            return h.req(path, "POST", payload)
        return h.req(path, "POST", urllib.parse.urlencode(payload),
                     ctype="application/x-www-form-urlencoded")

    def _normalise(body, user):
        """Remove every trace of the submitted username so the comparison cannot be won by
        the string we sent."""
        b = body or ""
        # Replaced with a fixed placeholder, not with "". Deleting the string would let two
        # genuinely different bodies collapse to the same thing (or the reverse), and the
        # comparison would then be measuring our own edit.
        for variant in {user, urllib.parse.quote(user), user.lower(), user.upper()}:
            if variant:
                b = b.replace(variant, "@@SCRUBBED@@")
        return b

    cand, ctrl = [], []
    for _ in range(max(1, samples)):
        cand.append(_post(known_user))
        ctrl.append(_post(control))

    if any(r["code"] == 0 for r in cand + ctrl):
        return _verdict("user-enum", f"Account enumeration on {path}", False,
                        "one or more login requests did not complete",
                        "", "", None,
                        extra={"inconclusive": True,
                               "inconclusive_reason":
                                   "a login request never completed, so the comparison is "
                                   "not a measurement"})

    c_codes = {r["code"] for r in cand}
    t_codes = {r["code"] for r in ctrl}
    c_bodies = {_normalise(r["body"], known_user) for r in cand}
    t_bodies = {_normalise(r["body"], control) for r in ctrl}

    # Inconsistent results across samples mean we are looking at noise, not a signal.
    if len(c_codes) > 1 or len(t_codes) > 1:
        return _verdict("user-enum", f"Account enumeration on {path}", False,
                        f"responses were not stable across {samples} samples "
                        f"(candidate {sorted(c_codes)}, control {sorted(t_codes)})",
                        "", "", None,
                        extra={"inconclusive": True,
                               "inconclusive_reason":
                                   "the endpoint did not answer consistently, so any "
                                   "difference could be transient rather than a signal"})

    code_diff = c_codes != t_codes
    body_diff = c_bodies != t_bodies
    vuln = code_diff or body_diff

    # Both sides rejected as a bad request means the login body was not shaped the way the
    # endpoint expects, so nothing was compared. Reporting "identical responses, not
    # vulnerable" here would be the silence-recorded-as-clean failure again.
    if not vuln and c_codes == {400}:
        return _verdict("user-enum", f"Account enumeration on {path}", False,
                        "both the candidate and the control were rejected as a malformed "
                        "request (HTTP 400)",
                        "", "", None,
                        extra={"inconclusive": True,
                               "inconclusive_reason":
                                   "the endpoint rejected the login body as malformed, so "
                                   "the two responses were never really compared. Check "
                                   "--user-field and the content type."})

    if not vuln:
        return _verdict(
            "user-enum", f"Account enumeration on {path}", False,
            f"candidate and control both -> HTTP {c_codes.pop()}, identical body after "
            "scrubbing the submitted username",
            "The endpoint answers an unknown account and a wrong password the same way, so "
            "it does not disclose which accounts exist.",
            "", None)

    detail = []
    if code_diff:
        detail.append(f"status differs: {sorted(c_codes)[0]} for an existing account vs "
                      f"{sorted(t_codes)[0]} for one that cannot exist")
    if body_diff:
        detail.append("response body differs after removing the submitted username")
    return _verdict(
        "user-enum", f"Account enumeration on {path}", True,
        f"over {samples} sample(s): " + "; ".join(detail),
        "The login endpoint distinguishes an account that does not exist from one that "
        "exists but was given the wrong password. An attacker can walk a list of candidate "
        "usernames and keep the ones the server confirms, turning a password attack from a "
        "guess over two unknowns into a guess over one.",
        "Answer every failed authentication identically: same status, same body, same "
        "latency, whether the account exists or not. If the account does not exist, still "
        "run the password hash so the timing matches. Where the business needs to tell a "
        "user their address is unregistered, do it out of band by email rather than in the "
        "login response.",
        "Medium" if not code_diff else "Medium",
        extra={"candidate_user": known_user, "control_user": control,
               "candidate_status": sorted(c_codes)[0], "control_status": sorted(t_codes)[0],
               "samples": samples})


def probe_acl_bypass(h, path, cookie=None):
    """Authorisation bypass by path normalisation.

    Requires an established baseline. If the plain path is not refused there is no control
    to bypass and the probe says so rather than hunting for a 200 to call a finding — that
    is how a probe starts reporting the application's own public pages as bypasses.

    A variant counts as a bypass only if it is (a) not refused and (b) materially different
    from the refusal. Plenty of stacks answer every unmatched route with 200 and an HTML
    error page; status alone would make those all false positives.
    """
    hdr = {"Cookie": cookie} if cookie else None
    base = h.req(path, headers=hdr)
    if base["code"] == 0:
        return _verdict("acl-bypass", f"ACL bypass on {path}", False,
                        f"the baseline request to {path} did not complete",
                        "", "", None,
                        extra={"inconclusive": True,
                               "inconclusive_reason":
                                   "the baseline request never completed, so there is no "
                                   "denial to compare variants against"})
    if not _looks_denied(base["code"], base["body"]):
        return _verdict("acl-bypass", f"ACL bypass on {path}", False,
                        f"{path} returned HTTP {base['code']} without any refusal, so there "
                        "is no access control here to bypass",
                        "", "", None,
                        extra={"inconclusive": True,
                               "inconclusive_reason":
                                   f"{path} is not protected (HTTP {base['code']}). Point "
                                   "this probe at a route that actually returns 401/403."})

    last = [x for x in path.split("/") if x][-1] if "/" in path else path.strip("/")
    # Re-case the first character of the final segment: /admin/Panel. Cheap, and it is the
    # spelling a case-insensitive back end behind a case-sensitive rule most often leaks.
    recased = path[:path.rfind(last)] + (last[:1].upper() + last[1:] if last else "") \
        if last and last in path else path
    tried, hits = [], []
    for tmpl, why in _ACL_VARIANTS:
        variant = tmpl.format(p=path.rstrip("/") or "/", P=path.upper(),
                              C=recased, last=last or "x")
        r = h.req(variant, headers=hdr, throttle=True)
        if r["code"] == 0:
            tried.append((variant, why, "no response", False))
            continue
        refused = _looks_denied(r["code"], r["body"])
        same_as_denial = (r["body"] == base["body"]
                          and len((r["body"] or "").strip()) > 0)
        bypass = (not refused) and (not same_as_denial)
        tried.append((variant, why, f"HTTP {r['code']}", bypass))
        if bypass:
            hits.append((variant, why, r["code"], len(r["body"] or "")))

    vuln = bool(hits)
    ev = f"baseline {path} -> HTTP {base['code']} (refused); " + (
        "; ".join(f"{v} [{w}] -> HTTP {c}, {n}b" for v, w, c, n in hits[:5])
        if hits else
        f"{len(tried)} normalisation variants all still refused")
    return _verdict(
        "acl-bypass", f"Authorisation bypass by path normalisation on {path}", vuln, ev,
        "A front end and the application behind it normalise the same URL differently, so "
        "an access rule written against the literal path is matched by the proxy but not by "
        "the app — or the other way round. The control exists and is real; it is simply "
        "evaluated against a different string than the one the handler receives.",
        "Never express authorisation as a string match on the request path. Decide after "
        "the framework has routed the request, from the matched route and the principal, so "
        "no spelling of the URL can reach the handler without passing the same check. "
        "Normalise once, at the edge, and reject encoded separators and dot segments rather "
        "than decoding them after the rule has run.",
        "High" if vuln else None,
        extra={"variants_tried": [{"url": v, "why": w, "result": res, "bypassed": b}
                                  for v, w, res, b in tried]})


def probe_method_tamper(h, path, cookie):
    hdr = {"Cookie": cookie, "X-HTTP-Method-Override": "DELETE"} if cookie else \
          {"X-HTTP-Method-Override": "DELETE"}
    r = h.req(path, "POST", {}, headers=hdr)
    vuln = r["code"] == 200 and "deleted" in r["body"].lower()
    return _verdict(
        "method-tamper", f"HTTP method tampering on {path}", vuln,
        f"POST + X-HTTP-Method-Override: DELETE -> HTTP {r['code']}",
        "The framework or handler honours a client-supplied method-override header, so "
        "restrictions expressed in terms of HTTP method can be bypassed.",
        "Don't express authorization in terms of HTTP method alone. If you must accept "
        "override headers, restrict them to authenticated same-origin requests and never "
        "let them grant access to a method the route would otherwise refuse.",
        "Medium" if vuln else None)


def probe_csrf(h, path, data, cookie, verify_fn, samesite=None, login_headers=None):
    """Cross-site request forgery, established by effect rather than by absence.

    "No CSRF token in the form" is not a finding — it is a guess about a defence that may
    live in a cookie attribute, a framework default, or a header check the probe never
    provoked. So this probe requires ALL of the following before it says anything:

      1. Authentication rides on a cookie. A bearer token in a header is not auto-attached
         by a browser, so cross-site forgery does not apply and reporting it is noise.
      2. That cookie is not SameSite=Strict or Lax, which would block the cross-site POST.
      3. The endpoint accepts the state-changing request bearing a foreign Origin.
      4. The state ACTUALLY CHANGED, observed through verify_fn — not inferred from a 200.

    Condition 4 is the one that matters. A correctly-defended endpoint and a vulnerable one
    can both return HTTP 200; only the resulting state distinguishes them.
    """
    FOREIGN = "https://attacker-not-in-scope.example"
    hdr = {"Origin": FOREIGN, "Referer": FOREIGN + "/"}
    if cookie:
        hdr["Cookie"] = cookie

    # Condition 1/2: is this cookie-authenticated at all, and is it same-site protected?
    ss = (samesite or "").lower()
    if login_headers:
        for c in (login_headers.get("Set-Cookie") or "").split(","):
            m = re.search(r"samesite=([A-Za-z]+)", c, re.I)
            if m:
                ss = m.group(1).lower()
                break
    same_site_blocks = ss in ("strict", "lax")

    r = h.req(path, "POST", data or {}, headers=hdr)
    accepted = r["code"] in (200, 201, 202, 204)
    changed = bool(verify_fn(h, {"Cookie": cookie} if cookie else {})) if accepted else False

    if same_site_blocks:
        return _verdict(
            "csrf", f"Cross-site request forgery on {path}", False,
            f"state-changing POST accepted a foreign Origin (HTTP {r['code']}, state "
            f"changed: {changed}), but the session cookie is SameSite={ss}, which blocks "
            f"the cross-site request a browser would send — not exploitable as CSRF",
            "The endpoint trusts the request, but the browser will not deliver the cookie "
            "cross-site, so the attack has no path.",
            "SameSite is a real defence here, not a mitigation. Keep it, and add a token "
            "so the protection does not depend on one cookie attribute.",
            None)

    vuln = accepted and changed
    return _verdict(
        "csrf", f"Cross-site request forgery on {path}", vuln,
        f"POST with Origin: {FOREIGN} -> HTTP {r['code']}; state ACTUALLY CHANGED: "
        f"{changed}; SameSite={ss or 'unset'}"
        + ("" if vuln else " (the request was refused or had no effect)"),
        "The endpoint performs a state change for any request carrying the session cookie, "
        "regardless of where the request came from. A browser will attach that cookie "
        "automatically to a cross-site form post, so a page on any origin can drive it.",
        "Bind the request to the session with an unguessable token the attacker's origin "
        "cannot read, and reject requests whose Origin or Referer is not your own. Set "
        "SameSite=Lax or Strict as defence in depth, not as the only control.",
        "High" if vuln else None)


def probe_ssti(h, path, cookie=None):
    hdr = {"Cookie": cookie} if cookie else {}
    r = h.req(path, "POST", {"template": "{user.__class__}"}, headers=hdr)
    # The payload must come back as a resolved object repr, not as the literal string.
    # Matching the word "class" reports a target that merely echoes input as vulnerable.
    resolved = re.search(r"<class\s+'[^']+'>", r["body"]) is not None
    echoed = "{user.__class__}" in r["body"]
    vuln = r["code"] == 200 and resolved and not echoed
    return _verdict(
        "ssti", f"Template injection on {path}", vuln,
        f"response: {r['body'][:90]} (resolved object repr: {resolved}, "
        f"payload echoed verbatim: {echoed})",
        "A user-supplied format or template string is evaluated against a live context, "
        "exposing object internals and potentially code execution.",
        "Never pass user input as a template. Pass it as data into a fixed template. "
        "Python's str.format is deceptively dangerous here because it looks harmless and "
        "still permits attribute traversal.",
        "High" if vuln else None)


# --- business logic ---------------------------------------------------------
# These probes are structurally different from the injection probes. An injection probe
# looks for attacker syntax reaching a sink; a business-logic probe looks for the
# application's own arithmetic producing a result the business would not accept. There is
# no payload to signature, so every one of them works the same way: read the state, act,
# read the state again, and report only what the second read proves.
#
# This matters because a 200 response proves nothing here. An endpoint that accepts a
# negative quantity and correctly rejects it still returns 200.

def probe_negative_quantity(h, path, item_field, sku, qty_field="qty", qty=-3,
                            balance_fn=None, cookie=None):
    """Order a negative quantity and see whether the account was charged or credited."""
    hdr = {"Cookie": cookie} if cookie else {}
    before = balance_fn(h, hdr) if balance_fn else None
    r = h.req(path, "POST", {item_field: sku, qty_field: qty}, headers=hdr)
    after = balance_fn(h, hdr) if balance_fn else None
    total, parsed = None, False
    try:
        total = json.loads(r["body"]).get("total")
        parsed = True
    except Exception:
        pass
    # The finding is the balance moving the WRONG WAY, not the request being accepted.
    credited = (before is not None and after is not None and after > before)
    vuln = credited or (total is not None and total < 0)
    # No balance available and the body unreadable means we never observed the effect.
    inconclusive = (before is None or after is None) and not parsed
    ev = f"POST {path} with {qty_field}={qty}: HTTP {r['code']}, total={total}"
    if before is not None and after is not None:
        ev += f"; balance {before} -> {after} ({'CREDITED' if credited else 'charged or unchanged'})"
    else:
        ev += "; no balance oracle supplied, so only the returned total is evidence"
    return _verdict(
        "negative-qty", f"Negative quantity accepted on {path}", vuln, ev,
        "Quantity is not validated, so a negative quantity produces a negative charge. "
        "The order pipeline multiplies price by quantity and applies the result to a "
        "balance without checking the sign.",
        "Validate quantity as a positive integer at the boundary, and re-derive every "
        "monetary value server-side. The deeper fix is to treat the balance update as a "
        "constraint rather than an assignment, so a credit from a purchase is impossible "
        "by construction. Note this class is invisible to every scanner: the request is "
        "well-formed, authenticated and syntactically valid.",
        "High" if vuln else None,
        extra={"inconclusive": inconclusive,
               "inconclusive_reason": "no balance was available to compare and the "
                                      "response body was not parseable, so the effect on "
                                      "the account was never observed"} if inconclusive else None)


def probe_price_tamper(h, path, item_field, sku, price_field="unit_price",
                       tampered=0.01, cookie=None):
    """Submit a price and see whether the order used it instead of the catalog price."""
    hdr = {"Cookie": cookie} if cookie else {}
    r = h.req(path, "POST", {item_field: sku, "qty": 1, price_field: tampered}, headers=hdr)
    body, parsed = {}, False
    try:
        body = json.loads(r["body"])
        parsed = True
    except Exception:
        pass
    charged = body.get("total", body.get(price_field))
    catalog = body.get("catalog_price")
    # Only a finding if the amount charged follows the submitted price. If the server
    # ignored it, the response proves the control works.
    vuln = (charged is not None and abs(float(charged) - float(tampered)) < 0.001)
    ev = (f"POST {path} with {price_field}={tampered}: HTTP {r['code']}, charged={charged}"
          + (f", catalog price={catalog}" if catalog is not None else ""))
    if catalog is not None and charged is not None:
        ev += f" — the order was priced at {float(charged)/float(catalog)*100:.2f}% of catalog"
    return _verdict(
        "price-tamper", f"Client-supplied price accepted on {path}", vuln, ev,
        "The unit price is taken from the request body instead of being looked up from the "
        "product record, so the buyer sets the price.",
        "Never accept a price from the client. Look it up server-side from the catalog at "
        "the moment of charging, and if a discount is legitimate, model it as a promotion "
        "applied server-side. Where a client must quote a price, sign it and verify the "
        "signature, or store the quote and reference it by ID.",
        "High" if vuln else None,
        extra={"inconclusive": not parsed,
               "inconclusive_reason": "the response body was not parseable, so the amount "
                                      "actually charged could not be read"} if not parsed else None)


def probe_refund_abuse(h, path, amount=5000.0, order_id=999999, balance_fn=None,
                       cookie=None):
    """Request a refund for an order that does not exist and see if it is paid."""
    hdr = {"Cookie": cookie} if cookie else {}
    before = balance_fn(h, hdr) if balance_fn else None
    r = h.req(path, "POST", {"order_id": order_id, "amount": amount}, headers=hdr)
    after = balance_fn(h, hdr) if balance_fn else None
    paid = (before is not None and after is not None
            and abs((after - before) - amount) < 0.01)
    partial = (before is not None and after is not None and after > before)
    vuln = paid or partial
    ev = (f"POST {path} for non-existent order {order_id}, amount={amount}: "
          f"HTTP {r['code']}")
    if before is not None and after is not None:
        ev += f"; balance {before} -> {after}"
        ev += " (FULLY PAID)" if paid else (" (partially credited)" if partial
                                            else " (correctly refused)")
    return _verdict(
        "refund-abuse", f"Refund granted without a valid order on {path}", vuln, ev,
        "The refund handler credits the caller without verifying that the referenced order "
        "exists, belongs to them, was paid, and has not already been refunded.",
        "Derive the refund amount from the stored order, never from the request. Check "
        "ownership, payment state, and that the sum of prior refunds does not exceed the "
        "original charge — and make that check a database constraint so a double refund "
        "cannot commit. Refund is the one operation where trusting client input moves "
        "money out of the business directly.",
        "Critical" if vuln else None)


def probe_workflow_bypass(h, path, gate_field="validated", extra=None, cookie=None):
    """Assert that a prior step happened and see whether the application believes it."""
    hdr = {"Cookie": cookie} if cookie else {}
    payload = dict(extra or {}); payload[gate_field] = True
    # First establish that the gate actually gates: calling without it must be refused.
    base = h.req(path, "POST", dict(extra or {}), headers=hdr)
    r = h.req(path, "POST", payload, headers=hdr)
    gated = base["code"] in (400, 401, 403, 409, 422)
    passed = r["code"] == 200
    vuln = gated and passed
    ev = (f"POST {path} without {gate_field} -> HTTP {base['code']}; "
          f"POST with {gate_field}=true -> HTTP {r['code']}")
    if vuln:
        ev += " — the step gate is a client-supplied assertion, so the step is optional"
    elif not gated:
        ev += (" — the endpoint did not refuse the unvalidated call either, so this is "
               "not a bypass of a gate but an absent gate (report separately)")
    return _verdict(
        "workflow-bypass", f"Workflow step bypassable on {path}", vuln, ev,
        "Whether a prior step completed is taken from the request rather than from "
        "server-side state, so a caller can assert that validation or payment happened.",
        "Track workflow state server-side against the order record and refuse transitions "
        "that are not legal from the current state. A state machine whose states live in "
        "the database cannot be talked past; one whose states live in the request can. "
        "The general rule: the client may request a transition, never declare a state.",
        "High" if vuln else None)


def probe_exposure(h, paths=None):
    """Look for files that should never be served."""
    paths = paths or ["/.env", "/.git/config", "/.git/HEAD", "/config.json",
                      "/backup.sql", "/web.config", "/package-lock.json",
                      "/composer.lock", "/.aws/credentials", "/server-status"]
    found, secrets = [], []
    for p in paths:
        r = h.req(p)
        if r["code"] == 200 and len(r["body"]) > 0:
            kind = "dependency manifest" if "lock" in p else "sensitive file"
            got = detect_secrets(r["body"])
            if got:
                kind += " with credential material"
                secrets += got
            found.append({"path": p, "bytes": len(r["body"]), "kind": kind,
                          "secrets": got})
    vuln = bool(found)
    return _verdict(
        "exposure", "Sensitive file exposure", vuln,
        "; ".join(f"{f['path']} ({f['bytes']}b, {f['kind']})" for f in found) or "none found",
        "Files intended for the build or deploy environment are reachable over HTTP.",
        "Serve from an explicit public directory and deny everything else by default. "
        "An exposed lockfile is not just information disclosure — it hands an attacker an "
        "exact dependency inventory to match against known CVEs.",
        "High" if any("lock" not in f["path"] for f in found) else ("Medium" if found else None),
        extra={"secrets_found": sorted(set(secrets)),
               "leaked_paths": [f["path"] for f in found]})


def probe_headers(h, path="/"):
    r = h.req(path)
    if _unreachable(r):
        return _verdict(
            "headers", "Security header and banner review", False,
            f"GET {path} never completed — no response was received, so no header could be "
            f"observed either way",
            "", "", None,
            extra={"inconclusive": True,
                   "inconclusive_reason": "the request did not complete; an empty header "
                                          "set is not a finding"})
    t = {k.lower(): v for k, v in r["headers"].items()}
    want = {"strict-transport-security": "HSTS", "x-frame-options": "X-Frame-Options",
            "content-security-policy": "CSP", "x-content-type-options": "X-Content-Type-Options",
            "referrer-policy": "Referrer-Policy"}
    missing = [v for k, v in want.items() if k not in t]
    # Banner disclosure means APPLICATION-set disclosure. Werkzeug and most servers emit a
    # default Server header the application never chose, so counting it as a leak produces
    # a false positive on any hardened target that simply failed to suppress the default.
    app_banners = {k: t[k] for k in ("x-powered-by", "x-aspnet-version", "x-runtime",
                                     "x-version", "x-drupal-cache") if k in t}
    server = t.get("server", "")
    framework_default = bool(re.match(r"^(werkzeug|gunicorn|uvicorn|nginx|apache|caddy|"
                                      r"microsoft-iis|cloudflare|amazon|openresty)",
                                      server, re.I))
    leaks = dict(app_banners)
    if server and not framework_default:
        leaks["server"] = server
    notes = []
    if server and framework_default:
        notes.append(f"server={server} (framework default, not counted as disclosure)")
    return _verdict(
        "headers", "Security header and banner review", bool(missing or leaks),
        f"missing: {', '.join(missing) or 'none'}; application-disclosed: "
        f"{', '.join(f'{k}={v}' for k, v in leaks.items()) or 'none'}" +
        (f"; {'; '.join(notes)}" if notes else ""),
        "Standard hardening headers are absent and the stack is disclosed in banners.",
        "Missing headers alone are Low — they are defence in depth, not a vulnerability, "
        "and a report padded with them gets skimmed while the real Critical is missed. "
        "Banner disclosure matters mainly because it accelerates an attacker's targeting.",
        "Low" if (missing or leaks) else None)


# --------------------------------------------------------------------------- #
# Confused deputy / open token-spending proxy                                  #
# --------------------------------------------------------------------------- #
def _cb(path):
    """Append a cache-buster so a caching proxy answers fresh, not from a stale entry.

    A proxy that caches can keep serving data for objects that no longer exist; reading that
    as live exposure is a false positive. Busting the cache makes the verdict about now.
    """
    return path + ("&" if "?" in path else "?") + "cb=%d" % int(time.time())


def probe_confused_deputy(h, path, param="endpoint", upstream="https://api.github.com",
                          auth_path="/user",
                          private_path="/user/repos?visibility=private"):
    """Detect a proxy that spends a server-side credential on behalf of anonymous callers.

    The oracle is a control/exploit pair against the UPSTREAM, exactly as a human would
    prove it:

      control : ask the upstream directly, unauthenticated. For an auth-gated path this is
                refused (GitHub returns 401). That establishes the path normally needs a
                credential.
      exploit : ask the SAME path through the candidate proxy. If the proxy returns what the
                upstream refuses, something behind it supplied a credential for us -- a
                confused deputy.

    If the upstream answers the control anonymously (200), the path is public and the oracle
    is meaningless, so we say inconclusive rather than guess. Escalation to Critical happens
    only on a second, independently-proven fact: that the deputy's credential is over-scoped
    (it will hand back private resources), never on assumption.
    """
    base = path if "?" not in path else path.split("?", 1)[0]
    up = Http(upstream, rps=5)
    control = up.req(auth_path)
    if control.get("error"):
        return _verdict(
            "confused-deputy", f"Open credential-spending proxy on {path}", False,
            f"upstream {upstream}{auth_path} did not complete: {control['error']}",
            "", "", None,
            extra={"inconclusive": True, "inconclusive_reason":
                   "the upstream control request failed, so nothing was established"})
    if control["code"] in (200, 201, 204):
        return _verdict(
            "confused-deputy", f"Open credential-spending proxy on {path}", False,
            f"upstream {upstream}{auth_path} is public (HTTP {control['code']}), so a proxy "
            f"answering it proves nothing about a credential",
            "", "", None)

    exploit = h.req(base + "?" + urllib.parse.urlencode({param: _cb(auth_path)}))
    if exploit.get("error") or exploit["code"] in (401, 403):
        return _verdict(
            "confused-deputy", f"Open credential-spending proxy on {path}", False,
            f"the proxy refused {auth_path} exactly as the upstream does "
            f"(proxy HTTP {exploit.get('code')}, upstream HTTP {control['code']}), so no "
            f"credential is being spent for anonymous callers",
            "", "", None)

    # Liveness control. A proxy that returns 200 for an object that CANNOT exist on the
    # upstream is serving stale or fabricated data, so the 200 above is not evidence of a
    # live credential spend. This is the control that prevents the classic cache false
    # positive: reading a stale cached "private repo" as a live breach.
    lie = h.req(base + "?" + urllib.parse.urlencode(
        {param: "/ptx-liveness-%d" % int(time.time())}))
    if not lie.get("error") and lie["code"] == 200:
        return _verdict(
            "confused-deputy", f"Open credential-spending proxy on {path}", False,
            f"the proxy returned HTTP 200 for a path that cannot exist on the upstream, so "
            f"its responses are stale or fabricated and the apparent credential spend "
            f"(exploit HTTP {exploit['code']}) cannot be trusted",
            "", "", None,
            extra={"inconclusive": True, "control_code": control["code"],
                   "exploit_code": exploit["code"], "liveness_code": lie["code"],
                   "inconclusive_reason":
                       "proxy answered 200 for a nonexistent object (stale/lying cache)"})

    # The proxy answered what the upstream refuses -> a credential is in play.
    priv = h.req(base + "?" + urllib.parse.urlencode({param: _cb(private_path)}))
    over_scoped = False
    priv_count = 0
    if not priv.get("error") and priv["code"] == 200:
        try:
            items = json.loads(priv["body"])
            if isinstance(items, list):
                priv_count = sum(1 for r in items if isinstance(r, dict) and r.get("private"))
                over_scoped = priv_count > 0
        except Exception:
            pass
    sev = "Critical" if over_scoped else "High"
    return _verdict(
        "confused-deputy", f"Open credential-spending proxy on {path}", True,
        f"upstream {upstream}{auth_path} refuses anonymous callers (HTTP {control['code']}) "
        f"but the proxy returned it with HTTP {exploit['code']} -- a server-side credential is "
        f"spent on behalf of anyone; over-scoped to private resources: {over_scoped} "
        f"({priv_count} private item(s) enumerated)",
        "The backend acts as a confused deputy, forwarding anonymous requests with its own "
        "token, so the upstream sees the deputy's identity, not the caller's.",
        "Remove the credential from the pass-through or require authentication; re-issue the "
        "token with minimum scope and treat the old one as disclosed.",
        sev,
        extra={"control_code": control["code"], "exploit_code": exploit["code"],
               "over_scoped": over_scoped, "private_items": priv_count})


# --------------------------------------------------------------------------- #
# Git history leak                                                             #
# --------------------------------------------------------------------------- #
_GIT_SECRET_PATTERNS = {
    "github token": r"gh[pousr]_[A-Za-z0-9]{20,}",
    "aws access key": r"AKIA[0-9A-Z]{16}",
    "stripe live key": r"sk_live_[A-Za-z0-9]{10,}",
    "google api key": r"AIza[0-9A-Za-z_-]{20,}",
    "private key block": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "slack token": r"xox[baprs]-[A-Za-z0-9-]{10,}",
}


def probe_git_history_leak(repo, extra_patterns=None):
    """Find secrets that were committed and later removed but remain in history.

    Working-tree scans miss the classic leak: a credential deleted from HEAD is still
    recoverable by anyone who can clone, because history is part of the object store. This
    probe scans the full reachable history, not the checkout.

    `repo` may be a URL (cloned to a temp dir) or a local path. The verdict reports what KIND
    of material is recoverable and how often, never the material itself.
    """
    import subprocess, tempfile, shutil
    tmp = None
    target = repo
    if re.match(r"^(https?://|git@)", repo):
        tmp = tempfile.mkdtemp(prefix="ptx-githist-")
        try:
            c = subprocess.run(["git", "clone", "--quiet", repo, tmp],
                               capture_output=True, timeout=300)
        except (OSError, subprocess.TimeoutExpired):
            shutil.rmtree(tmp, ignore_errors=True)
            return _verdict("git-history-leak", "Secrets recoverable from git history", False,
                            "git clone did not complete; no conclusion about repository history",
                            "", "", None,
                            extra={"inconclusive": True,
                                   "inconclusive_reason": "clone unavailable or timed out"})
        if c.returncode != 0:
            shutil.rmtree(tmp, ignore_errors=True)
            return _verdict("git-history-leak", "Secrets recoverable from git history", False,
                            f"git clone failed (exit {c.returncode}); remote error details "
                            "suppressed because they may contain credentials",
                            "", "", None,
                            extra={"inconclusive": True,
                                   "inconclusive_reason": "clone failed"})
        target = tmp
    try:
        try:
            log = subprocess.run(["git", "-C", target, "log", "-p", "--all",
                                  "--no-color", "--date=short"],
                                 capture_output=True, text=True, timeout=600)
        except (OSError, subprocess.TimeoutExpired):
            return _verdict("git-history-leak", "Secrets recoverable from git history", False,
                            "git history scan did not complete; no clean conclusion was made",
                            "", "", None,
                            extra={"inconclusive": True,
                                   "inconclusive_reason": "history scan unavailable or timed out"})
        if log.returncode != 0:
            return _verdict("git-history-leak", "Secrets recoverable from git history", False,
                            f"git history scan failed (exit {log.returncode}); no clean "
                            "conclusion was made",
                            "", "", None,
                            extra={"inconclusive": True,
                                   "inconclusive_reason": "history scan failed"})
        text = log.stdout
        pats = dict(_GIT_SECRET_PATTERNS)
        if extra_patterns:
            pats.update(extra_patterns)
        hits = {}
        for kind, pat in pats.items():
            n = len(set(re.findall(pat, text)))
            if n:
                hits[kind] = n
        emails = sorted(set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)))
        vuln = bool(hits)
        ev = ("recoverable from history: " +
              ", ".join(f"{k} x{v}" for k, v in hits.items()) if hits else
              "no credential material in history") + f"; {len(emails)} distinct e-mail(s)"
        return _verdict(
            "git-history-leak", "Secrets recoverable from git history", vuln, ev,
            "Removed credentials persist in the object store; a clone recovers them even "
            "though the working tree is clean.",
            "Rewrite history (filter-repo/BFG) and rotate anything that was ever committed.",
            "Medium" if vuln else None,
            extra={"secret_kinds": hits, "distinct_emails": len(emails)})
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


def probe_constraint_logic(h, endpoint, params, impossible, verify, *,
                           method="POST", baseline=None, max_models=8,
                           vid="constraint-logic"):
    """Solve for an input that breaks a stated business-logic invariant, then confirm it.

    Rather than one hand-written tampering probe per logic bug, model the operation's numeric
    parameters as SMT variables and ask the solver (z3) for an assignment that satisfies a
    predicate the server is supposed to make impossible (negative total, >100% discount,
    negative stock, ...). Send that assignment and confirm by EFFECT ON STATE that the
    forbidden outcome actually happened -- the status code alone never decides.

    h           an Http client; uses h.req(path, method=, data=) -> {code, body, headers, error}.
    params      {name: (lo, hi)} integer domain for each parameter.
    impossible  callable(sym) -> z3 BoolRef: the "must never happen" state over the symbols.
    verify      callable(chosen, response) -> bool: True only if the server truly produced the
                forbidden outcome (response is the dict returned by h.req).
    baseline    optional legitimate param dict (control); if given it must be accepted, else
                the endpoint is not being exercised and the result is inconclusive.

    Clean is never claimed from an unsearched model: an unsatisfiable predicate, a rejected
    candidate, or a transport failure yields inconclusive, not a false "safe".
    """
    try:
        import z3
    except Exception:
        return _verdict(vid, "Business-logic invariant violated", False,
                        "z3 unavailable - cannot solve for a violating input",
                        "", "", None,
                        extra={"inconclusive": True,
                               "inconclusive_reason": "z3 not installed"})

    def _send(values):
        return h.req(endpoint, method=method, data=values)

    # Control: a legitimate request must work, or the endpoint is not exercised at all.
    if baseline is not None:
        c = _send(baseline)
        if c.get("error"):
            return _verdict(vid, "Business-logic invariant violated", False,
                            "control request failed (transport)", "", "", None,
                            extra={"inconclusive": True,
                                   "inconclusive_reason": "control transport failure"})
        if c["code"] >= 500:
            return _verdict(vid, "Business-logic invariant violated", False,
                            "control request unhealthy (%s)" % c["code"], "", "", None,
                            extra={"inconclusive": True,
                                   "inconclusive_reason": "control request unhealthy"})

    syms = {n: z3.Int(n) for n in params}
    s = z3.Solver()
    for n, (lo, hi) in params.items():
        s.add(syms[n] >= lo, syms[n] <= hi)
    s.add(impossible(syms))
    if s.check() != z3.sat:
        return _verdict(vid, "Business-logic invariant violated", False,
                        "no input in the model satisfies the impossible-state predicate",
                        "", "", None,
                        extra={"inconclusive": True,
                               "inconclusive_reason": "model unsatisfiable"})

    tried = []
    for _ in range(max_models):
        if s.check() != z3.sat:
            break
        m = s.model()
        chosen = {n: int(m.evaluate(syms[n], model_completion=True).as_long()) for n in params}
        s.add(z3.Or([syms[n] != chosen[n] for n in params]))
        r = _send(chosen)
        if r.get("error"):
            continue
        tried.append(chosen)
        if r["code"] < 400 and verify(chosen, r):
            return _verdict(
                vid, "Business-logic invariant violated", True,
                "a solved input the server should reject was accepted and reached the "
                "forbidden state",
                "params=%s were accepted (HTTP %s) and the response confirms the outcome the "
                "invariant forbids. Judged on effect, not status." % (chosen, r["code"]),
                "Enforce the invariant server-side; never let client-supplied values decide "
                "the outcome.",
                "High",
                extra={"chosen": chosen, "response_code": r["code"],
                       "models_tried": len(tried)})
    return _verdict(vid, "Business-logic invariant violated", False,
                    "solver produced %d violating candidate(s); the server reached the "
                    "forbidden state on none of them" % len(tried),
                    "", "", None,
                    extra={"inconclusive": True,
                           "inconclusive_reason": "no candidate confirmed",
                           "models_tried": len(tried)})


# Credential-bearing response field names. Detected BY NAME because their values are often
# short-lived tokens with no recognisable provider format -- GitHub's `temp_clone_token`
# ("ATPC...") matches no value pattern, and the JSON `"field":"value"` shape defeats the
# name= assignment regex, so a value-shaped scanner misses them entirely. Born from a live
# finding: an open proxy returned `temp_clone_token` to anonymous callers, granting git-clone
# of a private repo. The value is never reported -- only the kind.
CREDENTIAL_FIELDS = {
    "temp_clone_token": "GitHub temporary clone token (grants git clone of the repo)",
    "clone_token": "repository clone token",
    "access_token": "OAuth access token",
    "refresh_token": "OAuth refresh token",
    "id_token": "OpenID id token",
    "download_token": "download token",
    "session_token": "session token",
    "client_secret": "OAuth client secret",
    "private_key": "private key",
    "signed_url": "pre-signed URL (carries a credential)",
    "presigned_url": "pre-signed URL (carries a credential)",
    "x-amz-security-token": "AWS session token",
}


def _concrete_secret(v):
    """True only for a concrete, non-placeholder secret value (avoids flagging examples)."""
    if not isinstance(v, str):
        return False
    s = v.strip()
    if len(s) < 8:
        return False
    low = s.lower()
    for p in ("your", "xxxx", "placeholder", "example", "changeme", "todo", "redacted",
              "dummy", "sample", "secret_here", "<", "***", "none", "null"):
        if p in low:
            return False
    return len(set(s)) >= 4


def probe_double_spend(h, state_endpoint, action_path, state_field, action_body=None,
                       *, method="POST", vid="double-spend"):
    """Business-logic, STATEFUL: does a ONE-TIME action replay its effect when repeated?

    A one-time action -- apply a coupon, claim a credit, redeem a code, post a refund -- must
    change the observed state ONCE. This reads a state quantity, applies the action, reads it
    again, then applies the SAME action a second time and reads once more. If the second
    application moves the state by substantially the same amount as the first, the server failed
    to make the one-time effect idempotent: it is double-spendable / coupon-reusable / replayable.

    Unlike a single-request constraint check this is a SEQUENCE invariant -- the bug only exists
    across two calls, so no single request reveals it. Destructive and stateful (gated at the
    CLI); both applications share one session so they act as the same principal. Reports the
    deltas, never a secret. state_field is the observable numeric quantity to watch (balance,
    discount_total, points...)."""
    name = "Double-spend / one-time-effect replay"

    def _read():
        r = h.req(state_endpoint)
        if r.get("error") or r.get("code", 0) == 0:
            return None, True
        try:
            return float(json.loads(r["body"]).get(state_field)), False
        except (TypeError, ValueError, AttributeError):
            return None, False

    baseline, transport = _read()
    if baseline is None:
        if transport:
            return _verdict(vid, name, False, "could not read the state endpoint (transport)",
                            "", "", None, extra={"inconclusive": True,
                            "inconclusive_reason": "state endpoint unreachable"})
        return _verdict(vid, name, False,
                        "state field '%s' is not a readable number; cannot measure replay"
                        % state_field, "", "", None)

    a1 = h.req(action_path, method, action_body)
    if a1.get("error") or a1.get("code", 0) == 0:
        return _verdict(vid, name, False, "the first action request did not complete",
                        "", "", None, extra={"inconclusive": True,
                        "inconclusive_reason": "action request failed (transport)"})
    after1, _ = _read()
    if after1 is None:
        return _verdict(vid, name, False, "could not re-read the state after the first action",
                        "", "", None, extra={"inconclusive": True,
                        "inconclusive_reason": "state unreadable after first action"})
    delta1 = after1 - baseline
    if abs(delta1) < 1e-9:
        return _verdict(vid, name, False,
                        "the action had no measurable effect on '%s'; nothing to replay"
                        % state_field, "", "", None)

    a2 = h.req(action_path, method, action_body)
    after2, _ = _read()
    if after2 is None:
        return _verdict(vid, name, False, "could not re-read the state after the second action",
                        "", "", None, extra={"inconclusive": True,
                        "inconclusive_reason": "state unreadable after second action"})
    delta2 = after2 - after1

    # A one-time action must be idempotent: the second application should be a no-op.
    if delta2 != 0 and (delta1 > 0) == (delta2 > 0) and abs(delta2) >= 0.5 * abs(delta1):
        money = any(k in state_field.lower() for k in
                    ("balance", "credit", "coupon", "discount", "points", "total",
                     "refund", "wallet", "cash", "amount", "payout"))
        return _verdict(
            vid, name, True,
            "repeating a one-time action replayed its effect: '%s' moved %+g, then %+g again on "
            "the identical second call (returned HTTP %s, not rejected). The one-time effect is "
            "double-spendable / replayable." % (state_field, delta1, delta2, a2.get("code")),
            "A one-time action (apply a coupon, claim a credit, redeem a code) was not made "
            "idempotent, so an identical second request produced the same state change again. "
            "This is a sequence invariant: it exists only across two calls, so a single-request "
            "scanner cannot see it.",
            "Make the one-time effect idempotent server-side: key it to a single-use nonce or "
            "the order/claim id, enforce a uniqueness constraint so a second application cannot "
            "commit, and derive the amount from stored state rather than from the request.",
            "Critical" if money else "High",
            extra={"state_endpoint": state_endpoint, "action_path": action_path,
                   "state_field": state_field, "delta_first": delta1, "delta_second": delta2})
    return _verdict(
        vid, name, False,
        "the second application was a no-op: '%s' moved %+g then %+g (the repeat returned HTTP "
        "%s). Replay prevented." % (state_field, delta1, delta2, a2.get("code")),
        "", "", None)


def probe_race_consume(h, state_endpoint, action_path, state_field, unit,
                       action_body=None, *, method="POST", n=8, cookie=None,
                       vid="race-consume"):
    """Business-logic, CONCURRENT: fire n identical requests at a single-use operation IN
    PARALLEL and judge by the ACTUAL state delta.

    This is the concurrent twin of probe_double_spend. A single-use resource -- a one-time
    credit, a quota of one, a unique redemption code -- must move the observed state by exactly
    ONE unit no matter how many requests race for it. probe_race counts a success marker in the
    response bodies; this measures the effect on state, which is the ground truth: a body can
    say "credited" when the ledger moved once, or stay silent when it moved many times. If the
    state moved by more than one unit, the check-then-act was not atomic and the race was won
    (TOCTOU). `unit` is the state change ONE legitimate success produces, so the probe can turn
    the total delta into a count of consumptions. Destructive and stateful (gated at the CLI).
    Reports the delta and the count, never a secret."""
    name = "Race condition / single-use over-consumption (TOCTOU)"
    hdr = {"Cookie": cookie} if cookie else {}

    def _read():
        r = h.req(state_endpoint, headers=hdr)
        if r.get("error") or r.get("code", 0) == 0:
            return None, True
        try:
            return float(json.loads(r["body"]).get(state_field)), False
        except (TypeError, ValueError, AttributeError):
            return None, False

    if not unit:
        return _verdict(vid, name, False,
                        "a non-zero 'unit' (the state change one success produces) is required "
                        "to count consumptions", "", "", None,
                        extra={"inconclusive": True, "inconclusive_reason": "no unit supplied"})
    baseline, transport = _read()
    if baseline is None:
        if transport:
            return _verdict(vid, name, False, "could not read the state endpoint (transport)",
                            "", "", None, extra={"inconclusive": True,
                            "inconclusive_reason": "state endpoint unreachable"})
        return _verdict(vid, name, False,
                        "state field '%s' is not a readable number; cannot measure the race"
                        % state_field, "", "", None)

    # Fire n identical requests CONCURRENTLY at the single-use operation. throttle=False so the
    # rate limiter does not serialise them back into a sequence and hide the race.
    def one():
        h.req(action_path, method, action_body, headers=hdr, throttle=False)
    ts = [threading.Thread(target=one) for _ in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    after, _ = _read()
    if after is None:
        return _verdict(vid, name, False, "could not re-read the state after the burst",
                        "", "", None, extra={"inconclusive": True,
                        "inconclusive_reason": "state unreadable after burst"})
    delta = after - baseline
    successes = int(round(delta / unit))
    if successes >= 2:
        money = any(k in state_field.lower() for k in
                    ("balance", "credit", "coupon", "discount", "points", "total",
                     "refund", "wallet", "cash", "amount", "payout", "quota"))
        return _verdict(
            vid, name, True,
            "%d concurrent requests moved '%s' by %+g -- about %d consumptions of a single-use "
            "resource (one unit = %+g). The check-then-act was not atomic, so the race was won "
            "%d times." % (n, state_field, delta, successes, unit, successes),
            "The single-use guard is a check followed by a separate commit with a window between "
            "them. Concurrent requests all pass the check before any commits, so the one-time "
            "effect fires once per racer. Judged by the effect on state, not by the response "
            "bodies, which can misreport success in either direction.",
            "Make the operation atomic: a conditional UPDATE with the guard in the WHERE clause, "
            "a UNIQUE constraint, SELECT ... FOR UPDATE, or a serialisable transaction. An "
            "application-level lock does not survive multiple workers or processes.",
            "Critical" if money else "High",
            extra={"state_endpoint": state_endpoint, "action_path": action_path,
                   "state_field": state_field, "delta": delta, "unit": unit,
                   "successes": successes, "concurrent": n})
    return _verdict(
        vid, name, False,
        "%d concurrent requests moved '%s' by %+g (%d consumption(s) of a single-use resource, "
        "one unit = %+g). The guard held under concurrency."
        % (n, state_field, delta, max(successes, 0), unit),
        "", "", None)


def probe_response_credential_leak(h, endpoint, method="GET", body=None, vid="response-credential-leak"):
    """Detect a usable credential embedded in an endpoint's response.

    Some endpoints return a credential the caller can immediately reuse -- GitHub's
    `temp_clone_token` (grants git-clone), OAuth access/refresh tokens, pre-signed URLs, client
    secrets. These are detected by FIELD NAME as well as by value shape, because short-lived
    tokens often have no recognisable provider format and a value-only scanner misses them.

    The request is made anonymously (no cookie): a credential handed back to an unauthenticated
    caller is the clear leak. Only a concrete, non-placeholder value counts, and the value itself
    is never reproduced -- only the kind. A token-issuing endpoint (e.g. /login) legitimately
    returns a token to a caller who just authenticated; that is why this is pointed at data and
    proxy endpoints, and why the report names the kind for a human to judge.
    """
    r = h.req(endpoint, method=method, data=body)
    if r.get("error"):
        return _verdict(vid, "Credential embedded in response", False,
                        "the request did not complete (%s)" % r["error"], "", "", None,
                        extra={"inconclusive": True, "inconclusive_reason": "transport failure"})
    if r["code"] == 0 or r["code"] >= 400:
        return _verdict(vid, "Credential embedded in response", False,
                        "endpoint returned HTTP %s; no body to inspect" % r["code"], "", "", None,
                        extra={"inconclusive": True,
                               "inconclusive_reason": "no successful response to inspect"})
    text = r.get("body") or ""
    kinds = set()
    try:
        data = json.loads(text)
    except Exception:
        data = None

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if str(k).lower() in CREDENTIAL_FIELDS and _concrete_secret(v):
                    kinds.add(CREDENTIAL_FIELDS[str(k).lower()])
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)
    if data is not None:
        walk(data)
    for pat, desc in SECRET_VALUES:
        if re.search(pat, text):
            kinds.add(desc)

    kinds = sorted(kinds)
    vuln = bool(kinds)
    grants = any(("clone" in k.lower() or "access token" in k.lower() or "refresh" in k.lower()
                  or "private key" in k.lower() or "security token" in k.lower()) for k in kinds)
    ev = ("response to an unauthenticated request embeds credential material: " + ", ".join(kinds)) \
        if vuln else "no credential material in the response"
    return _verdict(
        vid, "Credential embedded in response", vuln, ev,
        "The endpoint returned a credential the caller can reuse. Detected by field name and "
        "value shape; the value itself is never reproduced.",
        "Never return a credential (clone token, access token, signed URL, key) in a response "
        "body to an unauthenticated caller. If a token must be issued, scope it tightly, bind it "
        "to the session, and expire it fast.",
        ("Critical" if grants else "High") if vuln else None,
        extra={"credential_kinds": kinds, "count": len(kinds)})
