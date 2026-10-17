"""Attack-surface discovery: which endpoints exist, established by measurement.

The naive version of this tool compares each response against a hardcoded idea of what
"404" looks like. That fails in the direction that matters: plenty of applications answer
every unmatched route with HTTP 200 and an HTML error page, so a name-based or
status-based check reports the entire wordlist as discovered. That is not a noisy
result, it is a useless one — and it is the same fault as a probe that embeds its
answer.

So the not-found signature is measured first, from the target itself, using paths that
cannot exist. A candidate counts as discovered only when its response differs from that
signature in a way a client could observe: a different status, a materially different
length, or a redirect.

Three candidate sources, in order of how much they are worth:

  1. Paths the application itself references — href/src/action attributes and the
     string literals in its JavaScript. This is not guessing; the app is telling us.
  2. Paths derived from what we already found. `/api/notes` implies `/api/notes/1`.
  3. A small built-in list of common paths. The weakest source, and it is deliberately
     small: a big wordlist against a target that soft-404s produces noise, not findings.
"""

import html
import re
import time
import urllib.parse

# Deliberately small. A large wordlist is only useful once the not-found baseline is
# trustworthy, and against a soft-404 target it mostly measures how many ways the
# application can say "no".
COMMON_PATHS = (
    "/", "/index.html", "/robots.txt", "/sitemap.xml", "/security.txt",
    "/.well-known/security.txt", "/.env", "/.git/config", "/.git/HEAD",
    "/config.json", "/config.js", "/api", "/api/", "/api/v1", "/api/health",
    "/health", "/healthz", "/status", "/metrics", "/debug", "/debug/vars",
    "/admin", "/admin/", "/login", "/logout", "/signup", "/register", "/auth",
    "/oauth", "/.well-known/openid-configuration", "/swagger.json",
    "/openapi.json", "/api/docs", "/docs", "/graphql", "/actuator",
    "/actuator/env", "/server-status", "/.DS_Store", "/backup.zip", "/db.sqlite3",
    "/static/", "/assets/", "/uploads/", "/wp-login.php", "/phpinfo.php",
    "/console", "/trace", "/info", "/version", "/favicon.ico",
)

# Methods worth asking about on a path we know exists. OPTIONS is cheap and often
# answers with an Allow header the application never meant to publish.
INTERESTING_METHODS = ("OPTIONS", "POST", "PUT", "DELETE", "PATCH")

_TAG_PATH = re.compile(
    r"""(?:href|src|action|data-url|data-href|formaction)\s*=\s*["']([^"']+)["']""", re.I)
# String literals in JS that look like paths or endpoints. Bounded, because an
# unanchored regex over a minified bundle is how a scanner hangs.
_JS_PATH = re.compile(r"""["'`](/(?:[A-Za-z0-9_.\-]+/?){1,6})["'`]""")
_FETCH = re.compile(r"""(?:fetch|axios|xhr\.open|url\s*:)\s*\(?\s*["'`]([^"'`]+)["'`]""", re.I)

# Template literals: `/api/users/${id}/posts`. The interpolated part is not a literal
# path segment, but the static prefix IS a real route prefix and worth requesting.
# Missing these means every modern SPA's API surface is invisible to the scan.
_TEMPLATE_PATH = re.compile(r"""`(/(?:[A-Za-z0-9_.\-]+/)+)\$\{""")

# Route tables in SPA source: `path: "/admin"`, `to: "/x"`, `href: "/y"`,
# `component: ... route: "/z"`. These are declarations, so they name pages the HTML
# never links to -- exactly the ones a crawl misses.
_ROUTE_DECL = re.compile(
    r"""(?:path|to|route|redirect|href|url)\s*:\s*["'`](/[^"'`]*)["'`]""", re.I)

# Query parameters, from either a literal URL or a params object. Parsing JS is worth
# doing for the parameters at least as much as for the paths: a path tells you where
# to point a probe, a parameter tells you what to point it at.
_QUERY_PARAM = re.compile(r"""[?&]([A-Za-z_][A-Za-z0-9_]{0,40})=""")
_PARAMS_OBJ = re.compile(
    r"""(?:params|query|body|data|payload)\s*:\s*\{([^}]{0,400})\}""", re.I)
_KEY_IN_OBJ = re.compile(r"""([A-Za-z_][A-Za-z0-9_]{0,40})\s*:""")


def canary_path(prefix="ptx-nonexistent"):
    """A path that cannot exist, used to measure the not-found signature."""
    return "/%s-%d" % (prefix, int(time.time() * 1000000) % 10**12)


def _signature(code, body):
    """What a client can actually observe about a response, reduced to a tuple."""
    return (code, len(body or ""))


def measure_baseline(h, n=3):
    """Ask the target what 'not found' looks like, n times.

    Returns a dict with the observed signatures and whether the target is consistent.
    A target that answers random paths differently each time cannot be baselined, and
    saying so is more useful than pretending every difference is a discovery.
    """
    samples, failures = [], 0
    for _ in range(n):
        r = h.req(canary_path())
        if r.get("error"):
            failures += 1
            continue
        samples.append({"code": r["code"], "length": len(r["body"]),
                        "ctype": (r.get("headers") or {}).get("Content-Type", "")})
    if not samples:
        return {"signatures": [], "consistent": False, "soft_404": False,
                "measured": 0, "failures": failures,
                "note": "the baseline could not be measured: every request failed"}
    codes = {s["code"] for s in samples}
    lengths = {s["length"] for s in samples}
    return {
        "signatures": [tuple(sorted({_signature(s["code"], "x" * s["length"])}))
                       for s in samples],
        "codes": sorted(codes),
        "lengths": sorted(lengths),
        # Every random path answered 200: this target soft-404s, and length is the
        # only signal left. Worth surfacing, because it changes what "found" means.
        "soft_404": codes == {200},
        "consistent": len(codes) == 1 and len(lengths) <= 1,
        "measured": len(samples),
        "failures": failures,
        "note": "",
    }


def looks_found(r, base):
    """Does this response differ from the not-found baseline in an observable way?

    Status first, then length, then redirect. A redirect is always interesting: the
    application knew about the path well enough to send us somewhere else.
    """
    if r.get("error"):
        return False, "request failed"
    code = r["code"]
    body = r["body"] or ""
    if code in (301, 302, 303, 307, 308):
        return True, "redirect -> %s" % ((r.get("headers") or {}).get("Location", "?"))
    base_codes = set(base.get("codes") or [])
    base_lengths = set(base.get("lengths") or [])
    if base_codes and code not in base_codes:
        return True, "HTTP %s where not-found answered %s" % (
            code, "/".join(str(c) for c in sorted(base_codes)))
    # Same status: fall back to length. A 200 error page and a 200 real page differ in
    # size. The tolerance keeps trivial template jitter (a timestamp, a nonce) from
    # counting as a discovery.
    if base_lengths:
        nearest = min(base_lengths, key=lambda n: abs(n - len(body)))
        if abs(len(body) - nearest) > max(24, nearest * 0.05):
            return True, "HTTP %s but %d bytes against a %d-byte not-found page" % (
                code, len(body), nearest)
    if not base_codes:
        return False, "no baseline to compare against"
    return False, "indistinguishable from the not-found response"


def extract_params(body):
    """Pull the parameter names a document mentions.

    A path says where to point a probe; a parameter says what to point it at. Both come
    out of the same JavaScript, and only reading the paths throws half of it away.
    """
    found = set(_QUERY_PARAM.findall(body or ""))
    for inner in _PARAMS_OBJ.findall(body or ""):
        found.update(_KEY_IN_OBJ.findall(inner))
    # Names a minifier would never produce, and that no real application uses.
    junk = {"id", "e", "t", "n", "o", "a", "r", "i", "s", "l", "c", "d", "u", "p", "f",
            "h", "m", "g", "v", "b", "y", "w", "k", "x", "j", "z", "q"}
    return sorted(p for p in found if p.lower() not in junk and len(p) > 1)


def extract_paths(body, base_url=""):
    """Pull every path the application references out of an HTML or JS document.

    Off-host absolute URLs are dropped: following them would take the scan outside the
    engagement's scope, and a scanner that wanders onto a third party is a scanner
    that gets someone's engagement cancelled.
    """
    found = set()
    for m in _TAG_PATH.finditer(body or ""):
        found.add(m.group(1))
    for m in _JS_PATH.finditer(body or ""):
        found.add(m.group(1))
    for m in _FETCH.finditer(body or ""):
        found.add(m.group(1))
    # Template literals: keep the static prefix, which is a real route prefix.
    for m in _TEMPLATE_PATH.finditer(body or ""):
        found.add(m.group(1))
    # SPA route declarations name pages the HTML never links to.
    for m in _ROUTE_DECL.finditer(body or ""):
        found.add(m.group(1))
    out = set()
    for raw in found:
        raw = html.unescape(raw).strip()
        # A template expression is not a path segment. `/api/users/${id}` is worth
        # requesting as `/api/users/`, and worth nothing at all as a literal string
        # containing `${id}` -- requesting that would be a request to a route that
        # cannot exist, and it would pollute the discovered list.
        if "${" in raw:
            raw = raw.split("${", 1)[0]
        # Query strings are mined for parameters separately; the path itself is what
        # gets requested.
        raw = raw.split("?", 1)[0]
        if not raw or raw.startswith(("#", "mailto:", "javascript:", "data:", "tel:")):
            continue
        parsed = urllib.parse.urlparse(raw)
        if parsed.scheme in ("http", "https"):
            host = (parsed.netloc or "").split("@")[-1].split(":")[0].lower()
            origin = (urllib.parse.urlparse(base_url).netloc or "").split(":")[0].lower()
            if origin and host != origin:
                continue          # off-host: out of scope, do not touch
            raw = parsed.path or "/"
        elif parsed.scheme:
            continue              # some other scheme we should not be requesting
        path = raw.split("#", 1)[0]
        if not path.startswith("/"):
            continue
        out.add(path or "/")
    return out


def derive_paths(seen):
    """From what we have already found, infer what else is likely to exist.

    `/api/notes` implies an item route. This is the cheapest high-value source after
    the application's own references, and it costs one request each.
    """
    out = set()
    for p in seen:
        p = p.rstrip("/")
        if not p or p.count("/") < 2:
            continue
        out.add(p + "/1")
        out.add(p + "/0")
        out.add(p + "/")
    return out


def probe_methods(h, path):
    """Ask which methods a known path accepts. Only reports what the server said."""
    answered = {}
    for m in INTERESTING_METHODS:
        r = h.req(path, m, data={} if m in ("POST", "PUT", "PATCH") else None)
        if r.get("error"):
            answered[m] = "unreachable"
            continue
        allow = (r.get("headers") or {}).get("Allow")
        answered[m] = {"code": r["code"], "allow": allow}
    return answered


def scan(h, start=("/",), wordlist=None, limit=250, depth=2, methods=False):
    """Discover the attack surface. Returns a dict, never a bare list.

    `results` carries the paths that were distinguishable from not-found. `checked`
    records every path requested and why it was or was not kept, so a reader can tell
    "we looked and found nothing" apart from "we never looked".
    """
    base = measure_baseline(h)
    if base["measured"] == 0:
        return {"baseline": base, "results": [], "checked": [],
                "unmeasured": True,
                "note": "the target could not be reached, so nothing was discovered. "
                        "This is not an empty attack surface."}

    queue, seen, checked, results = [], set(), [], []
    for p in start:
        queue.append((p, 0, "start"))
    for p in (wordlist if wordlist is not None else COMMON_PATHS):
        queue.append((p, 0, "wordlist"))

    while queue and len(checked) < limit:
        path, lvl, source = queue.pop(0)
        path = path.split("?", 1)[0]
        if path in seen:
            continue
        seen.add(path)
        r = h.req(path)
        found, why = looks_found(r, base)
        rec = {"path": path, "source": source, "code": r["code"],
               "length": len(r["body"] or ""), "found": found, "why": why,
               "error": r.get("error")}
        checked.append(rec)
        if not found:
            continue
        entry = dict(rec)
        # Retained only for discovered pages, and capped: a bundle can be megabytes and
        # the scan result is meant to be read, not stored.
        entry["body_text"] = (r["body"] or "")[:20000]
        if lvl < depth:
            for child in sorted(extract_paths(r["body"], h.base)):
                if child not in seen:
                    queue.append((child, lvl + 1, "referenced-by:" + path))
            for child in sorted(derive_paths({path})):
                if child not in seen:
                    queue.append((child, lvl + 1, "derived-from:" + path))
        if methods:
            entry["methods"] = probe_methods(h, path)
        results.append(entry)

    params = sorted({p for e in results for p in extract_params(e.get("body_text", ""))})
    return {"baseline": base, "results": results, "checked": checked,
            "unmeasured": False, "note": "", "parameters": params,
            "requests": len(checked) + base["measured"]}


def summarise(res):
    """A short human-readable summary. Kept separate so the CLI and the report agree."""
    if res.get("unmeasured"):
        return ["UNMEASURED: " + res.get("note", "the target could not be reached")]
    b = res["baseline"]
    lines = [
        "baseline: not-found answered %s (%s), soft-404=%s, consistent=%s" % (
            "/".join(str(c) for c in b.get("codes") or []),
            "/".join(str(n) for n in b.get("lengths") or []),
            b.get("soft_404"), b.get("consistent")),
        "discovered %d of %d paths checked" % (len(res["results"]), len(res["checked"])),
    ]
    if b.get("soft_404") and not b.get("consistent"):
        lines.append("WARNING: this target answers unknown paths inconsistently, so "
                     "length is the only signal and the results below are approximate")
    for e in sorted(res["results"], key=lambda x: x["path"]):
        lines.append("  %-38s HTTP %-4s %6db  (%s)" % (
            e["path"], e["code"], e["length"], e["why"]))
    if res.get("parameters"):
        lines.append("parameters named in those responses: %s"
                     % ", ".join(res["parameters"][:40]))
    return lines
