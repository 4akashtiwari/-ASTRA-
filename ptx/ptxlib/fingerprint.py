"""Technology + version fingerprinting, feeding the live CVE pipeline.

recon.http() already notes server identity and body hints, but it does not pull VERSIONS out
of them or correlate anything with a vulnerability database. This layer turns an HTTP response
into (product, version, ecosystem) tuples and hands the ones with a known package ecosystem to
cve.query() -- a LIVE OSV.dev lookup, never model memory.

Two rules carry over from cve.py and matter just as much here:

  * Detection is deterministic and offline. Given the same headers and body it returns the same
    components, so it can be tested without a network and trusted not to drift.
  * A fingerprint is a LEAD, not a finding. A CVE on a component the application never reaches
    is not exploitable; reachability is a separate assessment (see cmd_cve_reach). This module
    reports what is present and what OSV says about that version, and stops there.

Confidence is recorded per component because the evidence is not uniform: a versioned JS file
the server actually served is strong, a `Server:` header is weak (trivially stripped or faked),
and a generator meta tag is somewhere between.
"""

import re

# "name/version" tokens inside a header value: nginx/1.25.3, Werkzeug/2.3.7 Python/3.11.4.
_HEADER_TOKEN = re.compile(r"([A-Za-z][A-Za-z0-9._+-]*)/(\d[\w.\-]*)")

# Common client-side libraries, as (pattern, npm package name). The version is captured from a
# CDN filename, an @-pin, or a "Lib vX.Y.Z" banner. Curated like retire.js -- add entries as
# new libraries turn up; an unknown library is simply not detected rather than misdetected.
_JS_LIBS = [
    (r"jquery[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "jquery"),
    (r"jquery-migrate[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "jquery-migrate"),
    (r"jquery[.-]ui[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "jquery-ui"),
    (r"lodash[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "lodash"),
    (r"bootstrap[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "bootstrap"),
    (r"react-dom[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "react-dom"),
    (r"react[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "react"),
    (r"vue[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "vue"),
    (r"ng-version=[\"']?(\d+\.\d+\.\d+)", "@angular/core"),
    (r"angular[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "@angular/core"),
    (r"moment[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "moment"),
    (r"axios[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "axios"),
    (r"underscore[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "underscore"),
    (r"backbone[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "backbone"),
    (r"handlebars[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "handlebars"),
    (r"ember[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "ember-source"),
    (r"alpinejs[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "alpinejs"),
    (r"htmx[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "htmx.org"),
    (r"three[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "three"),
    (r"d3[\s./@-]{0,2}v?(\d+\.\d+\.\d+)", "d3"),
]
_JS_LIBS = [(re.compile(p, re.I), name) for p, name in _JS_LIBS]

# Products whose name maps to a package OSV knows. Anything not here is still reported as a
# detected component, but with ecosystem None -- nginx/apache/php have no OSV ecosystem, so the
# operator is pointed at vendor advisories instead of being given a false "clean".
_PRODUCT_ECOSYSTEM = {
    "werkzeug": "PyPI", "gunicorn": "PyPI", "django": "PyPI", "flask": "PyPI",
    "jinja2": "PyPI", "tornado": "PyPI", "uvicorn": "PyPI",
    "express": "npm", "next": "npm", "next.js": "npm", "nuxt": "npm", "react": "npm",
    "vue": "npm", "lodash": "npm", "jquery": "npm",
}

_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=[\"\']?generator[\"\']?[^>]+content=[\"\']?([^\"\'>]+)', re.I)


def _parse_header_products(value):
    """Yield (product, version) for every name/version token in a header value."""
    for m in _HEADER_TOKEN.finditer(value or ""):
        yield m.group(1), m.group(2)


def detect(headers, body):
    """Return detected components as a list of dicts, each with product, version (or None),
    ecosystem (or None), source, and confidence. Deterministic; no network."""
    out = []
    seen = set()

    def add(product, version, source, confidence, ecosystem=None):
        key = (product.lower(), version)
        if key in seen:
            return
        seen.add(key)
        eco = ecosystem or _PRODUCT_ECOSYSTEM.get(product.lower())
        out.append({"product": product, "version": version, "ecosystem": eco,
                    "source": source, "confidence": confidence})

    h = {k.lower(): v for k, v in (headers or {}).items()}
    # A versioned header token is MEDIUM confidence: headers are trivially stripped or faked,
    # but a real one is cheap, strong evidence of the running version.
    for hdr in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                "x-generator", "x-runtime"):
        val = h.get(hdr)
        if not val:
            continue
        if hdr in ("x-aspnet-version", "x-aspnetmvc-version"):
            add("ASP.NET", val.strip(), "header:" + hdr, "MEDIUM")
            continue
        for product, version in _parse_header_products(val):
            add(product, version, "header:" + hdr, "MEDIUM")

    body = body or ""
    # Generator meta tag: "WordPress 6.4.2", "Hugo 0.120.4".
    gm = _GENERATOR_RE.search(body)
    if gm:
        content = gm.group(1).strip()
        parts = content.split()
        product = parts[0] if parts else content
        version = parts[1] if len(parts) > 1 and re.match(r"\d", parts[1]) else None
        add(product, version, "meta:generator", "MEDIUM")

    # Client-side libraries, by versioned filename / @-pin / banner. HIGH confidence: the file
    # is actually being served, so the version is real rather than advertised.
    for pat, name in _JS_LIBS:
        m = pat.search(body)
        if m:
            add(name, m.group(1), "body:js-lib", "HIGH", ecosystem="npm")

    return out


def enrich(components, query_fn=None, timeout=30):
    """Correlate detected components with OSV.dev via cve.query (injectable for tests).

    Only components with BOTH an ecosystem and a version are queried -- OSV needs both. A
    component with no ecosystem mapping is skipped here and surfaced by the caller as
    "check vendor advisories", never silently passed over as clean.
    """
    if query_fn is None:
        from ptxlib import cve
        query_fn = cve.query
    results = []
    for c in components:
        if not (c.get("ecosystem") and c.get("version")):
            continue
        try:
            r = query_fn(c["product"], c["ecosystem"], c["version"], timeout=timeout)
        except Exception as e:                                    # CVEError or transport
            results.append(dict(c, error=str(e)))
            continue
        counts = r.get("counts", {})
        cves = sorted({x for v in r.get("vulns", []) for x in v.get("cves", [])})
        results.append(dict(c, advisories=counts, cves=cves))
    return results
