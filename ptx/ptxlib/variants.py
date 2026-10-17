"""
Variant analysis — from one confirmed fault, sweep the same pattern across siblings.

A scanner reports each finding in isolation, as if vulnerabilities were independent
events. They are not. They cluster: the developer who left one endpoint unsanitised
usually left its siblings the same way, because the siblings were written the same way —
often copy-pasted from the same snippet, the same framework idiom, the same author's
habit. So the moment one SQL injection is confirmed, the useful question stops being
"is this endpoint vulnerable?" and becomes "which OTHER endpoints share this fault?"

This module reasons along the axis the fault revealed rather than broadly. Given a
confirmed finding's CLASS and where it was confirmed (the seed), it re-runs that exact
probe across every comparable (endpoint, parameter) the target exposes and partitions
the results into: the seed (re-confirmed), NEW variants (siblings that share the flaw),
clean siblings, and endpoints that errored. Finding one is the trigger; the sweep is the
work. A "seed only, siblings clean" result is a real finding too — it bounds the issue
instead of leaving the reader to wonder whether anyone looked.

Only classes whose probe takes (h, path, param) can be swept this way; those are the
injection families. Business-logic and stateful classes are deliberately excluded — a
double-spend has no meaningful "sibling endpoint" to sweep, and pretending otherwise
would produce noise.
"""
from . import probes, discover

# Probe classes that take (h, path, param) and so can be swept across endpoints/params.
# Each maps to a callable (h, path, param) -> verdict dict. ssrf/traversal need a canary
# and a payload respectively; the defaults are the conventional ones (cloud metadata for
# ssrf, /etc/passwd + "root:" for traversal) so a sweep needs no extra setup.
VARIANT_PROBES = {
    "sqli":      lambda h, p, q: probes.probe_sqli(h, p, q),
    "xss":       lambda h, p, q: probes.probe_xss(h, p, q),
    "cmdi":      lambda h, p, q: probes.probe_cmdi(h, p, q),
    "redirect":  lambda h, p, q: probes.probe_redirect(h, p, q),
    "ssrf":      lambda h, p, q: probes.probe_ssrf(h, p, q, "http://169.254.169.254/latest/meta-data/"),
    "traversal": lambda h, p, q: probes.probe_traversal(h, p, q, "../../../../etc/passwd", "root:"),
}


def supported():
    """The classes that can be swept, for --help and for refusing the ones that can't."""
    return sorted(VARIANT_PROBES)


# Parameter names a backend commonly reads but its own HTML rarely advertises. When an
# endpoint exposes no discoverable param, these are swept instead of a single guess:
# /search?q and /greet?name both inject through params that appear nowhere in the body.
COMMON_PARAMS = ("id", "q", "query", "search", "name", "user", "url", "file",
                 "path", "page", "redirect", "next", "target", "cmd", "email", "lang")


def discover_targets(h, seeds=("/",), limit=60, default_param="id", max_params=10):
    """Build the (endpoint, param) sweep list by crawling the target.

    An endpoint that advertises params (form fields, query strings in links) is swept with
    those. One that advertises none is swept against COMMON_PARAMS rather than a single
    default, because a backend routinely reads a parameter its own HTML never mentions:
    /search?q and /greet?name both reflect and inject through params that appear nowhere
    in the served body, so trusting only advertised params would sweep /search?id and miss
    the injection entirely. default_param is always included. Capped so a large site does
    not turn one confirmed finding into an unbounded scan.
    """
    scan = discover.scan(h, start=seeds, limit=limit)
    if scan.get("unmeasured"):
        return []
    targets, seen = [], set()
    for e in scan.get("results", []):
        path = e["path"]
        advertised = discover.extract_params(e.get("body_text", ""))
        params = [default_param] + (advertised if advertised else list(COMMON_PARAMS))
        for prm in list(dict.fromkeys(params))[:max_params]:
            pair = (path, prm)
            if pair not in seen:
                seen.add(pair)
                targets.append(pair)
    return targets


def sweep(h, klass, targets):
    """Run the class's probe against each (endpoint, param). Never raises: a probe that
    errors on one sibling is recorded as inconclusive for that sibling and the sweep
    continues — one broken endpoint must not blind the rest of the analysis."""
    if klass not in VARIANT_PROBES:
        raise ValueError(f"no variant sweep for class {klass!r}; supported: {supported()}")
    fn = VARIANT_PROBES[klass]
    out = []
    for path, param in targets:
        try:
            v = fn(h, path, param)
        except Exception as e:  # noqa: BLE001 - a sibling error must not abort the sweep
            v = {"id": klass, "name": klass, "vulnerable": False, "inconclusive": True,
                 "evidence": f"probe raised on this endpoint: {e}", "mechanism": "",
                 "teaching": "", "severity": "Info"}
        out.append({"path": path, "param": param, "verdict": v})
    return out


def analyze(h, klass, targets, seed=None):
    """Sweep `targets` for `klass` and partition the results.

    `seed` is the (path, param) where the fault was already confirmed, if known. The seed
    is swept too (to re-confirm it in the same run) but reported separately from the NEW
    variants, because the reader already knows about the seed — the value here is what
    else shares the flaw. Returns a structured report the CLI renders and records.
    """
    results = sweep(h, klass, targets)

    def is_seed(t):
        return bool(seed) and t["path"] == seed[0] and t["param"] == seed[1]

    variants, clean, errored = [], [], []
    for t in results:
        v = t["verdict"]
        if v.get("inconclusive"):
            errored.append(t)
        elif v.get("vulnerable"):
            variants.append(t)
        else:
            clean.append(t)

    seed_result = next((t for t in results if is_seed(t)), None)
    new_variants = [t for t in variants if not is_seed(t)]
    return {
        "class": klass,
        "seed": {"path": seed[0], "param": seed[1]} if seed else None,
        "seed_confirmed": bool(seed_result and seed_result["verdict"].get("vulnerable")),
        "tested": len(results),
        "vulnerable_total": len(variants),
        "new_variants": [{"path": t["path"], "param": t["param"],
                          "evidence": (t["verdict"].get("evidence") or "")[:200]}
                         for t in new_variants],
        "clean": [{"path": t["path"], "param": t["param"]} for t in clean],
        "errored": [{"path": t["path"], "param": t["param"],
                     "evidence": (t["verdict"].get("evidence") or "")[:200]} for t in errored],
        "results": results,
    }
