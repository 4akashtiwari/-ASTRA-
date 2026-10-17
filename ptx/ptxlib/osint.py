"""
OSINT — phase 1. Passive collection, zero packets to the target.

All sources here are live by definition: crt.sh, Wayback CDX, DNS. Nothing is recalled
from memory, so there is no staleness problem in this module.
"""
import json, os, re, socket, subprocess, urllib.request, urllib.error

UA = {"User-Agent": "ptx-osint/1.0 (authorized security assessment)"}


# Passive-source endpoints. Module-level so they can be pointed at a mirror, a corporate
# proxy, or a local fake. Both crt.sh and the Wayback CDX API have never once completed a
# request in this sandbox, which meant the parsing code below — the part where the
# fabricated-DMARC bug lived — was never exercised by anything. Tests now serve canned
# responses from a local server and drive the real functions.
CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
WAYBACK_URL = ("http://web.archive.org/cdx/search/cdx?url={domain}*"
               "&output=text&collapse=urlkey&fl=original&limit={limit}")

def _belongs(name, domain):
    """True if `name` is `domain` itself or a subdomain of it.

    This was `domain in name` — a substring test. That accepted `notacme.test`,
    `evilacme.test.evil.com` and `acme.test.attacker.example` as subdomains of
    `acme.test`. The last one is the dangerous case: a host on infrastructure the target
    does not control, presented to the operator as part of the target's estate and then
    probed. It is the same fault as the scope-exclusion bug — a second, weaker
    implementation of "belongs to this domain" sitting in another module.
    """
    name, domain = name.strip().lower(), domain.strip().lower()
    return name == domain or name.endswith("." + domain)



def save(engagement, name, payload):
    d = os.path.join(engagement, "osint")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, f"{name}.json")
    with open(p, "w") as f:
        json.dump(payload, f, indent=2)
    return p


def _get(url, timeout):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


# --- DNS ---------------------------------------------------------------------
def dns(domain, timeout=20):
    """Full record set via `dig`, with a socket fallback for A/AAAA.

    CRITICAL: if DNS could not actually be queried, this reports a COVERAGE GAP and
    emits no findings. Reporting "DMARC absent" because `dig` is not installed is a
    false positive manufactured by the tooling — the exact failure mode the operator
    prompt lists as an anti-pattern.
    """
    types = ["A", "AAAA", "MX", "NS", "SOA", "TXT", "CAA"]
    records, errors = {}, {}
    dig_missing = False

    for t in types:
        try:
            out = subprocess.run(["dig", "+short", t, domain], capture_output=True,
                                 text=True, timeout=timeout)
            records[t] = [l.strip() for l in out.stdout.splitlines() if l.strip()]
        except FileNotFoundError:
            dig_missing = True
            errors[t] = "dig not installed"
            break
        except subprocess.TimeoutExpired:
            errors[t] = f"{t} query timed out"

    # Fallback: A/AAAA via the resolver library, so we at least know the host exists.
    # This cannot retrieve MX/TXT/NS — those gaps are reported, never guessed.
    if dig_missing:
        for t, family in (("A", socket.AF_INET), ("AAAA", socket.AF_INET6)):
            try:
                infos = socket.getaddrinfo(domain, None, family)
                records[t] = sorted({i[4][0] for i in infos})
            except Exception as e:
                records[t] = []
                errors[t] = f"fallback failed: {e}"
        for t in ("MX", "NS", "SOA", "TXT", "CAA"):
            records.setdefault(t, [])

    # AXFR attempt — occasionally still works, and is a real finding
    axfr = []
    if not dig_missing:
        for ns in records.get("NS", [])[:2]:
            try:
                out = subprocess.run(["dig", "AXFR", f"@{ns.rstrip('.')}", domain],
                                     capture_output=True, text=True, timeout=timeout)
                if "Transfer failed" not in out.stdout and out.stdout.strip():
                    axfr.append({"ns": ns, "output_lines": len(out.stdout.splitlines())})
            except Exception:
                pass

    spf = [t for t in records.get("TXT", []) if "v=spf1" in t]
    dmarc = []
    if not dig_missing:
        try:
            out = subprocess.run(["dig", "+short", "TXT", f"_dmarc.{domain}"],
                                 capture_output=True, text=True, timeout=timeout)
            dmarc = [l.strip() for l in out.stdout.splitlines() if l.strip()]
        except Exception:
            errors["_dmarc"] = "query failed"

    # --- findings are ONLY emitted when the data actually supports them ---
    findings, coverage_gaps = [], []
    txt_queryable = not dig_missing and "TXT" not in errors
    if not txt_queryable:
        coverage_gaps.append(
            "SPF/DMARC NOT ASSESSED — TXT records could not be queried "
            "(dig unavailable). This is a gap, not a negative result.")
    else:
        if not dmarc:
            findings.append("NO DMARC record — domain is spoofable (email forgery / phishing)")
        elif "p=none" in " ".join(dmarc):
            findings.append("DMARC policy is p=none — monitoring only, spoofing not prevented")
        if spf and "+all" in " ".join(spf):
            findings.append("SPF ends in +all — any host may send as this domain")
    if axfr:
        findings.append(f"ZONE TRANSFER SUCCEEDED against {axfr[0]['ns']} — full zone disclosed")
    if dig_missing:
        coverage_gaps.append("MX/NS/SOA/TXT/CAA unqueried — install dnsutils for full DNS coverage")

    total = sum(len(v) for v in records.values())
    lines = [f"DNS {domain} — {total} records" + ("  [PARTIAL — see gaps]" if dig_missing else "")]
    got = "  ".join(f"{k}={len(v)}" for k, v in records.items() if v)
    if got:
        lines.append("  " + got)
    lines += [f"  FINDING: {f}" for f in findings]
    lines += [f"  COVERAGE GAP: {g}" for g in coverage_gaps]
    if not findings and not coverage_gaps:
        lines.append("  no findings")
    return {"domain": domain, "records": records, "spf": spf, "dmarc": dmarc,
            "axfr": axfr, "findings": findings, "coverage_gaps": coverage_gaps,
            "errors": errors, "tool_complete": not dig_missing,
            "counts": {"records": total, "findings": len(findings),
                       "coverage_gaps": len(coverage_gaps)},
            "summary_lines": lines}


# --- subdomains --------------------------------------------------------------
def subdomains(domain, timeout=30):
    """crt.sh certificate transparency — the highest-yield free passive source."""
    subs, source, source_error = set(), "crt.sh", None
    try:
        raw = _get(CRTSH_URL.format(domain=domain), timeout)
        for row in json.loads(raw):
            for n in (row.get("name_value") or "").splitlines():
                n = n.strip().lstrip("*.").lower()
                if n and _belongs(n, domain):
                    subs.add(n)
    except Exception as e:
        source_error = str(e)
    subs = sorted(subs)

    # which ones actually resolve — an unresolvable name is a lead, not an asset
    resolved = {}
    for s in subs[:200]:
        try:
            resolved[s] = socket.gethostbyname(s)
        except Exception:
            pass

    if source_error:
        lines = [f"subdomains for {domain} — SOURCE UNAVAILABLE, NOT ENUMERATED",
                 f"  crt.sh query failed: {source_error}",
                 "  This is a COVERAGE GAP. Do not read '0 subdomains' as a result.",
                 "  Retry, extend the timeout, or use a passive DNS source with an API key."]
    else:
        lines = [f"subdomains for {domain} — {len(subs)} from {source}",
                 f"  resolving: {len(resolved)}   non-resolving: {len(subs) - len(resolved)}"]
    interesting = [s for s in subs if re.search(
        r"(^|\.)(stg|staging|stage|dev|qa|uat|test|preprod|sandbox|beta|internal|admin)", s)]
    if source_error is None:
        if interesting:
            lines.append(f"  HIGH INTEREST (forgotten environments): {', '.join(interesting[:12])}")
        lines.append("  Forgotten staging/dev hosts are the most consistently exploitable assets:")
        lines.append("  debug modes, default creds, last year's dependencies, unwatched logs.")
    return {"domain": domain, "subdomains": subs, "resolved": resolved,
            "high_interest": interesting, "source": source, "source_error": source_error,
            "enumerated": source_error is None,
            "counts": {"total": len(subs), "resolved": len(resolved)},
            "summary_lines": lines}


# --- wayback -----------------------------------------------------------------
def wayback(domain, timeout=40, limit=2000):
    """Full URL history. The gold is old JS bundles — historic builds leak keys and
    internal endpoints long after they were 'removed' from production."""
    urls, err = [], None
    try:
        raw = _get(WAYBACK_URL.format(domain=domain, limit=limit), timeout)
        urls = sorted({l.strip() for l in raw.splitlines() if l.strip()})
    except Exception as e:
        err = str(e)

    js = [u for u in urls if re.search(r"\.js(\?|$)", u)]
    params = sorted({m for u in urls for m in re.findall(r"[?&]([A-Za-z0-9_]+)=", u)})
    interesting = [u for u in urls if re.search(
        r"(admin|login|debug|backup|\.env|\.git|config|internal|staging|wp-admin|phpmyadmin)", u, re.I)]

    if err:
        lines = [f"wayback {domain} — SOURCE UNAVAILABLE, NOT ENUMERATED",
                 f"  CDX query failed: {err}",
                 "  COVERAGE GAP. Historic URL mining and JS-bundle secret hunting",
                 "  could not run. Retry with a longer timeout."]
    else:
        lines = [f"wayback {domain} — {len(urls)} archived URLs"]
    lines += [f"  JS bundles (historic secrets live here): {len(js)}",
              f"  distinct parameters mined: {len(params)}",
              f"  high-interest paths: {len(interesting)}"]
    for u in interesting[:8]:
        lines.append(f"    {u[:110]}")
    lines.append("  NEXT: download historic JS versions and grep for secrets —")
    lines.append("        keys rotated in the UI are often never rotated in reality.")
    return {"domain": domain, "urls": urls, "js_bundles": js, "parameters": params,
            "high_interest": interesting, "error": err, "enumerated": err is None,
            "counts": {"urls": len(urls), "js": len(js), "params": len(params)},
            "summary_lines": lines}


# --- email security ----------------------------------------------------------
def email_security(domain, timeout=20):
    """SPF / DMARC analysis. include: chains enumerate every third-party mail sender,
    which expands the attack surface into their infrastructure."""
    d = dns(domain, timeout=timeout)
    spf = " ".join(d["spf"])
    includes = re.findall(r"include:([^\s]+)", spf)
    lines = [f"email security {domain}",
             f"  SPF    : {spf or 'ABSENT'}",
             f"  DMARC  : {' '.join(d['dmarc']) or 'ABSENT'}",
             f"  third-party senders via include: {len(includes)}"]
    for i in includes[:10]:
        lines.append(f"    {i}")
    lines += [f"  FINDING: {f}" for f in d["findings"]]
    lines += [f"  COVERAGE GAP: {g}" for g in d.get("coverage_gaps", [])]
    lines.append("  Each include: is a third party that can send as this domain —")
    lines.append("  compromise one and you inherit their sender reputation.")
    return {"domain": domain, "spf": spf, "dmarc": d["dmarc"], "includes": includes,
            "findings": d["findings"], "coverage_gaps": d.get("coverage_gaps", []),
            "tool_complete": d.get("tool_complete"), "summary_lines": lines,
            "counts": {"includes": len(includes)}}
