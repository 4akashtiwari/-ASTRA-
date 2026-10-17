"""Reconnaissance: ports, TLS, HTTP fingerprint.

Three honesty rules carried over from the rest of this toolkit, because recon is where
they are easiest to violate:

1. CLOSED, FILTERED AND UNREACHABLE ARE DIFFERENT ANSWERS. A refused connection means a
   host answered and said no. A timeout means something dropped the packet, which is
   usually a firewall and is *more* informative than an open port. Reporting both as
   "not open" throws away the distinction that tells you a filter exists.

2. "NO OPEN PORTS" IS NOT "NO SERVICE". If the scan could not run — no permission, no
   route, host down — that is a coverage gap, not a negative result, and it is reported
   as one.

3. A TLS or HTTP observation is evidence about the endpoint that answered. Certificates
   and banners identify what is exposed; they do not establish that a specific
   vulnerability is reachable. That step belongs to the reachability module.
"""

import json
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                 1433, 1521, 2049, 2375, 2376, 3000, 3128, 3306, 3389, 4443, 5000,
                 5432, 5601, 5900, 6379, 7001, 8000, 8008, 8080, 8081, 8443, 8888,
                 9000, 9090, 9200, 9300, 11211, 27017]

WELL_KNOWN = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
              110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https",
              445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
              2049: "nfs", 2375: "docker-api", 2376: "docker-api-tls", 3000: "dev-server",
              3128: "proxy", 3306: "mysql", 3389: "rdp", 5000: "dev-server",
              5432: "postgres", 5601: "kibana", 5900: "vnc", 6379: "redis",
              7001: "weblogic", 8000: "http-alt", 8080: "http-alt", 8443: "https-alt",
              9000: "app", 9090: "prometheus", 9200: "elasticsearch", 9300: "elasticsearch",
              11211: "memcached", 27017: "mongodb"}

# Ports that are frequently exposed by accident and nearly always a finding.
RISKY = {2375: "unauthenticated Docker API — equivalent to root on the host",
         6379: "Redis with no authentication by default",
         9200: "Elasticsearch with no authentication by default",
         27017: "MongoDB with no authentication by default",
         11211: "memcached, unauthenticated by design and used for amplification",
         5900: "VNC, frequently weakly authenticated",
         3389: "RDP exposed to the network",
         23: "telnet, credentials in cleartext",
         2049: "NFS, access controlled by source IP only",
         1521: "Oracle listener",
         1433: "MSSQL listener",
         5601: "Kibana, frequently unauthenticated",
         9090: "metrics endpoint, leaks internal topology"}


def parse_ports(spec):
    """'80,443,8000-8010' -> [80, 443, 8000, ..., 8010]. Raises on malformed input
    rather than silently scanning nothing."""
    out = []
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if a > b:
                raise ValueError(f"reversed range {part}")
            if b - a > 65535:
                raise ValueError(f"range too large: {part}")
            out.extend(range(a, b + 1))
        else:
            out.append(int(part))
    bad = [p for p in out if not 0 < p < 65536]
    if bad:
        raise ValueError(f"port out of range: {bad[:5]}")
    return sorted(set(out))


def _probe_port(host, port, timeout):
    """Return one of: open, refused, filtered. The three are not interchangeable."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
        return {"port": port, "state": "open", "ms": round((time.time() - t0) * 1000)}
    except ConnectionRefusedError:
        return {"port": port, "state": "refused"}
    except socket.timeout:
        return {"port": port, "state": "filtered"}
    except OSError as e:
        # No route / host unreachable is a scan-level failure, not a port state.
        return {"port": port, "state": "unreachable", "error": str(e)}
    finally:
        s.close()


# A connect() succeeding does not mean the target is listening. Transparent egress
# proxies, some NAT gateways and captive portals accept every outbound connection and
# answer on the far side, so a naive connect scan reports 100% of ports open. Observed
# directly: this sandbox answered 192.0.2.1:80 (RFC 5737 TEST-NET, guaranteed
# unroutable), 198.51.100.7:9999 and 203.0.113.1:22 in 0.000s.
#
# Defence: every scan includes control ports that cannot legitimately be open. If one of
# them reports open, the scan is being intercepted and its results are refused.
CONTROL_RANGE = (60000, 65000)


def control_ports(n=3, exclude=()):
    import random
    picked, seen = [], set(exclude)
    while len(picked) < n:
        c = random.randint(*CONTROL_RANGE)
        if c not in seen:
            picked.append(c); seen.add(c)
    return sorted(picked)


def ports(host, spec=None, timeout=1.5, rps=None, workers=64, n_control=3):
    """TCP connect scan. No raw sockets, so no root required.

    Returns open ports plus counts of refused/filtered, because the ratio tells you
    whether a firewall is in front of the host. Results are withheld if a control port
    reports open, which means the network path is intercepting connections.
    """
    plist = parse_ports(spec) if spec else list(DEFAULT_PORTS)
    if not plist:
        return {"host": host, "error": "no ports to scan", "open": [], "counts": {}}
    ctrl = control_ports(n_control, exclude=plist) if n_control else []
    targets = sorted(set(plist) | set(ctrl))

    # Honour the rate ceiling: bound concurrency so a ceiling of N rps with a T-second
    # timeout means at most N*T sockets in flight.
    if rps:
        workers = max(1, min(workers, int(rps * max(timeout, 0.2)) + 1))

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(lambda p: _probe_port(host, p, timeout), targets))
    elapsed = time.time() - t0

    cset = set(ctrl)
    ctrl_res = [r for r in results if r["port"] in cset]
    real = [r for r in results if r["port"] not in cset]
    intercepted = any(r["state"] == "open" for r in ctrl_res)

    open_ = [] if intercepted else [r for r in real if r["state"] == "open"]
    counts = {}
    for r in real:
        counts[r["state"]] = counts.get(r["state"], 0) + 1

    scanned_ok = counts.get("refused", 0) + len(open_) > 0
    for r in open_:
        r["service"] = WELL_KNOWN.get(r["port"], "unknown")
        if r["port"] in RISKY:
            r["risk"] = RISKY[r["port"]]

    gaps = []
    if intercepted:
        gaps.append(
            f"SCAN INVALID — {len([r for r in ctrl_res if r['state'] == 'open'])} of "
            f"{len(ctrl)} control ports reported open. Control ports are chosen to be "
            f"ports that cannot legitimately be listening, so something on the network "
            f"path is accepting connections on the target's behalf (transparent egress "
            f"proxy, NAT gateway or captive portal). Every 'open' result from this scan "
            f"is unusable. Re-run from a network with a direct route to the target.")
    if not scanned_ok and not intercepted:
        gaps.append("SCAN REACHED NOTHING — every port was filtered or unreachable. "
                    "This is not evidence that no service is running; it usually means "
                    "a firewall is dropping packets. Report as a coverage gap, not as a "
                    "closed port.")

    return {
        "host": host, "ports_tested": len(plist), "elapsed": round(elapsed, 2),
        "open": open_, "counts": counts,
        "intercepted": intercepted,
        "control_ports": [{"port": r["port"], "state": r["state"]} for r in ctrl_res],
        "scan_reached_host": scanned_ok,
        "coverage_gaps": gaps,
        "rate_bounded": bool(rps),
    }


def _decode_der(der):
    """Parse a DER certificate without requiring a successful verification.

    Uses the stdlib decoder over a temporary PEM. Returns {} if it cannot be decoded, in
    which case the caller records a coverage gap rather than inventing findings.
    """
    import base64, tempfile, os
    try:
        pem = ("-----BEGIN CERTIFICATE-----\n"
               + "\n".join(base64.encodebytes(der).decode().split())
               + "\n-----END CERTIFICATE-----\n")
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(pem)
            return ssl._ssl._test_decode_cert(path) or {}
        finally:
            os.unlink(path)
    except Exception:
        return {}


def tls(host, port=443, timeout=8):
    """Inspect the certificate and negotiated parameters of a TLS endpoint."""
    out = {"host": host, "port": port}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # we are inspecting, not trusting
    findings, notes = [], []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                out["protocol"] = s.version()
                out["cipher"] = (s.cipher() or [None])[0]
                # CRITICAL: with verify_mode=CERT_NONE, getpeercert() returns an EMPTY
                # dict — Python only parses the certificate once verification succeeds.
                # The first version read getpeercert() here, so every certificate-based
                # check (self-signed, expiry, SAN coverage, CN) silently evaluated against
                # nothing and reported no findings for any certificate at all. Protocol
                # and cipher still worked because they come from the socket, which made
                # the module look alive while its main job did nothing.
                # The DER is available regardless, so decode that instead.
                der = s.getpeercert(binary_form=True)
                cert = _decode_der(der) if der else (s.getpeercert() or {})
    except ssl.SSLError as e:
        return {"host": host, "port": port, "error": f"no TLS on this port: {e}",
                "coverage_gaps": [f"TLS handshake failed on {host}:{port} — the endpoint "
                                  f"may not speak TLS at all. Not a negative result about "
                                  f"certificate quality."]}
    except (socket.timeout, OSError) as e:
        return {"host": host, "port": port, "error": f"could not connect: {e}",
                "coverage_gaps": [f"could not reach {host}:{port} — certificate quality "
                                  f"unassessed, not assessed as good."]}

    if not cert:
        out["findings"] = []
        out["notes"] = []
        out["coverage_gaps"] = [f"connected to {host}:{port} and negotiated "
                                f"{out.get('protocol')}, but the certificate could not be "
                                f"parsed — expiry, issuer and SAN coverage are UNASSESSED, "
                                f"not assessed as good."]
        return out

    subj = dict(x[0] for x in cert.get("subject", ()))
    out["subject_cn"] = subj.get("commonName")
    out["issuer"] = dict(x[0] for x in cert.get("issuer", ())).get("organizationName") or \
                    dict(x[0] for x in cert.get("issuer", ())).get("commonName")
    out["not_before"] = cert.get("notBefore")
    out["not_after"] = cert.get("notAfter")
    out["san"] = [v for t, v in cert.get("subjectAltName", ())]
    out["serial"] = cert.get("serialNumber")

    # Self-signed: subject and issuer identical. Common on internal services and a real
    # finding when the service faces users, because it trains them to click through.
    if subj and dict(x[0] for x in cert.get("issuer", ())) == subj:
        findings.append({"check": "self-signed certificate", "severity": "Low",
                         "detail": "subject and issuer are identical"})

    # Expiry, computed rather than eyeballed.
    try:
        exp = ssl.cert_time_to_seconds(cert["notAfter"])
        days = int((exp - time.time()) / 86400)
        out["days_to_expiry"] = days
        if days < 0:
            findings.append({"check": "certificate expired", "severity": "High",
                             "detail": f"expired {-days} day(s) ago"})
        elif days < 30:
            findings.append({"check": "certificate expiring soon", "severity": "Medium",
                             "detail": f"{days} day(s) remaining"})
    except Exception:
        notes.append("expiry could not be parsed")

    if out.get("protocol") in ("SSLv3", "TLSv1", "TLSv1.1"):
        findings.append({"check": "deprecated TLS protocol negotiated", "severity": "High",
                         "detail": f"{out['protocol']} — deprecated and with known weaknesses"})
    elif out.get("protocol") == "TLSv1.2":
        notes.append("TLSv1.2 negotiated; TLSv1.3 preferred")

    # Hostname coverage, checked against SAN only — CN fallback is itself deprecated.
    if out["san"]:
        names = [n.lstrip("*.").lower() for n in out["san"] if not n.startswith("*")]
        wild = [n for n in out["san"] if n.startswith("*.")]
        if host.lower() not in names and not any(
                host.lower().endswith("." + w.lstrip("*.").lower()) for w in wild):
            findings.append({"check": "hostname not covered by certificate",
                             "severity": "Medium",
                             "detail": f"{host} not in SAN {out['san'][:6]}"})
    elif out.get("subject_cn"):
        notes.append("no SAN extension; CN-only certificates are deprecated")

    out["findings"] = findings
    out["notes"] = notes
    return out


def http(url, timeout=10):
    """Fingerprint an HTTP endpoint: server identity, cookies, methods, TLS posture."""
    import urllib.request
    import urllib.error

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        r = opener.open(url, timeout=timeout)
        code, headers, body = r.getcode(), dict(r.headers), r.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        code, headers, body = e.code, dict(e.headers), e.read(4096).decode("utf-8", "replace")
    except Exception as e:
        return {"url": url, "error": str(e),
                "coverage_gaps": [f"could not reach {url} — fingerprint unassessed"]}

    h = {k.lower(): v for k, v in headers.items()}
    out = {"url": url, "status": code, "server": h.get("server"),
           "powered_by": h.get("x-powered-by"), "findings": [], "notes": []}

    # Cookie flags. Absence of HttpOnly on a session cookie is a real finding; absence of
    # Secure on a cookie served over HTTPS is another. Both are checkable, not guessed.
    cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    cookie_report = []
    for c in cookies:
        name = c.split("=")[0].strip()
        low = c.lower()
        problems = []
        if "httponly" not in low:
            problems.append("no HttpOnly — readable by injected script")
        if "secure" not in low and url.startswith("https"):
            problems.append("no Secure flag on an HTTPS endpoint")
        if "samesite" not in low:
            problems.append("no SameSite")
        cookie_report.append({"name": name, "problems": problems})
        if problems:
            out["findings"].append({"check": f"cookie {name} missing flags",
                                    "severity": "Medium" if "httponly" not in low else "Low",
                                    "detail": "; ".join(problems)})
    out["cookies"] = cookie_report

    # Methods. An OPTIONS response advertising PUT/DELETE/TRACE is worth recording.
    allow = h.get("allow", "")
    if allow:
        out["allow"] = allow
        for m in ("PUT", "DELETE", "TRACE", "PATCH"):
            if m in allow.upper():
                out["findings"].append({"check": f"{m} advertised", "severity": "Low",
                                        "detail": f"OPTIONS advertises {m}"})

    for hdr, name in (("strict-transport-security", "HSTS"),
                      ("x-content-type-options", "X-Content-Type-Options"),
                      ("content-security-policy", "CSP"),
                      ("x-frame-options", "X-Frame-Options")):
        if hdr not in h:
            out["findings"].append({"check": f"missing {name}", "severity": "Low",
                                    "detail": f"{hdr} header absent"})

    # Identity hints from the body. Confidence is recorded because a generator meta tag
    # and a framework error page are not equally strong evidence.
    hints = []
    for pat, label, conf in (
        (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', "generator meta", "MEDIUM"),
        (r'(Django|Flask|Express|Laravel|Rails|ASP\.NET|Next\.js|Nuxt)', "framework string", "MEDIUM"),
        (r'wp-content|wp-includes', "WordPress", "HIGH"),
        (r'/sites/default/files', "Drupal", "HIGH"),
        (r'Traceback \(most recent call last\)', "Python traceback in response", "HIGH"),
        (r'sqlite3\.|psycopg2|mysql\.connector', "database driver in error output", "HIGH"),
    ):
        m = re.search(pat, body, re.I)
        if m:
            hints.append({"hint": label, "value": m.group(1) if m.groups() else label,
                          "confidence": conf})
    out["identity_hints"] = hints
    return out


def run(host, spec=None, rps=None, timeout=1.5):
    """Ports, then TLS and HTTP on whatever was found to be listening."""
    pr = ports(host, spec, timeout=timeout, rps=rps)
    out = {"host": host, "ports": pr, "tls": [], "http": [], "coverage_gaps": list(pr.get("coverage_gaps", []))}
    for p in pr.get("open", []):
        port = p["port"]
        if port in (443, 8443) or p.get("service", "").endswith("tls"):
            t = tls(host, port)
            out["tls"].append(t)
            out["coverage_gaps"] += t.get("coverage_gaps", [])
        if port in (80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9090):
            scheme = "https" if port in (443, 8443) else "http"
            hh = http(f"{scheme}://{host}:{port}/")
            out["http"].append(hh)
            out["coverage_gaps"] += hh.get("coverage_gaps", [])
    return out


def render(res):
    L = [f"# Reconnaissance — {res.get('host', '?')}", ""]
    pr = res.get("ports", res)
    if "ports_tested" in pr:
        L.append(f"## Ports ({pr['ports_tested']} tested, {pr.get('elapsed', '?')}s)")
        L.append("")
        if pr.get("intercepted"):
            L.append("**SCAN INVALID — network path is intercepting connections.** "
                     "Control ports reported open, so no 'open' result below can be "
                     "trusted. See coverage gaps.")
            L.append("")
        if pr.get("open"):
            L.append("| port | service | state | note |")
            L.append("|---|---|---|---|")
            for p in pr["open"]:
                L.append(f"| {p['port']} | {p.get('service', '?')} | {p['state']} | "
                         f"{p.get('risk', '')} |")
        else:
            L.append("_No open ports._")
        L.append("")
        L.append(f"counts: {json.dumps(pr.get('counts', {}))}")
        L.append("")
    for t in res.get("tls", []):
        L.append(f"## TLS {t.get('host')}:{t.get('port')}")
        if t.get("error"):
            L.append(f"_{t['error']}_")
        else:
            L.append(f"- protocol {t.get('protocol')}, cipher {t.get('cipher')}")
            L.append(f"- CN {t.get('subject_cn')}, issuer {t.get('issuer')}")
            L.append(f"- expires {t.get('not_after')} ({t.get('days_to_expiry')} days)")
            for f in t.get("findings", []):
                L.append(f"- **[{f['severity']}]** {f['check']}: {f['detail']}")
        L.append("")
    for h in res.get("http", []):
        L.append(f"## HTTP {h.get('url')}")
        if h.get("error"):
            L.append(f"_{h['error']}_")
        else:
            L.append(f"- HTTP {h.get('status')}, server={h.get('server') or 'none'}, "
                     f"powered-by={h.get('powered_by') or 'none'}")
            for hi in h.get("identity_hints", []):
                L.append(f"- identity hint ({hi['confidence']}): {hi['hint']} = {hi['value']}")
            for f in h.get("findings", []):
                L.append(f"- **[{f['severity']}]** {f['check']}: {f['detail']}")
        L.append("")
    gaps = res.get("coverage_gaps") or []
    if gaps:
        L.append("## Coverage gaps")
        L.append("")
        for g in gaps:
            L.append(f"- {g}")
        L.append("")
    return "\n".join(L)
