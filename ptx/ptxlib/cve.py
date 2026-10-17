"""
Version -> CVE correlation via LIVE lookup against OSV.dev.

The absolute rule this module exists to enforce: no CVE ID or version-vulnerability
mapping is ever produced from model memory. Either OSV returns it, or it is labelled
UNVERIFIED. A model will happily invent CVE-2024-31337 with a plausible description.
"""
import json, os, urllib.request, urllib.error

OSV_URL = "https://api.osv.dev/v1/query"


class CVEError(Exception):
    pass


def _post(payload, timeout):
    req = urllib.request.Request(
        OSV_URL, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "ptx/1.0"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise CVEError(f"OSV HTTP {e.code}: {e.read().decode()[:200]}")
    except Exception as e:
        raise CVEError(f"OSV unreachable: {e}")


def _severity(v):
    ds = v.get("database_specific") or {}
    if ds.get("severity"):
        return str(ds["severity"]).upper()
    for s in v.get("severity") or []:
        if s.get("score"):
            return s["score"]
    return "UNRATED"


def query(package, ecosystem, version, timeout=30):
    """Query OSV for one package@version. Returns live advisory data, never cached."""
    data = _post({"package": {"name": package, "ecosystem": ecosystem},
                  "version": version}, timeout)
    vulns = data.get("vulns", [])
    out = []
    for v in vulns:
        aliases = v.get("aliases") or []
        out.append({
            "id": v.get("id"),
            "aliases": aliases,
            "cves": [a for a in aliases if a.startswith("CVE-")],
            "severity": _severity(v),
            "summary": (v.get("summary") or v.get("details") or "")[:200],
            "source": "OSV.dev",
            "queried_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ",
                                                      __import__("time").gmtime()),
        })
    crit = sum(1 for x in out if x["severity"] == "CRITICAL")
    high = sum(1 for x in out if x["severity"] == "HIGH")
    lines = [
        f"{package}@{version} ({ecosystem}) — {len(out)} advisories from OSV.dev",
        f"  CRITICAL {crit}  HIGH {high}  other {len(out) - crit - high}",
    ]
    for x in sorted(out, key=lambda y: {"CRITICAL": 0, "HIGH": 1}.get(y["severity"], 2))[:10]:
        cv = ",".join(x["cves"]) or x["id"]
        lines.append(f"  [{x['severity']:8s}] {cv:18s} {x['summary'][:70]}")
    lines.append("  NOTE: reachability NOT assessed — a CVE in code the app never calls")
    lines.append("        is not a finding. Verify before assigning severity.")
    return {"package": package, "ecosystem": ecosystem, "version": version,
            "vulns": out, "counts": {"total": len(out), "critical": crit, "high": high},
            "summary_lines": lines}


def audit_lockfile(path, timeout=30):
    """Parse a package-lock.json and query every pinned dependency against OSV."""
    if not os.path.exists(path):
        raise CVEError(f"no such file: {path}")
    with open(path) as f:
        lock = json.load(f)

    pkgs = {}
    for k, v in (lock.get("packages") or {}).items():
        if not k or "node_modules/" not in k:
            continue
        name = k.split("node_modules/")[-1]
        ver = v.get("version")
        if name and ver:
            pkgs[name] = ver
    # lockfileVersion 1 style
    for name, v in (lock.get("dependencies") or {}).items():
        if v.get("version"):
            pkgs.setdefault(name, v["version"])

    affected, clean, errors = [], [], []
    for name, ver in sorted(pkgs.items()):
        try:
            r = query(name, "npm", ver, timeout=timeout)
        except CVEError as e:
            errors.append({"package": name, "version": ver, "error": str(e)})
            continue
        if r["vulns"]:
            affected.append({"package": name, "version": ver,
                             "advisory_count": r["counts"]["total"],
                             "critical": r["counts"]["critical"],
                             "high": r["counts"]["high"],
                             "cves": sorted({c for x in r["vulns"] for c in x["cves"]}),
                             "advisory_text": " ".join(x["summary"] for x in r["vulns"])})
        else:
            clean.append({"package": name, "version": ver})

    lines = [
        f"lockfile audit: {path}",
        f"  packages checked : {len(pkgs)}",
        f"  AFFECTED         : {len(affected)}",
        f"  no advisories    : {len(clean)}",
        f"  lookup errors    : {len(errors)}",
    ]
    for a in sorted(affected, key=lambda x: (-x["critical"], -x["high"])):
        lines.append(f"  [{a['critical']}C/{a['high']}H] {a['package']}@{a['version']} "
                     f"-> {a['advisory_count']} advisories: {', '.join(a['cves'][:4])}")
    for c in clean:
        lines.append(f"  [clean]        {c['package']}@{c['version']}")
    lines.append("")
    lines.append("  ALL DATA LIVE FROM OSV.dev. Nothing here came from model memory.")
    lines.append("  Reachability is UNASSESSED — verify each before reporting.")
    return {"path": path, "packages_checked": len(pkgs), "affected": affected,
            "clean": clean, "errors": errors, "lockdata": lock,
            "counts": {"checked": len(pkgs), "affected": len(affected),
                       "clean": len(clean), "errors": len(errors)},
            "summary_lines": lines}
