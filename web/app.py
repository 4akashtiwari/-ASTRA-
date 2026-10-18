#!/usr/bin/env python3
"""
ASTRA web console — a thin backend that brings the ptx CLI to life in a browser.

Design choices, and why:

* STDLIB ONLY. No Flask/FastAPI for the backend. This sandbox wipes pip installs between
  steps, so a backend that needs an install to boot is a backend that randomly dies. The
  stdlib http.server always imports. (The bench TARGET still needs Flask; that is installed
  by the launch command and is a separate process.)

* IT SHELLS OUT TO THE CLI rather than re-implementing probes. Every active command runs
  `python3 ptx/ptx.py ...` as a subprocess, so the CLI's scope guard, rate ceiling,
  evidence discipline and exit codes are enforced exactly as they are on the command line.
  A web UI is exactly the place a scope guard must NOT be bypassed, and the surest way to
  keep it is to never route around it.

* THE TARGET IS FIXED TO THE SANDBOX BENCH. The base URL is not user-supplied for active
  scanning; it points at a local, owned benchmark target. Out-of-scope hosts are rejected
  by the CLI itself, and the UI surfaces that rejection rather than hiding it.
"""
import json
import os
import subprocess
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "ptx", "ptx.py")
PTX_CWD = os.path.join(ROOT, "ptx")
ENG = os.path.join(ROOT, "web", "demo-engagement")
BENCH_BASE = "http://127.0.0.1:5001"
BENCH_SCRIPT = os.path.join(ROOT, "bench", "target_v2.py")
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
HOST, PORT = "0.0.0.0", 8080

# Probe classes the console offers. These map 1:1 to `ptx probe <class>`; the parameterised
# ones take --path/--param, the rest need no input. Anything the CLI rejects is reported
# verbatim — the console does not pretend to support a probe the CLI does not.
PROBE_CLASSES = [
    "unauthenticated", "exposure", "headers", "sqli", "xss", "cmdi", "ssrf",
    "traversal", "redirect", "jwt-none", "method-tamper",
]
SWEEP_CLASSES = ["sqli", "xss", "cmdi", "ssrf", "traversal", "redirect"]


def run_ptx(args, timeout=180):
    """Run the ptx CLI in the demo engagement. Returns (code, output). Never shell=True, so
    user input passed as list elements cannot inject a shell command."""
    cmd = [sys.executable, CLI, "--engagement", ENG] + [str(a) for a in args]
    try:
        p = subprocess.run(cmd, cwd=PTX_CWD, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
        return p.returncode, out.strip()
    except subprocess.TimeoutExpired:
        return 124, f"(command timed out after {timeout}s)"
    except Exception as e:  # noqa: BLE001
        return 1, f"(failed to run ptx: {e})"


def read_findings():
    d = os.path.join(ENG, "findings")
    out = []
    if os.path.isdir(d):
        for fn in sorted(os.listdir(d)):
            if fn.endswith(".json"):
                try:
                    with open(os.path.join(d, fn)) as f:
                        rec = json.load(f)
                    out.append({k: rec.get(k) for k in
                                ("id", "title", "class", "severity", "status", "endpoint",
                                 "param", "summary", "evidence", "remediation", "confirmed_at")})
                except Exception:  # noqa: BLE001 - a corrupt finding must not blank the table
                    out.append({"id": fn, "title": "(unreadable)", "severity": "Info"})
    return out


def read_scope():
    p = os.path.join(ENG, "scope.yaml")
    if not os.path.exists(p):
        return {"exists": False}
    raw = open(p).read()
    # The scope file is a flat key: value / "  - item" shape; parse just what the UI shows.
    sc = {"exists": True, "raw": raw}
    key = None
    for line in raw.splitlines():
        if line.startswith("  - "):
            if key:
                if not isinstance(sc.get(key), list):
                    sc[key] = []
                sc[key].append(line[4:].strip())
        elif line and not line.startswith(" ") and ":" in line:
            k, _, v = line.partition(":")
            key = k.strip()
            v = v.strip()
            sc[key] = v if v else []  # an empty value means a "  - item" list follows
    return sc


def ensure_demo():
    """Create the demo engagement (scoped to the sandbox bench) and start the bench target."""
    os.makedirs(ENG, exist_ok=True)
    if not os.path.exists(os.path.join(ENG, "scope.yaml")):
        run_ptx(["scope", "init", "127.0.0.1", "--in-scope", "127.0.0.1",
                 "--authorization", "local sandbox benchmark target (owned) — ASTRA web console demo",
                 "--rate", "25"], timeout=60)
    # Start the bench target if nothing is answering on it yet.
    import urllib.request
    try:
        urllib.request.urlopen(BENCH_BASE + "/search?q=ping", timeout=2)
    except Exception:  # noqa: BLE001 - not up yet; start it
        subprocess.Popen([sys.executable, BENCH_SCRIPT], cwd=ROOT,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(30):
            time.sleep(0.5)
            try:
                urllib.request.urlopen(BENCH_BASE + "/search?q=ping", timeout=2)
                break
            except Exception:  # noqa: BLE001
                pass


class Handler(BaseHTTPRequestHandler):
    server_version = "ASTRA/1.0"

    def log_message(self, *a):  # keep the console quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:  # noqa: BLE001
            return {}

    def do_GET(self):
        try:
            self._get()
        except Exception as e:  # noqa: BLE001 - a handler bug returns 500, not a dead socket
            try:
                self._send(500, {"error": f"server error: {e}"})
            except Exception:  # noqa: BLE001
                pass

    def _get(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html"):
            return self._file("index.html", "text/html")
        if path.startswith("/static/"):
            return self._file(path[len("/static/"):], None)
        if path == "/api/health":
            return self._send(200, {"ok": True, "base": BENCH_BASE,
                                    "bench": self._bench_up(), "engagement": ENG})
        if path == "/api/scope":
            return self._send(200, read_scope())
        if path == "/api/findings":
            return self._send(200, {"findings": read_findings()})
        if path == "/api/coverage":
            code, out = run_ptx(["coverage"])
            return self._send(200, {"code": code, "output": out})
        if path == "/api/meta":
            return self._send(200, {"probe_classes": PROBE_CLASSES,
                                    "sweep_classes": SWEEP_CLASSES, "base": BENCH_BASE})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        try:
            self._post()
        except Exception as e:  # noqa: BLE001
            try:
                self._send(500, {"error": f"server error: {e}"})
            except Exception:  # noqa: BLE001
                pass

    def _post(self):
        path = urllib.parse.urlparse(self.path).path
        b = self._body()
        if path == "/api/probe":
            cls = b.get("class", "")
            if cls not in PROBE_CLASSES:
                return self._send(400, {"error": f"unsupported probe class: {cls!r}"})
            args = ["probe", cls, "--base", BENCH_BASE]
            if b.get("path"):
                args += ["--path", b["path"]]
            if b.get("param"):
                args += ["--param", b["param"]]
            code, out = run_ptx(args)
            return self._send(200, {"code": code, "output": out})
        if path == "/api/variants":
            args = ["variants", "--base", BENCH_BASE]
            if b.get("from_finding"):
                args += ["--from-finding", b["from_finding"]]
            elif b.get("class"):
                args += ["--class", b["class"]]
            else:
                return self._send(400, {"error": "variants needs class or from_finding"})
            if b.get("discover"):
                args += ["--discover"]
            for t in (b.get("targets") or []):
                args += ["--target", t]
            code, out = run_ptx(args, timeout=300)
            return self._send(200, {"code": code, "output": out})
        if path == "/api/retest":
            args = ["retest", "--base", BENCH_BASE]
            if b.get("finding"):
                args += ["--finding", b["finding"]]
            code, out = run_ptx(args, timeout=300)
            return self._send(200, {"code": code, "output": out})
        if path == "/api/fingerprint":
            args = ["fingerprint", "--base", BENCH_BASE]
            if b.get("cve"):
                args += ["--cve"]
            code, out = run_ptx(args, timeout=120)
            return self._send(200, {"code": code, "output": out})
        if path == "/api/discover":
            code, out = run_ptx(["discover", "--base", BENCH_BASE], timeout=180)
            return self._send(200, {"code": code, "output": out})
        return self._send(404, {"error": "not found"})

    def _bench_up(self):
        import urllib.request
        try:
            urllib.request.urlopen(BENCH_BASE + "/search?q=ping", timeout=2)
            return True
        except Exception:  # noqa: BLE001
            return False

    def _file(self, name, ctype):
        # Never serve a path that escapes the static dir.
        safe = os.path.normpath(name).lstrip("/")
        full = os.path.join(STATIC, safe)
        if not full.startswith(STATIC) or not os.path.isfile(full):
            return self._send(404, {"error": "not found"})
        if ctype is None:
            ctype = {".html": "text/html", ".js": "text/javascript",
                     ".css": "text/css"}.get(os.path.splitext(full)[1], "text/plain")
        with open(full, "rb") as f:
            self._send(200, f.read(), ctype)


def main():
    ensure_demo()
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"ASTRA web console on http://{HOST}:{PORT}  (engagement: {ENG})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
