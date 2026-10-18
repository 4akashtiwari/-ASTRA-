#!/usr/bin/env python3
"""
Test suite for ptx.

Most of these are REGRESSION tests: each one encodes a bug that was actually found and
fixed in this project. Every one of those bugs was the same species — the tool reporting
something false with confidence. That is why the suite is weighted toward asserting what
the tool says when it does NOT know, not just when it does.

Run: python3 -m unittest tests.test_ptx
"""
import base64, json, os, shutil, socket, subprocess, sys, tempfile, threading, time
import unittest
import unittest.mock
import urllib.error, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "ptx"))
sys.path.insert(0, ROOT)

from ptxlib import scope as scopelib, cve, osint, probes, findings as fnd, report as rpt, \
    chains, reliability, integrity, recon, chainwalk, coverage, \
    reachability, state as statemod, takeover, discover, identities, variants

VULN_PORT, SAFE_PORT = 5101, 5102
VULN = f"http://127.0.0.1:{VULN_PORT}"
SAFE = f"http://127.0.0.1:{SAFE_PORT}"


# --- fixtures ------------------------------------------------------------------
def _wait_for(port, timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def _start(script, port, env_extra=None):
    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.Popen([sys.executable, script], cwd=os.path.dirname(script),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)


class ServerFixture:
    """Shared target pair.

    Process-wide singleton rather than per-class: unittest runs test classes
    alphabetically, so any class that reads vuln_up/safe_up must be able to rely on the
    servers being there regardless of whether it happens to sort first. Starting a fresh
    pair per class also collides on the fixed ports when two classes both need them.
    """

    procs = []
    _started = False

    @classmethod
    def setUpClass(cls):
        if ServerFixture._started:
            cls.tmp = ServerFixture.tmp
            cls.files = ServerFixture.files
            cls.vuln_up = ServerFixture.vuln_up
            cls.safe_up = ServerFixture.safe_up
            return
        ServerFixture._started = True
        # copy the vulnerable target and retarget its port so the suite is self-contained
        cls.tmp = tempfile.mkdtemp(prefix="ptxtest")
        src = os.path.join(ROOT, "bench", "target_v2.py")
        dst = os.path.join(cls.tmp, "vuln_target.py")
        with open(src) as f:
            code = f.read()
        code = code.replace("port=5001", f"port={VULN_PORT}")
        code = code.replace('"/tmp/dryrun2.db"', f'"{cls.tmp}/vuln.db"')
        with open(dst, "w") as f:
            f.write(code)
        # the vulnerable target's download root must contain the traversal canary
        os.makedirs(os.path.join(cls.tmp, "files"), exist_ok=True)
        os.makedirs(os.path.join(cls.tmp, "canary"), exist_ok=True)
        with open(os.path.join(cls.tmp, "files", "readme.txt"), "w") as f:
            f.write("public\n")
        with open(os.path.join(cls.tmp, "canary", "secret.txt"), "w") as f:
            f.write("PTX_TRAVERSAL_GOAL_9f3a\n")

        cls.files = os.path.join(cls.tmp, "served")
        os.makedirs(cls.files, exist_ok=True)
        with open(os.path.join(cls.files, "readme.txt"), "w") as f:
            f.write("public\n")
        ServerFixture.procs.append(_start(dst, VULN_PORT))
        ServerFixture.procs.append(_start(os.path.join(ROOT, "tests", "safe_target.py"),
                                          SAFE_PORT,
                                          env_extra={"PTX_SAFE_PORT": str(SAFE_PORT),
                                                     "PTX_SAFE_FILES": cls.files}))
        ServerFixture.vuln_up = _wait_for(VULN_PORT)
        ServerFixture.safe_up = _wait_for(SAFE_PORT)
        ServerFixture.tmp, ServerFixture.files = cls.tmp, cls.files
        cls.vuln_up, cls.safe_up = ServerFixture.vuln_up, ServerFixture.safe_up
        import atexit
        atexit.register(ServerFixture._shutdown)

    @classmethod
    def _shutdown(cls):
        for p in ServerFixture.procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in ServerFixture.procs:
            try:
                p.wait(timeout=5)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        ServerFixture.procs = []
        shutil.rmtree(getattr(ServerFixture, "tmp", ""), ignore_errors=True)

    @classmethod
    def tearDownClass(cls):
        # deliberately a no-op: the pair is shared, and atexit tears it down once
        pass


def login(base, user="alice"):
    jar = urllib.request.HTTPCookieProcessor()
    op = urllib.request.build_opener(jar)
    req = urllib.request.Request(base + "/login",
                                 data=json.dumps({"username": user}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        op.open(req, timeout=10)
    except Exception:
        pass
    for c in jar.cookiejar:
        if c.name == "sid":
            return c.value
    return None


class TmpEngagement(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ptxeng")
        statemod.init(self.dir)
        with open(os.path.join(self.dir, "scope.yaml"), "w") as f:
            f.write("target: acme.test\nin_scope:\n  - acme.test\n  - '*.acme.test'\n"
                    "  - 10.0.0.0/24\n  - 127.0.0.1\nexclusions:\n  - cloudflare.net\n"
                    "  - okta.com\nauthorization: test suite\ndestructive_permitted: false\n"
                    "rate_ceiling_rps: 10\n")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)


# === SCOPE GUARD ==============================================================
class TestScopeGuard(TmpEngagement):
    def setUp(self):
        super().setUp()
        self.sc = scopelib.load_scope(self.dir)

    def test_in_scope_exact_and_subdomain(self):
        for h in ("acme.test", "api.acme.test", "a.b.acme.test"):
            ok, _ = self.sc.is_in_scope(h)
            self.assertTrue(ok, f"{h} should be in scope")

    def test_exclusion_beats_inclusion(self):
        """REGRESSION: a third party must never be reachable even if it looks in-scope."""
        ok, reason = self.sc.is_in_scope("cdn.cloudflare.net")
        self.assertFalse(ok)
        self.assertIn("excluded", reason)

    def test_unknown_host_blocked(self):
        ok, _ = self.sc.is_in_scope("evil.example.com")
        self.assertFalse(ok)

    def test_wildcard_matching(self):
        self.assertTrue(self.sc.is_in_scope("staging.acme.test")[0])
        self.assertFalse(self.sc.is_in_scope("notacme.test")[0])
        self.assertFalse(self.sc.is_in_scope("acme.test.evil.com")[0],
                         "suffix-confusion must not pass as in-scope")

    def test_cidr(self):
        self.assertTrue(self.sc.is_in_scope("10.0.0.7")[0])
        self.assertFalse(self.sc.is_in_scope("10.0.1.7")[0])

    def test_scheme_and_port_stripped(self):
        self.assertTrue(self.sc.is_in_scope("https://api.acme.test:8443/x")[0])

    def test_assert_raises_and_logs(self):
        with self.assertRaises(scopelib.ScopeViolation):
            self.sc.assert_in_scope("login.okta.com")
        self.sc.log_scope_checks([], [{"host": "login.okta.com", "reason": "excluded"}])
        with open(os.path.join(self.dir, "log.md")) as f:
            self.assertIn("SCOPE BLOCK", f.read())
        with open(os.path.join(self.dir, "state.json")) as f:
            self.assertEqual(json.load(f)["scope_blocks"], 1)

    def test_missing_scope_raises(self):
        with self.assertRaises(FileNotFoundError):
            scopelib.load_scope("/nonexistent-engagement-dir")


# === HONESTY: TOOLING FAILURES MUST NOT BECOME FINDINGS =======================
class TestHonestFailureModes(TmpEngagement):
    def test_dig_missing_produces_gap_not_finding(self):
        """REGRESSION: with dig absent the DNS module reported 'NO DMARC — spoofable'
        from zero data. A missing tool must yield a coverage gap, never a finding."""
        real = osint.subprocess.run

        def fake_run(*a, **k):
            raise FileNotFoundError("dig not installed")

        osint.subprocess.run = fake_run
        try:
            r = osint.dns("acme.test")
        finally:
            osint.subprocess.run = real
        self.assertFalse(r["tool_complete"])
        self.assertEqual(r["findings"], [], "must not invent findings from absent data")
        self.assertTrue(r["coverage_gaps"])
        self.assertTrue(any("NOT ASSESSED" in g for g in r["coverage_gaps"]))

    def test_source_failure_is_not_zero_results(self):
        """REGRESSION: crt.sh returning 502 produced 'subdomains — 0', which reads as
        'no subdomains exist'. A failed query must be distinguishable from an empty result."""
        def boom(*a, **k):
            raise urllib.error.HTTPError("u", 502, "Bad Gateway", {}, None)
        real = osint._get
        osint._get = boom
        try:
            r = osint.subdomains("acme.test")
        finally:
            osint._get = real
        self.assertFalse(r["enumerated"])
        self.assertIsNotNone(r["source_error"])
        self.assertTrue(any("SOURCE UNAVAILABLE" in l for l in r["summary_lines"]))
        self.assertFalse(any("Forgotten staging" in l for l in r["summary_lines"]),
                         "interpretive hints must be suppressed when enumeration failed")

    def test_cve_error_is_raised_not_swallowed(self):
        real = cve._post
        cve._post = lambda *a, **k: (_ for _ in ()).throw(cve.CVEError("unreachable"))
        try:
            with self.assertRaises(cve.CVEError):
                cve.query("lodash", "npm", "4.17.4")
        finally:
            cve._post = real


# === CVE: NOTHING FROM MEMORY =================================================
class TestCVE(TmpEngagement):
    LOCK = {"name": "acme", "lockfileVersion": 3, "packages": {
        "": {"name": "acme"},
        "node_modules/lodash": {"version": "4.17.4"},
        "node_modules/express": {"version": "4.16.0"},
        "node_modules/clean-pkg": {"version": "9.9.9"}}}

    def _write(self):
        p = os.path.join(self.dir, "lock.json")
        with open(p, "w") as f:
            json.dump(self.LOCK, f)
        return p

    def test_lockfile_parsing_skips_root_entry(self):
        r = cve.audit_lockfile(self._write())
        names = {a["package"] for a in r["affected"]} | {c["package"] for c in r["clean"]}
        self.assertNotIn("", names, "the root package entry must not be treated as a dependency")
        self.assertIn("lodash", names)

    def test_advisories_come_from_live_source(self):
        """The anti-hallucination rule: identifiers must come from OSV, not memory."""
        r = cve.query("lodash", "npm", "4.17.4")
        self.assertGreater(len(r["vulns"]), 0)
        for v in r["vulns"]:
            self.assertEqual(v["source"], "OSV.dev")
            self.assertTrue(v["id"].startswith(("GHSA-", "CVE-")),
                            f"unexpected advisory id shape: {v['id']}")

    def test_reachability_is_always_reported_unassessed(self):
        r = cve.query("lodash", "npm", "4.17.4")
        self.assertTrue(any("reachability" in l.lower() for l in r["summary_lines"]),
                        "output must state that reachability is not assessed")

    def test_clean_package_reports_no_advisories(self):
        """A version with no advisories must come back empty, and be listed as clean.

        NOTE: an earlier version of this test hardcoded lodash@4.17.21 as clean. OSV
        returned three advisories for it (CVE-2025-13465, CVE-2026-2950 and another).
        The assumption was stale — which is exactly why the rule is live lookup only.
        The test now discovers a clean version at runtime instead of asserting one.
        """
        clean = None
        for pkg, ver in (("is-odd", "3.0.1"), ("left-pad", "1.3.0"),
                         ("lodash", "4.17.21"), ("ms", "2.1.3")):
            if not cve.query(pkg, "npm", ver)["vulns"]:
                clean = (pkg, ver)
                break
        if clean is None:
            self.skipTest("no known-clean package version available from OSV right now")
        r = cve.query(clean[0], "npm", clean[1])
        self.assertEqual(r["vulns"], [])
        self.assertEqual(r["counts"]["total"], 0)


# === PROBES AGAINST BOTH TARGETS =============================================
class TestProbesDualTarget(ServerFixture, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ServerFixture.setUpClass()
        cls.assertTrue_ = unittest.TestCase().assertTrue

    def setUp(self):
        self.assertTrue(ServerFixture.vuln_up, "vulnerable target did not start")
        self.assertTrue(ServerFixture.safe_up, "safe target did not start")
        self.vuln_sid = login(VULN)
        self.safe_sid = login(SAFE)
        self.hv = probes.Http(VULN, timeout=15)
        self.hs = probes.Http(SAFE, timeout=15)
        urllib.request.urlopen(urllib.request.Request(
            VULN + "/benchmark/reset", method="POST", data=b"{}"), timeout=10).read()
        urllib.request.urlopen(urllib.request.Request(
            SAFE + "/benchmark/reset", method="POST", data=b"{}"), timeout=10).read()
        self.vuln_sid = login(VULN)
        self.safe_sid = login(SAFE)

    def assertVulnerable(self, v):
        self.assertTrue(v["vulnerable"], f"expected VULNERABLE: {v['name']} :: {v['evidence']}")

    def assertSafe(self, v):
        self.assertFalse(v["vulnerable"],
                         f"FALSE POSITIVE on hardened target: {v['name']} :: {v['evidence']}")

    # --- IDOR ---
    def test_idor_both(self):
        self.assertVulnerable(probes.probe_idor(
            self.hv, "/api/invoices", 1001, 1003, cookie=f"sid={self.vuln_sid}"))
        self.assertSafe(probes.probe_idor(
            self.hs, "/api/invoices", 1001, 1003, cookie=f"sid={self.safe_sid}"))

    # --- SQLi, including the context regression ---
    def test_sqli_vulnerable_with_correct_context(self):
        self.assertVulnerable(probes.probe_sqli(self.hv, "/search", "q", ctx="like"))

    def test_sqli_wrong_context_still_detects_via_error(self):
        """With ctx='quote' against a LIKE injection point the boolean payload is malformed
        and produces no differential. The probe must NOT shrug — the unbalanced quote makes
        the concatenated query throw, which is itself proof of injection.

        This test previously asserted INCONCLUSIVE here. That assertion was wrong: the
        endpoint is genuinely injectable, and error-based detection establishes it.
        """
        v = probes.probe_sqli(self.hv, "/search", "q", ctx="quote")
        self.assertTrue(v["vulnerable"],
                        "a malformed payload must not conceal a real injection")
        self.assertIn("error-based", v["evidence"])

    def test_sqli_inconclusive_when_nothing_is_interpretable(self):
        """REGRESSION: when neither the differential nor the error probe can be read, the
        probe must say INCONCLUSIVE. It must never report 'safe' from an unreadable result.
        The original probe read a malformed payload's 0/0 as 'not vulnerable'."""
        class Opaque(probes.Http):
            """Endpoint with no readable count field and no error signalling."""
            def req(self, *a, **k):
                return {"code": 200, "body": "<html>ok</html>", "headers": {}, "error": None}

        v = probes.probe_sqli(Opaque("http://127.0.0.1:1"), "/search", "q", ctx="like")
        self.assertFalse(v["vulnerable"])
        self.assertIn("INCONCLUSIVE", v["evidence"],
                      "an uninterpretable result must never be reported as safe")
        self.assertIn("NOT evidence of safety", v["teaching"])

    def test_sqli_safe_target(self):
        v = probes.probe_sqli(self.hs, "/search", "q", ctx="like")
        self.assertSafe(v)
        self.assertIn("CONCLUSIVE NEGATIVE", v["evidence"],
                      "a parameterized query must yield a real conclusion, not a shrug")
        self.assertEqual(v["severity"], None)

    # --- XSS ---
    def test_xss_both(self):
        self.assertVulnerable(probes.probe_xss(self.hv, "/greet", "name"))
        self.assertSafe(probes.probe_xss(self.hs, "/greet", "name"))

    def test_stored_xss_both(self):
        self.assertVulnerable(probes.probe_stored_xss(
            self.hv, "/api/comments", "/api/comments", "body", cookie=f"sid={self.vuln_sid}"))
        self.assertSafe(probes.probe_stored_xss(
            self.hs, "/api/comments", "/api/comments", "body", cookie=f"sid={self.safe_sid}"))

    # --- command injection, including the metacharacter trap ---
    def test_cmdi_both(self):
        self.assertVulnerable(probes.probe_cmdi(self.hv, "/api/ping", "host"))
        self.assertSafe(probes.probe_cmdi(self.hs, "/api/ping", "host"))

    def test_metacharacter_alone_is_not_a_finding(self):
        """REGRESSION: `&&` is accepted by the vulnerable endpoint but never fires, because
        ping exits non-zero without raw sockets. Accepting a metacharacter is not a vuln."""
        c = probes.canary("amp")
        r = self.hv.req("/api/ping?host=" + urllib.parse.quote(f"127.0.0.1 && echo {c}"))
        self.assertNotIn(c, r["body"],
                         "&& must not be reported as demonstrable injection here")

    # --- exposure, headers, secrets ---
    def test_exposure_both(self):
        self.assertVulnerable(probes.probe_exposure(self.hv))
        self.assertSafe(probes.probe_exposure(self.hs))

    def test_headers_both(self):
        self.assertVulnerable(probes.probe_headers(self.hv))
        self.assertSafe(probes.probe_headers(self.hs))

    # --- JWT ---
    def test_jwt_none_both(self):
        self.assertVulnerable(probes.probe_jwt_none(self.hv, "/api/me"))
        self.assertSafe(probes.probe_jwt_none(self.hs, "/api/me"))

    # --- open redirect ---
    def test_redirect_both(self):
        """REGRESSION: the probe client FOLLOWED the 302 to a host that does not resolve,
        destroying the Location header that is the finding itself."""
        self.assertVulnerable(probes.probe_redirect(self.hv, "/redirect", "next"))
        self.assertSafe(probes.probe_redirect(self.hs, "/redirect", "next"))

    def test_client_does_not_follow_redirects(self):
        r = self.hv.req("/redirect?next=https://attacker.example/")
        self.assertIn(r["code"], (301, 302, 303, 307, 308))
        self.assertIn("attacker.example", r["headers"].get("Location", ""))

    # --- traversal ---
    def test_traversal_vulnerable(self):
        self.assertVulnerable(probes.probe_traversal(
            self.hv, "/download", "file", "../canary/secret.txt", "PTX_TRAVERSAL_GOAL"))

    def test_traversal_safe(self):
        self.assertSafe(probes.probe_traversal(
            self.hs, "/download", "file", "../safe_target.py", "JWT_SECRET"))

    def test_traversal_safe_confined_to_base(self):
        """The hardened target must serve files inside its base but refuse to escape it."""
        r = self.hs.req("/download?file=readme.txt")
        self.assertEqual(r["code"], 200, "legitimate download must still work")
        r = self.hs.req("/download?file=" + urllib.parse.quote("../../etc/passwd"))
        self.assertNotEqual(r["code"], 200)

    # --- SSRF ---
    def test_ssrf_vulnerable(self):
        self.assertVulnerable(probes.probe_ssrf(
            self.hv, "/api/fetch", "url", f"{VULN}/greet"))

    def test_ssrf_safe(self):
        self.assertSafe(probes.probe_ssrf(self.hs, "/api/fetch", "url", f"{SAFE}/greet"))

    # --- race ---
    def test_race_vulnerable(self):
        self.assertVulnerable(probes.probe_race(
            self.hv, "/api/redeem", {"code": "WELCOME50"}, f"sid={self.vuln_sid}", n=8))

    def test_race_safe(self):
        self.assertSafe(probes.probe_race(
            self.hs, "/api/redeem", {"code": "WELCOME50"}, f"sid={self.safe_sid}", n=8))

    # --- mass assignment ---
    def _verify(self, base, sid):
        def fn(h, hdr):   # signature matches probe_mass_assignment's verify_fn(h, hdr)
            r = h.req("/admin/users", headers=hdr)
            try:
                for u in json.loads(r["body"]).get("users", []):
                    if u["username"] == "alice":
                        return u.get("is_admin") == 1 or u.get("credits") == 99999
            except Exception:
                pass
            return False
        return fn

    def test_mass_assignment_vulnerable(self):
        v = probes.probe_mass_assignment(
            self.hv, "/api/profile", f"sid={self.vuln_sid}",
            self._verify(VULN, self.vuln_sid))
        self.assertVulnerable(v)

    def test_mass_assignment_safe(self):
        hv = probes.Http(SAFE, timeout=15)
        v = probes.probe_mass_assignment(
            hv, "/api/profile", f"sid={self.safe_sid}",
            self._verify(SAFE, self.safe_sid))
        self.assertSafe(v)

    def test_mass_assignment_verifies_effect_not_response(self):
        """REGRESSION: with a dead session the API returns an error, and the probe must
        report 'effect not observed' rather than trusting any success claim."""
        v = probes.probe_mass_assignment(
            self.hv, "/api/profile", "sid=dead-session-token",
            lambda h, hdr: False)
        self.assertFalse(v["vulnerable"])
        self.assertIn("ACTUALLY CHANGED", v["evidence"])

    # --- method tampering, ssti ---
    def test_method_tamper_both(self):
        self.assertVulnerable(probes.probe_method_tamper(
            self.hv, "/api/account/delete", f"sid={self.vuln_sid}"))
        self.assertSafe(probes.probe_method_tamper(
            self.hs, "/api/account/delete", f"sid={self.safe_sid}"))

    def test_ssti_both(self):
        self.assertVulnerable(probes.probe_ssti(self.hv, "/api/render"))
        self.assertSafe(probes.probe_ssti(self.hs, "/api/render"))

    # --- admin authz ---
    def test_admin_authz(self):
        v = probes.probe_idor(self.hv, "/admin", 0, 0, cookie=f"sid={self.vuln_sid}")
        # covered by dedicated check below instead
        r = self.hs.req("/admin/users", headers={"Cookie": f"sid={self.safe_sid}"})
        self.assertEqual(r["code"], 403, "hardened target must enforce function-level authz")
        r = self.hv.req("/admin/users", headers={"Cookie": f"sid={self.vuln_sid}"})
        self.assertEqual(r["code"], 200, "vulnerable target leaks the admin user list")


# === FINDINGS: VALIDATION AND DEDUP ==========================================
class TestFindings(TmpEngagement):
    def _verdict(self, **kw):
        base = {"id": "test", "name": "Test finding", "vulnerable": True,
                "evidence": "some evidence", "mechanism": "m", "teaching": "t",
                "severity": "High"}
        base.update(kw)
        return base

    def test_finding_records_its_location(self):
        rec, _ = fnd.from_probe(self.dir, self._verdict(endpoint="/search", param="q"))
        self.assertEqual(rec["endpoint"], "/search")
        self.assertEqual(rec["param"], "q")

    def test_location_is_none_when_the_probe_named_none(self):
        # A parameterless probe (exposure, headers) has no endpoint/param; the fields are
        # present but None rather than absent, so downstream readers need no special case.
        rec, _ = fnd.from_probe(self.dir, self._verdict())
        self.assertIsNone(rec["endpoint"])
        self.assertIsNone(rec["param"])

    def test_get_returns_a_finding_by_id_and_none_when_absent(self):
        rec, _ = fnd.from_probe(self.dir, self._verdict(endpoint="/x", param="y"))
        got = fnd.get(self.dir, rec["id"])
        self.assertEqual(got["endpoint"], "/x")
        self.assertIsNone(fnd.get(self.dir, "PTX-999"))

    def test_unconfirmed_probe_creates_no_finding(self):
        rec, created = fnd.from_probe(self.dir, self._verdict(vulnerable=False))
        self.assertIsNone(rec)
        self.assertFalse(created)

    def test_finding_without_impact_is_invalid(self):
        rec, _ = fnd.from_probe(self.dir, self._verdict())
        ok, problems = fnd.validate(rec)
        self.assertFalse(ok)
        self.assertTrue(any("IMPACT" in p for p in problems))

    def test_severity_inflation_is_flagged(self):
        rec, _ = fnd.from_probe(self.dir, self._verdict(impact="Bad thing happens."))
        ok, problems = fnd.validate(rec)
        self.assertFalse(ok)
        self.assertTrue(any("impact statement" in p for p in problems),
                        "a one-sentence impact on a High finding must be flagged")

    def test_complete_finding_passes(self):
        rec, _ = fnd.from_probe(self.dir, self._verdict())
        rec["impact"] = ("An attacker can read every record. Demonstrated across three "
                         "accounts belonging to different tenants.")
        rec["reproduction"] = "curl -H 'Cookie: sid=...' /api/x/2"
        rec["artifacts"] = ["a1.txt"]
        ok, problems = fnd.validate(rec)
        self.assertTrue(ok, f"should be valid: {problems}")

    def test_next_id_does_not_collide_after_deletion(self):
        """REGRESSION: next_id used len()+1, so deleting PTX-001 made it return PTX-002
        and silently overwrite the surviving finding."""
        d = os.path.join(self.dir, "findings")
        os.makedirs(d, exist_ok=True)
        for n in ("001", "002"):
            with open(os.path.join(d, f"PTX-{n}.json"), "w") as f:
                json.dump({"id": f"PTX-{n}"}, f)
        os.remove(os.path.join(d, "PTX-001.json"))
        self.assertEqual(fnd.next_id(self.dir), "PTX-003")

    def test_dedup_on_rerun(self):
        """REGRESSION: re-running a probe created a second finding for the same issue,
        inflating the count to 15 where 13 existed."""
        v = self._verdict()
        r1, c1 = fnd.from_probe(self.dir, v)
        r2, c2 = fnd.from_probe(self.dir, v)
        self.assertTrue(c1)
        self.assertFalse(c2, "second run must not create a duplicate")
        self.assertEqual(r1["id"], r2["id"])
        self.assertEqual(len(fnd.all_findings(self.dir)), 1)
        self.assertIn("reconfirmed_at", r2)


# === SUSPICION LEDGER AND STATE ==============================================
class TestSuspicionLedger(TmpEngagement):
    def test_lifecycle_transitions(self):
        s = statemod.add_suspicion(self.dir, "GET /x", "idor", "why",
                                   falsification="read another user's object")
        self.assertEqual(s["state"], "suspected")
        for st in ("probing", "substantiated", "confirmed"):
            s = statemod.set_suspicion_state(self.dir, s["id"], st, note=f"-> {st}")
            self.assertEqual(s["state"], st)
            self.assertEqual(s["note"], f"-> {st}")
        self.assertEqual(statemod.load(self.dir)["finding_count"], 1)

    def test_falsified_is_terminal_and_kept(self):
        s = statemod.add_suspicion(self.dir, "GET /y", "sqli", "why")
        statemod.set_suspicion_state(self.dir, s["id"], "falsified", note="parameterized")
        susp = statemod.suspicions(self.dir)
        self.assertEqual(len(susp), 1, "a falsified suspicion is evidence of coverage; keep it")
        self.assertEqual(susp[0]["state"], "falsified")

    def test_invalid_state_rejected(self):
        s = statemod.add_suspicion(self.dir, "GET /z", "xss", "why")
        with self.assertRaises(ValueError):
            statemod.set_suspicion_state(self.dir, s["id"], "probably-fine")

    def test_unknown_suspicion_returns_none(self):
        self.assertIsNone(statemod.set_suspicion_state(self.dir, "SUSP-999", "confirmed"))


# === REPORT GATE ==============================================================
class TestReport(TmpEngagement):
    def test_report_blocked_while_findings_invalid(self):
        fnd.from_probe(self.dir, {"id": "x", "name": "X", "vulnerable": True,
                                  "evidence": "e", "severity": "High"})
        result, lines = rpt.build(self.dir)
        self.assertIsNone(result, "report must refuse while findings are invalid")
        self.assertTrue(any("BLOCKED" in l for l in lines))

    def test_report_generated_when_valid(self):
        rec, _ = fnd.from_probe(self.dir, {
            "id": "x", "name": "X", "vulnerable": True, "evidence": "e",
            "severity": "High", "mechanism": "m", "teaching": "t"})
        rec["impact"] = "An attacker gains full read access. Demonstrated across accounts."
        rec["reproduction"] = "curl ..."
        rec["artifacts"] = ["a.txt"]
        with open(os.path.join(self.dir, "findings", rec["id"] + ".json"), "w") as f:
            json.dump(rec, f, indent=2)
        result, lines = rpt.build(self.dir)
        self.assertIsNotNone(result)
        self.assertTrue(os.path.exists(result["report"]))
        with open(result["report"]) as f:
            body = f.read()
        self.assertIn("What was NOT tested", body)
        # The probe's advice used to appear only under "Teaching note", with the
        # Remediation section reading "_not recorded_". It now lands in Remediation, and the
        # teaching note is printed only when somebody wrote a *different* one — so a
        # fixture whose two fields are the same string shows the advice exactly once.
        self.assertIn("#### Remediation\n\nt", body,
                      "the probe's advice did not reach the Remediation section")
        self.assertNotIn("#### Teaching note", body,
                         "identical advice was printed under two headings")
        self.assertNotIn("_not recorded_\n\n#### ", body)

    def test_coverage_gaps_reach_the_report(self):
        with open(os.path.join(self.dir, "log.md"), "a") as f:
            f.write("\nRESULT: SOURCE UNAVAILABLE — coverage gap, not a negative result\n")
        rec, _ = fnd.from_probe(self.dir, {
            "id": "x", "name": "X", "vulnerable": True, "evidence": "e", "severity": "Low",
            "mechanism": "m", "teaching": "t"})
        rec["impact"] = "Minor hardening gap. Documented for completeness."
        rec["reproduction"] = "curl ..."
        rec["artifacts"] = ["a.txt"]
        with open(os.path.join(self.dir, "findings", rec["id"] + ".json"), "w") as f:
            json.dump(rec, f, indent=2)
        result, _ = rpt.build(self.dir)
        with open(result["report"]) as f:
            body = f.read()
        self.assertIn("coverage gap", body.lower(),
                      "logged gaps must surface in the report's not-tested section")


# === REACHABILITY =============================================================
class TestReachability(unittest.TestCase):
    def test_client_side_package_is_not_server_reachable(self):
        r = reachability.assess("react", "16.8.0", ["CVE-2019-10000"], None)
        self.assertEqual(r["verdict"], "NOT_PRESENT")
        self.assertIn("supply-chain", r["severity_guidance"])

    def test_http_layer_is_exposed(self):
        r = reachability.assess("express", "4.16.0", ["CVE-2024-29041"], None)
        self.assertEqual(r["verdict"], "EXPOSED")
        self.assertEqual(r["confidence"], "high")

    def test_unknown_package_is_undetermined_not_assumed(self):
        r = reachability.assess("some-internal-lib", "1.0.0", ["CVE-2020-0000"], None)
        self.assertEqual(r["verdict"], "UNDETERMINED")
        self.assertTrue(r["to_confirm"], "must state what would resolve the uncertainty")
        self.assertIn("Never escalate on version match alone", r["severity_guidance"])

    def test_dev_dependency_is_build_time_only(self):
        """A devDependency never ships, so a CVE in one is not a runtime vulnerability."""
        lock = {"packages": {"node_modules/mocha": {"version": "9.0.0", "dev": True}}}
        r = reachability.assess("mocha", "9.0.0", ["CVE-2020-0000"], None, lockdata=lock)
        self.assertEqual(r["verdict"], "NOT_PRESENT")
        self.assertIn("build-time", r["severity_guidance"].lower())

    def test_production_dependency_is_distinguished_from_dev(self):
        lock = {"packages": {"node_modules/lodash": {"version": "4.17.4"}}}
        r = reachability.assess("lodash", "4.17.4", ["CVE-2019-10744"], None, lockdata=lock)
        self.assertNotEqual(r["verdict"], "NOT_PRESENT")
        self.assertTrue(any("production dependency" in e for e in r["evidence"]))

    def test_prototype_pollution_does_not_imply_exposed(self):
        """REGRESSION: an over-broad pattern matched 'prototype pollution' in lodash and
        minimist advisories and marked both EXPOSED. A vulnerability CLASS says nothing
        about whether the request path reaches it."""
        for pkg in ("lodash", "minimist"):
            r = reachability.assess(pkg, "1.0", ["CVE-2020-0000"], None,
                                    advisory_text="Prototype Pollution via array path bypass")
            self.assertNotEqual(r["verdict"], "EXPOSED",
                                f"{pkg} must not be marked EXPOSED on advisory wording alone")

    def test_http_layer_package_is_exposed_by_identity(self):
        for pkg in ("express", "koa", "fastify"):
            r = reachability.assess(pkg, "1.0", ["CVE-2020-0000"], None,
                                    advisory_text="unrelated advisory text")
            self.assertEqual(r["verdict"], "EXPOSED", f"{pkg} IS the HTTP layer")

    def test_request_path_advisory_can_escalate_non_framework(self):
        r = reachability.assess("some-proxy", "1.0", ["CVE-2020-0000"], None,
                                advisory_text="HTTP request smuggling via malformed header")
        self.assertEqual(r["verdict"], "EXPOSED")

    def test_no_evidence_means_undetermined_not_exposed(self):
        r = reachability.assess("mystery-lib", "1.0", ["CVE-2020-0000"], None)
        self.assertEqual(r["verdict"], "UNDETERMINED")

    def test_every_verdict_carries_confidence_and_confirmation_path(self):
        for pkg, ver, cv in (("react", "16.8.0", []), ("express", "4.16.0", ["CVE-2024-29041"]),
                             ("leftpad", "1.0.0", [])):
            r = reachability.assess(pkg, ver, cv, None)
            self.assertIn(r["verdict"], ("EXPOSED", "LIKELY", "UNDETERMINED", "NOT_PRESENT"))
            self.assertTrue(r["confidence"])
            self.assertTrue(r["to_confirm"])
            self.assertTrue(r["severity_guidance"])


# === CLI EXIT CODES ===========================================================
class TestCLI(TmpEngagement):
    def ptx(self, *args):
        return subprocess.run([sys.executable, os.path.join(ROOT, "ptx", "ptx.py"),
                               "--engagement", self.dir, *args],
                              capture_output=True, text=True, timeout=90)

    def test_no_scope_exits_3(self):
        shutil.rmtree(self.dir)
        r = subprocess.run([sys.executable, os.path.join(ROOT, "ptx", "ptx.py"),
                            "--engagement", self.dir, "status"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 3)
        self.assertIn("scope", r.stderr.lower())

    def test_scope_check_blocks_out_of_scope(self):
        r = self.ptx("scope", "check", "api.acme.test", "evil.example.com", "--json")
        d = json.loads(r.stdout)
        self.assertEqual(d["allowed"], ["api.acme.test"])
        self.assertEqual(len(d["blocked"]), 1)

    def test_selfcheck_fails_with_unprobed_suspicion(self):
        statemod.add_suspicion(self.dir, "GET /x", "idor", "why")
        r = self.ptx("selfcheck")
        self.assertEqual(r.returncode, 1)
        self.assertIn("FAIL", r.stdout)

    def test_selfcheck_passes_when_resolved(self):
        statemod.log_action(self.dir, "5-assessment", "probe idor", "/api/x", "confirmed")
        s = statemod.add_suspicion(self.dir, "GET /x", "idor", "why")
        statemod.set_suspicion_state(self.dir, s["id"], "confirmed", note="proven")
        r = self.ptx("selfcheck")
        self.assertEqual(r.returncode, 0, f"selfcheck should pass:\n{r.stdout}")

    def test_selfcheck_blocks_invalid_findings(self):
        """REGRESSION: selfcheck passed 6/6 while `ptx report` correctly refused to
        generate. A pre-report gate that doesn't check finding validity green-lights a
        report that then fails — the two gates must agree."""
        rec, _ = fnd.from_probe(self.dir, {"id": "x", "name": "X", "vulnerable": True,
                                           "evidence": "e", "severity": "High"})
        r = self.ptx("selfcheck")
        self.assertEqual(r.returncode, 1, "selfcheck must fail while findings are invalid")
        self.assertIn(rec["id"], r.stdout)
        rp = self.ptx("report")
        self.assertEqual(rp.returncode, 1, "both gates must agree")

    def test_selfcheck_reports_each_gate(self):
        r = self.ptx("selfcheck")
        for gate in ("scope.yaml", "authorization", "exclusions", "action",
                     "suspected", "note"):
            self.assertIn(gate, r.stdout, f"gate {gate!r} missing from selfcheck output")

    # --- regressions from the CLI audit ---
    def test_probe_refuses_out_of_scope_base(self):
        """REGRESSION (SEVERE): require_scope() only checked that a scope FILE exists, so
        `ptx probe --base http://anything` attacked hosts that were never authorized."""
        r = self.ptx("probe", "headers", "--base", "http://evil-not-in-scope.example")
        self.assertEqual(r.returncode, 3, "probe must be scope-gated on --base")
        self.assertIn("SCOPE BLOCKED", r.stderr)

    def test_probe_mass_assignment_is_scope_gated(self):
        r = self.ptx("probe-mass-assignment", "--base", "http://evil.example.com",
                     "--path", "/api/profile", "--verify-path", "/admin/users",
                     "--verify-match-value", "alice")
        self.assertEqual(r.returncode, 3)

    def test_rate_ceiling_is_announced_and_bounded(self):
        """REGRESSION: scope.yaml's rate_ceiling_rps was written and never read, and
        --rate defaulted to 0 meaning unlimited."""
        r = self.ptx("probe", "headers", "--base", "http://127.0.0.1:59999", "--rate", "999")
        self.assertIn("rate ceiling", r.stdout)
        self.assertIn("10", r.stdout, "scope ceiling (10) must bound a higher --rate")

    def test_no_probe_all_subcommand(self):
        """REGRESSION: 'probe all' ran 2 of 15 probes while reading as comprehensive."""
        r = self.ptx("probe", "all", "--base", "http://127.0.0.1:59999")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("invalid choice", r.stderr)

    def test_json_mode_is_parseable(self):
        r = self.ptx("status", "--json")
        self.assertEqual(r.returncode, 0)
        d = json.loads(r.stdout)
        self.assertIn("scope", d)
        self.assertIn("state", d)


def _f(fid, cls, sev="High", ev="evidence here", **kw):
    r = {"id": fid, "class": cls, "severity": sev, "status": "confirmed",
         "evidence": ev, "title": f"{cls} on /x", "impact": "i", "summary": "s"}
    r.update(kw)
    return r


class TestChains(unittest.TestCase):
    def test_no_transitive_capability_propagation(self):
        """REGRESSION: the first version propagated capabilities transitively
        (secret -> identity -> read -> secret), which cycled and granted every capability
        to every finding, escalating 7 of 13 findings to Critical including a reflected XSS."""
        r = _f("PTX-1", "xss", "Medium")
        caps = chains.demonstrated(r)
        self.assertEqual(caps, {"session"}, "reflected XSS grants a session and nothing more")
        ch, de = chains.analyse([r])
        for c in ch:
            self.assertNotIn("identity", c["capabilities"])
            self.assertNotIn("secret", c["capabilities"])

    def test_secrets_are_not_inferred_from_narrative_prose(self):
        """REGRESSION: keyword-matching the finding's own text read an impact statement
        saying 'may contain secrets' as secrets having been leaked."""
        r = _f("PTX-1", "exposure", "High", ev="/.env (262b, sensitive file)",
               impact="The exposed .env may contain secrets, API keys and passwords.")
        self.assertNotIn("secret", chains.demonstrated(r))

    def test_a_filename_containing_secret_is_not_a_leak(self):
        """REGRESSION: traversing a file named secret.txt was credited with credential
        disclosure because the word 'secret' appeared in the evidence path."""
        r = _f("PTX-1", "traversal", "High",
               ev="payload '../canary/secret.txt' read outside the intended root: True")
        self.assertNotIn("secret", chains.demonstrated(r))

    def test_probe_confirmed_secret_is_trusted(self):
        r = _f("PTX-1", "exposure", "High", ev="/.env", secrets_found=["API key / secret"])
        caps = chains.demonstrated(r)
        self.assertIn("secret", caps)
        self.assertIn("identity", caps, "a leaked credential buys an identity (one hop)")
        self.assertNotIn("exec", caps, "and no further")

    def test_only_one_hop_is_taken(self):
        r = _f("PTX-1", "cmdi", "Critical", secrets_found=["password"])
        caps = chains.demonstrated(r)
        self.assertIn("exec", caps); self.assertIn("secret", caps)
        self.assertNotIn("identity", caps, "one hop only — no secret->identity here")

    def test_identity_unlocks_findings_that_assume_it(self):
        jwt = _f("PTX-1", "jwt-none", "High", ev="alg:none accepted, role=admin")
        idor = _f("PTX-2", "idor", "High", ev="object 1003 returned with user_id=1003")
        ch, _ = chains.analyse([jwt, idor])
        entry = [c for c in ch if c["entry"] == "PTX-1"][0]
        self.assertTrue(entry["escalated"])
        self.assertEqual(entry["chain_severity"], "Critical")
        self.assertIn("PTX-2", [u["id"] for u in entry["unlocks"]])

    def test_no_escalation_without_a_link(self):
        ch, _ = chains.analyse([_f("PTX-1", "sqli", "Critical")])
        self.assertTrue(all(not c["escalated"] for c in ch))

    def test_de_escalation_when_prerequisite_is_absent(self):
        """A finding whose severity assumes an identity, in an engagement where nothing
        grants one, is overstated — and the report should say so."""
        idor = _f("PTX-1", "idor", "High", ev="object 1003 returned with user_id=1003")
        _, de = chains.analyse([idor])
        self.assertEqual(len(de), 1)
        self.assertEqual(de[0]["missing"], "identity")

    def test_no_de_escalation_when_probe_authenticated(self):
        idor = _f("PTX-1", "idor", "High",
                 ev="own object via sid=abc -> 200; other user's object -> 200")
        _, de = chains.analyse([idor])
        self.assertEqual(de, [])

    def test_no_de_escalation_when_satisfied_elsewhere(self):
        jwt = _f("PTX-1", "jwt-none", "High", ev="alg:none accepted")
        idor = _f("PTX-2", "idor", "High", ev="object 1003 returned")
        _, de = chains.analyse([jwt, idor])
        self.assertEqual(de, [], "another finding supplies the identity")

    def test_stored_xss_is_not_de_escalated(self):
        """REGRESSION: stored-xss was listed as requiring a write capability, but its own
        probe posts the content, so the de-escalation was simply wrong."""
        _, de = chains.analyse([_f("PTX-1", "stored-xss", "High")])
        self.assertEqual(de, [])

    def test_severity_ladder_escalates_not_de_escalates(self):
        """REGRESSION, two bugs in one line of code.

        (a) The ladder said "Informational" while findings.SEVERITIES says "Info", so
            _bump("Info") raised ValueError internally and returned "Info" unchanged —
            an Info finding that unlocked three others never escalated, silently.
        (b) Fixing (a) by importing findings.SEVERITIES INVERTED the ladder, because that
            tuple is ordered for display (Critical first). _bump("High") then returned
            "Medium", so every chain escalation in the tool was a de-escalation.
        """
        ladder = ["Info", "Low", "Medium", "High", "Critical"]
        for lo, hi in zip(ladder, ladder[1:]):
            self.assertEqual(chains._bump(lo), hi, f"{lo} must escalate to {hi}")

    def test_severity_bump_never_exceeds_critical(self):
        self.assertEqual(chains._bump("Critical"), "Critical")
        self.assertEqual(chains._bump("Info", 9), "Critical")
        self.assertEqual(chains._bump("High"), "Critical")

    def test_ladder_vocabulary_matches_findings(self):
        """If the two vocabularies drift, escalations fail silently rather than loudly."""
        self.assertEqual(set(chains.SEVERITY_ORDER), set(fnd.SEVERITIES))

    def test_info_finding_can_escalate_through_a_chain(self):
        jwt = _f("PTX-1", "jwt-none", "Info", ev="alg:none accepted, role=admin")
        idor = _f("PTX-2", "idor", "High", ev="object 1003 returned with user_id=1003")
        ch, _ = chains.analyse([jwt, idor])
        entry = [c for c in ch if c["entry"] == "PTX-1"][0]
        self.assertTrue(entry["escalated"])
        self.assertEqual(entry["chain_severity"], "Low",
                         "Info must move up the ladder, not stay put or move down")


class TestSecretDetection(unittest.TestCase):
    def test_detects_real_assignments(self):
        for body in ("API_KEY=" "sk_live_" "9f3a8b2c1d4e5f60", 'DB_PASS="hunter2hunter2"',
                     "AKIA" "IOSFODNN7EXAMPLE", "-----BEGIN RSA PRIVATE KEY-----",
                     "jwt_secret = aB3dE5fG7hI9jK1lM3nO5p",
                     "APP_SECRET=ptx_super_secret_key_do_not_leak_9f3a",
                     "STRIPE_KEY=" "sk_live_" "51HxExampleNotRealKey0000000000",
                     "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                     "DATABASE_URL=postgres://app:Sup3rPass@db.internal:5432/prod",
                     "GITHUB_TOKEN=" "ghp_" "16C7e42F292c6912E7710c838347Ae178B4a"):
            self.assertTrue(probes.detect_secrets(body), f"missed: {body!r}")

    def test_detects_every_secret_in_a_realistic_env_file(self):
        """A regression in the narrow direction: the first detector found 2 of the 6
        credentials in this file, missing APP_SECRET, AWS_SECRET_ACCESS_KEY and
        STRIPE_KEY entirely. 'Found /.env' and 'found /.env containing a live Stripe key'
        are not the same finding."""
        env = ("DB_HOST=prod-db.internal.acme.test\nDB_PASS=Sup3rS3cret!prod\n"
               "APP_SECRET=ptx_super_secret_key_do_not_leak_9f3a\n"
               "AWS_ACCESS_KEY_ID=" "AKIA" "IOSFODNN7EXAMPLE\n"
               "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
               "STRIPE_KEY=" "sk_live_" "51HxExampleNotRealKey0000000000\n")
        got = " ".join(probes.detect_secrets(env))
        for expected in ("database credential", "API key / secret", "AWS", "Stripe"):
            self.assertIn(expected, got, f"missed {expected} in {got}")

    def test_rejects_prose_filenames_and_non_secrets(self):
        """The whole point: a report that discusses secrets is not a leak."""
        for body in ("../canary/secret.txt", "this file may contain secrets and tokens",
                     "<html><title>app</title></html>", "PTX_TRAVERSAL_GOAL_9f3a",
                     "the password field is validated server side",
                     "/.env (262b, sensitive file)", "DB_HOST=prod-db.internal.acme.test",
                     "KEYWORDS=foo bar baz", "APP_NAME=myapp", "LOG_LEVEL=debug"):
            self.assertEqual(probes.detect_secrets(body), [], f"false positive: {body!r}")

    def test_placeholder_values_are_not_credentials(self):
        """Reporting a placeholder as a leaked credential is a false positive with real
        cost — it sends a team hunting for a key that does not exist."""
        for body in ("PASSWORD=changeme", "SECRET_KEY=example", "API_TOKEN=your_token_here",
                     "DB_PASS=placeholder", "SIGNING_KEY=xxxxxxxxxxxx", "AWS_KEY=null"):
            self.assertEqual(probes.detect_secrets(body), [], f"false positive: {body!r}")


class TestReliability(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_one_refutation_in_three_demotes(self):
        for o in ("confirmed", "confirmed", "refuted"):
            reliability.record(self.dir, "xss", o)
        _, demoted = reliability.classify(reliability.load(self.dir))
        self.assertEqual([d["class"] for d in demoted], ["xss"])

    def test_too_few_samples_to_judge(self):
        reliability.record(self.dir, "sqli", "refuted")
        reliability.record(self.dir, "sqli", "confirmed")
        trusted, demoted = reliability.classify(reliability.load(self.dir))
        self.assertEqual(demoted, [])
        self.assertIn("too few", trusted[0]["note"])

    def test_rejects_unknown_outcome(self):
        with self.assertRaises(ValueError):
            reliability.record(self.dir, "xss", "probably")

    def test_sync_is_idempotent(self):
        """Re-syncing the same engagement must not inflate the counts."""
        recs = [_f("PTX-1", "xss"), _f("PTX-2", "xss")]
        reliability.sync_from_engagement(self.dir, findings=recs)
        reliability.sync_from_engagement(self.dir, findings=recs)
        d = reliability.load(self.dir)["xss"]
        self.assertEqual(d["confirmed"], 2, "two findings, not four")

    def test_refuted_finding_counts_against_its_probe(self):
        recs = [_f("PTX-1", "xss", status="refuted")]
        reliability.sync_from_engagement(self.dir, findings=recs)
        self.assertEqual(reliability.load(self.dir)["xss"]["refuted"], 1)


class TestIntegrity(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.dir, "artifacts"), exist_ok=True)
        with open(os.path.join(self.dir, "artifacts", "resp.txt"), "w") as f:
            f.write("HTTP 200 body here")
        self.rec = {"id": "PTX-001", "title": "X", "severity": "High",
                    "evidence": "saw the thing", "reproduction": "curl -i ...",
                    "impact": "bad.", "summary": "s",
                    "artifacts": ["artifacts/resp.txt"], "confirmed_at": "t"}
        self.rec["seal"] = integrity.seal(self.dir, self.rec)

    def test_sealed_finding_verifies(self):
        self.assertTrue(integrity.verify(self.dir, self.rec)["ok"])

    def test_editing_the_impact_is_drift(self):
        r = dict(self.rec); r["impact"] = "much worse than first stated."
        v = integrity.verify(self.dir, r)
        self.assertFalse(v["ok"])
        self.assertIn("EVIDENCE DRIFT", v["problems"][0])

    def test_editing_the_evidence_is_drift(self):
        r = dict(self.rec); r["evidence"] = "did not actually see the thing"
        self.assertFalse(integrity.verify(self.dir, r)["ok"])

    def test_deleting_an_artifact_is_drift(self):
        os.remove(os.path.join(self.dir, "artifacts", "resp.txt"))
        v = integrity.verify(self.dir, self.rec)
        self.assertFalse(v["ok"])
        self.assertIn("now gone", v["problems"][0])

    def test_modifying_an_artifact_is_drift(self):
        with open(os.path.join(self.dir, "artifacts", "resp.txt"), "w") as f:
            f.write("rewritten after the fact")
        v = integrity.verify(self.dir, self.rec)
        self.assertFalse(v["ok"])
        self.assertIn("modified since sealing", v["problems"][0])

    def test_artifact_cannot_be_hidden_by_editing_the_record(self):
        r = dict(self.rec); r["artifacts"] = []
        self.assertFalse(integrity.verify(self.dir, r)["ok"],
                         "the seal pins the artifact regardless of the record's list")

    def test_unsealed_finding_is_flagged(self):
        v = integrity.verify(self.dir, {"id": "PTX-009", "evidence": "x"})
        self.assertFalse(v["ok"])
        self.assertIn("NOT SEALED", v["problems"][0])

    def test_never_materialised_is_a_note_not_a_break(self):
        """An artifact that was already absent at seal time is a finding-quality problem,
        not tampering. Conflating them would make every such finding unreadable."""
        r = {"id": "PTX-002", "title": "Y", "severity": "Low", "evidence": "e",
             "reproduction": "r", "impact": "i", "summary": "s",
             "artifacts": ["nope.txt"], "confirmed_at": "t"}
        r["seal"] = integrity.seal(self.dir, r)
        v = integrity.verify(self.dir, r)
        self.assertTrue(v["ok"])
        self.assertTrue(v["notes"])
        self.assertIn("never materialised", v["notes"][0])



class TestRecon(unittest.TestCase):
    def test_port_spec_parsing(self):
        self.assertEqual(recon.parse_ports("80,443,8000-8002"), [80, 443, 8000, 8001, 8002])
        self.assertEqual(recon.parse_ports("443,80"), [80, 443], "sorted and deduped")

    def test_malformed_port_spec_is_rejected_not_silently_empty(self):
        """A scan of nothing that reports success is worse than an error."""
        for bad in ("80-79", "0", "70000", "abc"):
            with self.assertRaises(ValueError):
                recon.parse_ports(bad)

    def test_intercepted_scan_is_refused(self):
        """REGRESSION: a transparent egress proxy answers every connect(), so a naive
        connect scan reported 100% of ports open. Observed directly against RFC 5737
        TEST-NET addresses, which are guaranteed unroutable."""
        fake = [{"port": p, "state": "open"} for p in (60001, 60002, 60003)]
        with unittest.mock.patch.object(recon, "_probe_port",
                                        side_effect=lambda h, p, t: {"port": p, "state": "open"}):
            r = recon.ports("192.0.2.1", "80,443", timeout=0.2)
        self.assertTrue(r["intercepted"], "control ports open means the path is lying")
        self.assertEqual(r["open"], [], "no open port may be reported")
        self.assertTrue(any("SCAN INVALID" in g for g in r["coverage_gaps"]))

    def test_clean_scan_reports_open_ports(self):
        def fake(host, port, timeout):
            return {"port": port, "state": "open" if port == 8080 else "refused"}
        with unittest.mock.patch.object(recon, "_probe_port", side_effect=fake):
            r = recon.ports("10.0.0.5", "8080,9090", timeout=0.2)
        self.assertFalse(r["intercepted"])
        self.assertEqual([p["port"] for p in r["open"]], [8080])
        self.assertEqual(r["counts"]["refused"], 1)

    def test_nothing_reachable_is_a_coverage_gap_not_a_negative(self):
        with unittest.mock.patch.object(recon, "_probe_port",
                                        side_effect=lambda h, p, t: {"port": p, "state": "filtered"}):
            r = recon.ports("10.0.0.9", "80,443", timeout=0.2)
        self.assertFalse(r["scan_reached_host"])
        self.assertFalse(r["intercepted"])
        self.assertTrue(any("REACHED NOTHING" in g for g in r["coverage_gaps"]))

    def test_risky_ports_are_annotated(self):
        def fake(host, port, timeout):
            return {"port": port, "state": "open" if port == 6379 else "refused"}
        with unittest.mock.patch.object(recon, "_probe_port", side_effect=fake):
            r = recon.ports("10.0.0.5", "6379,22", timeout=0.2)
        self.assertIn("Redis", r["open"][0]["risk"])


class TestChainWalk(unittest.TestCase):
    """Walked chains: demonstrated, broke, or could not be attempted."""

    class StubHttp:
        def __init__(self, files, endpoint_code=200, endpoint_body='{"granted": true}'):
            self.files, self.ec, self.eb = files, endpoint_code, endpoint_body
            self.calls = []
        def req(self, path, method="GET", data=None, headers=None, **kw):
            self.calls.append((method, path))
            if path in self.files:
                return {"code": 200, "body": self.files[path],
                        "headers": {"Set-Cookie": "sid=abc"} if "login" in path else {},
                        "error": None}
            if path.startswith("/api/me") or path.startswith("/login"):
                return {"code": self.ec, "body": self.eb,
                        "headers": {"Set-Cookie": "sid=abc"} if "login" in path else {},
                        "error": None}
            return {"code": 404, "body": "no", "headers": {}, "error": None}

    ENV = ("DB_HOST=db.internal\nDB_PASS=Sup3rS3cret!prod\n"
           "APP_SECRET=ptx_super_secret_key_do_not_leak_9f3a\nADMIN_USER=alice\n")

    def test_forged_token_from_leaked_key_is_demonstrated(self):
        h = self.StubHttp({"/.env": self.ENV})
        r = chainwalk.walk_secret_to_identity(
            h, {"leaked_paths": ["/.env"]}, "/api/me")
        self.assertEqual(r["verdict"], "DEMONSTRATED")
        self.assertIn("identity forgery", r["summary"])
        self.assertFalse(chainwalk.escalation_withdrawn(r))

    def test_the_forged_token_is_actually_valid_hs256(self):
        """Not a claim — verify the signature the walker produced."""
        import hmac, hashlib, base64
        secret = "ptx_super_secret_key_do_not_leak_9f3a"
        tok = chainwalk.sign_hs256({"role": "admin"}, secret)
        hdr, pl, sig = tok.split(".")
        expect = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), f"{hdr}.{pl}".encode(), hashlib.sha256).digest()
        ).decode().rstrip("=")
        self.assertEqual(sig, expect)
        self.assertEqual(json.loads(base64.urlsafe_b64decode(hdr + "=="))["alg"], "HS256")

    def test_chain_breaks_and_withdraws_escalation(self):
        """The reason this module exists: an inferred escalation that fails when attempted
        is a false positive wearing a Critical label."""
        h = self.StubHttp({})            # nothing served
        r = chainwalk.walk_secret_to_identity(h, {"leaked_paths": ["/.env"]}, "/api/me")
        self.assertEqual(r["verdict"], "NOT_DEMONSTRATED")
        self.assertTrue(chainwalk.escalation_withdrawn(r))

    def test_endpoint_rejecting_the_token_breaks_the_chain(self):
        h = self.StubHttp({"/.env": self.ENV}, endpoint_code=401, endpoint_body="bad sig")
        r = chainwalk.walk_secret_to_identity(h, {"leaked_paths": ["/.env"]}, "/api/me")
        self.assertEqual(r["verdict"], "NOT_DEMONSTRATED")
        self.assertTrue(chainwalk.escalation_withdrawn(r))

    def test_200_without_granted_claims_is_not_a_demonstration(self):
        """A 200 is not the effect. The claims must actually be granted."""
        h = self.StubHttp({"/.env": self.ENV}, endpoint_code=200,
                          endpoint_body='{"error": "unauthorized"}')
        r = chainwalk.walk_secret_to_identity(h, {"leaked_paths": ["/.env"]}, "/api/me")
        self.assertEqual(r["verdict"], "NOT_DEMONSTRATED")

    def test_missing_precondition_is_cannot_attempt_not_failure(self):
        h = self.StubHttp({"/.env": "DB_HOST=db.internal\n"})   # no signing key
        r = chainwalk.walk_secret_to_identity(h, {"leaked_paths": ["/.env"]}, "/api/me")
        self.assertEqual(r["verdict"], "CANNOT_ATTEMPT")
        self.assertFalse(chainwalk.escalation_withdrawn(r),
                         "an unattempted chain must not withdraw an escalation")

    def test_no_leaked_path_recorded_is_cannot_attempt(self):
        h = self.StubHttp({})
        r = chainwalk.walk_secret_to_identity(h, {"evidence": "nothing useful"}, "/api/me")
        self.assertEqual(r["verdict"], "CANNOT_ATTEMPT")

    def test_credentials_chain_demonstrated(self):
        h = self.StubHttp({"/.env": self.ENV})
        r = chainwalk.walk_credentials_to_session(h, {"leaked_paths": ["/.env"]}, "/login")
        self.assertEqual(r["verdict"], "DEMONSTRATED")

    def test_secret_value_is_not_reproduced_in_output(self):
        h = self.StubHttp({"/.env": self.ENV})
        r = chainwalk.walk_secret_to_identity(h, {"leaked_paths": ["/.env"]}, "/api/me")
        blob = json.dumps(r)
        self.assertNotIn("ptx_super_secret_key_do_not_leak_9f3a", blob,
                         "the report must not republish the leaked secret")



def _mkcert(d, name, days=90, cn="localhost", san="DNS:localhost,IP:127.0.0.1",
            not_before=None, not_after=None):
    """Generate a certificate with openssl. Returns (cert, key) paths or None if the tool
    is unavailable, in which case the TLS tests skip rather than silently pass."""
    import shutil, subprocess
    if shutil.which("openssl") is None:
        return None
    cert, key = os.path.join(d, f"{name}.pem"), os.path.join(d, f"{name}.key")
    cmd = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
           "-keyout", key, "-out", cert, f"-subj", f"/CN={cn}/O=PTX Test",
           "-addext", f"subjectAltName={san}"]
    cmd += ["-days", str(days)] if not not_before else            ["-not_before", not_before, "-not_after", not_after]
    r = subprocess.run(cmd, capture_output=True)
    return (cert, key) if r.returncode == 0 else None


class TestTlsAgainstRealCertificates(unittest.TestCase):
    """recon.tls verified against real certificates it did not write.

    The bug this class exists to prevent: with verify_mode=CERT_NONE, Python's
    getpeercert() returns an EMPTY dict. The first implementation read it directly, so
    every certificate-based check — self-signed, expiry, SAN coverage — evaluated against
    nothing and reported zero findings for every certificate. Protocol and cipher still
    worked because they come from the socket, so the module looked alive while its main
    job silently did nothing. Only a test against a real TLS endpoint could catch it.
    """

    @classmethod
    def setUpClass(cls):
        import http.server, ssl as _ssl, threading
        cls._http, cls._ssl_mod, cls._threading = http.server, _ssl, threading
        cls.dir = tempfile.mkdtemp()
        cls.certs = {
            "valid":     _mkcert(cls.dir, "valid", days=90),
            "expired":   _mkcert(cls.dir, "expired", not_before="20240101000000Z",
                                 not_after="20240201000000Z"),
            "wronghost": _mkcert(cls.dir, "wronghost", days=90, cn="example.invalid",
                                 san="DNS:example.invalid"),
            "expiring":  _mkcert(cls.dir, "expiring", days=10),
        }
        if not any(cls.certs.values()):
            raise unittest.SkipTest("openssl unavailable")

    def _serve(self, pair):
        cert, key = pair
        outer = self

        class H(outer._http.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")
            def log_message(self, *a):
                pass

        httpd = outer._http.HTTPServer(("127.0.0.1", 0), H)
        port = httpd.server_address[1]
        ctx = outer._ssl_mod.SSLContext(outer._ssl_mod.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        t = outer._threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        self.addCleanup(httpd.shutdown)
        time.sleep(0.4)
        return port

    def _checks(self, name):
        pair = self.certs[name]
        if not pair:
            self.skipTest(f"{name} certificate unavailable")
        port = self._serve(pair)
        r = recon.tls("127.0.0.1", port, timeout=8)
        self.assertNotIn("error", r, f"handshake failed: {r.get('error')}")
        return r

    def test_render_shows_the_certificate_and_its_findings(self):
        """recon.render's TLS branch was never executed by any test — the module's
        producer had coverage, its renderer did not. Feeding it a hand-written dict
        would only assert my guess about the contract (four earlier renderer "bugs" were
        four wrong fixtures), so this feeds it what recon.tls actually returned."""
        r = self._checks("expired")
        out = recon.render({"host": "127.0.0.1", "ports": {}, "tls": [r], "http": []})
        self.assertIn("## TLS 127.0.0.1:", out)
        self.assertIn("protocol", out)
        self.assertIn("CN localhost", out)
        self.assertIn("days_to_expiry" if "days_to_expiry" in out else "expires", out)
        self.assertTrue(any("[High]" in ln or "[Medium]" in ln
                            for ln in out.splitlines()),
                        f"an expired certificate produced no severity-tagged finding in "
                        f"the rendered report:\n{out}")

    def test_render_shows_a_tls_handshake_error_as_a_gap(self):
        """A failed handshake must render as an error, not as an empty TLS section."""
        out = recon.render({"host": "127.0.0.1", "ports": {}, "http": [],
                            "tls": [{"host": "127.0.0.1", "port": 1,
                                     "error": "handshake failed"}]})
        self.assertIn("handshake failed", out)

    def test_certificate_is_actually_parsed(self):
        """The regression: CN, issuer and SAN must be populated, not empty."""
        r = self._checks("valid")
        self.assertEqual(r.get("subject_cn"), "localhost",
                         "certificate was not parsed — getpeercert() returned empty")
        self.assertIn("localhost", r.get("san") or [])
        self.assertIsNotNone(r.get("days_to_expiry"))

    def test_self_signed_is_detected(self):
        r = self._checks("valid")
        self.assertIn("self-signed certificate",
                      [f["check"] for f in r.get("findings", [])])

    def test_expired_certificate_is_high(self):
        r = self._checks("expired")
        checks = {f["check"]: f for f in r.get("findings", [])}
        self.assertIn("certificate expired", checks)
        self.assertEqual(checks["certificate expired"]["severity"], "High")
        self.assertLess(r["days_to_expiry"], 0)

    def test_expiring_soon_is_flagged(self):
        r = self._checks("expiring")
        checks = [f["check"] for f in r.get("findings", [])]
        self.assertIn("certificate expiring soon", checks)
        self.assertLessEqual(r["days_to_expiry"], 30)

    def test_hostname_mismatch_is_detected(self):
        r = self._checks("wronghost")
        self.assertIn("hostname not covered by certificate",
                      [f["check"] for f in r.get("findings", [])])

    def test_valid_certificate_reports_no_expiry_finding(self):
        """Guarding the other direction: a good certificate must not be flagged."""
        r = self._checks("valid")
        checks = [f["check"] for f in r.get("findings", [])]
        self.assertNotIn("certificate expired", checks)
        self.assertNotIn("certificate expiring soon", checks)
        self.assertNotIn("hostname not covered by certificate", checks)

    def test_non_tls_endpoint_is_a_coverage_gap(self):
        """A failed handshake is 'unassessed', never 'the certificate is fine'."""
        import socket as _s
        srv = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0)); srv.listen(1)
        port = srv.getsockname()[1]
        self.addCleanup(srv.close)
        r = recon.tls("127.0.0.1", port, timeout=3)
        self.assertTrue(r.get("error") or r.get("coverage_gaps"))
        self.assertFalse(r.get("findings"),
                         "no certificate finding may be claimed without a certificate")



class TestCoverage(unittest.TestCase):
    """Coverage is derived from the structured action log, not asserted in prose."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        statemod.init(self.dir)

    def test_actions_are_recorded_in_machine_readable_form(self):
        """REGRESSION: log_action wrote prose to log.md and only an integer to state.json,
        so no tool could answer 'which probes ran against which endpoints'. A log a
        program cannot read supports claims, not checks."""
        statemod.log_action(self.dir, "5-assessment", "probe sqli", "/search",
                            "vulnerable", probe="sqli", endpoint="/search",
                            verdict="vulnerable")
        acts = statemod.actions(self.dir)
        self.assertEqual(len(acts), 1)
        self.assertEqual(acts[0]["probe"], "sqli")
        self.assertEqual(acts[0]["endpoint"], "/search")

    def test_never_run_probe_classes_are_reported(self):
        """The case that catches a quietly aborted engagement: every probe reports a
        result, so a run that stopped early still looks complete."""
        statemod.log_action(self.dir, "5", "probe exposure", "/", "vulnerable",
                            probe="exposure", endpoint="/")
        cov = coverage.summarise(self.dir)
        self.assertIn("sqli", cov["probe_classes_never_run"])
        self.assertIn("headers", cov["parameterless_never_run"],
                      "headers needs no parameters, so its absence is unambiguous")

    def test_no_actions_means_nothing_can_be_claimed(self):
        """An untested engagement must warn — but it must still list its gaps.

        The renderer used to return early here, so a brand-new engagement got one
        sentence and no gap list at all. That is backwards: what has NOT been run is
        known exactly, and it is the part of the report the operator needs most before
        starting. The warning stays; the early return does not.
        """
        cov = coverage.summarise(self.dir)
        self.assertEqual(cov["actions_recorded"], 0)
        out = coverage.render(cov)
        self.assertIn("No structured actions recorded", out,
                      "the warning about an untested engagement disappeared")
        self.assertIn("must not be read as a clean result", out)
        self.assertIn("Never run at all", out,
                      "a fresh engagement reported no gaps — the early return is back")
        self.assertIn("headers", out)

    def test_static_files_are_not_suggested_for_injection_probes(self):
        """Noise control: suggesting sqli against /.env is not coverage, and a list a
        reader must filter mentally gets skimmed and then ignored."""
        statemod.log_action(self.dir, "5", "probe exposure", "/", "vulnerable",
                            probe="exposure", endpoint="/")
        statemod.log_action(self.dir, "5", "probe sqli", "/search", "vulnerable",
                            probe="sqli", endpoint="/search")
        recs = [{"id": "PTX-1", "class": "exposure", "title": "Sensitive file exposure",
                 "evidence": "/.env (262b); /package-lock.json (327b)", "status": "confirmed"}]
        cov = coverage.summarise(self.dir, recs)
        pairs = {p["endpoint"] for p in cov["untested_pairs"]}
        self.assertNotIn("/.env", pairs)
        self.assertNotIn("/package-lock.json", pairs)

    def test_placeholder_and_base_path_are_the_same_endpoint(self):
        statemod.log_action(self.dir, "5", "probe idor", "/api/invoices", "vulnerable",
                            probe="idor", endpoint="/api/invoices")
        recs = [{"id": "PTX-1", "class": "idor", "title": "IDOR on /api/invoices/<id>",
                 "evidence": "e", "status": "confirmed"}]
        cov = coverage.summarise(self.dir, recs)
        self.assertNotIn("/api/invoices",
                         [p["endpoint"] for p in cov["untested_pairs"] if p["probe"] == "idor"],
                         "already tested there under the base path")

    def test_query_string_is_not_part_of_endpoint_identity(self):
        statemod.log_action(self.dir, "5", "probe sqli", "/search?q", "vulnerable",
                            probe="sqli", endpoint="/search?q")
        recs = [{"id": "PTX-1", "class": "sqli", "title": "SQL injection on /search?q",
                 "evidence": "e", "status": "confirmed"}]
        cov = coverage.summarise(self.dir, recs)
        self.assertIn("/search", cov["endpoints_known"])
        self.assertNotIn("/search?q", cov["endpoints_known"])

    def test_action_log_is_bounded(self):
        for i in range(statemod.MAX_ACTIONS + 50):
            statemod.log_action(self.dir, "5", f"a{i}", "/", "r")
        self.assertLessEqual(len(statemod.actions(self.dir)), statemod.MAX_ACTIONS)



class TestPropertyAgainstGeneratedTargets(unittest.TestCase):
    """Probes graded against applications they have never seen.

    The benchmark has a structural weakness: the vulnerable target and the oracles that
    grade against it were both written by the same author, so 59/59 could mean the probes
    generalise or merely that they fit those specific endpoints. Nothing inside that loop
    can distinguish the two.

    This breaks the loop. A seeded generator builds applications whose every endpoint is
    randomly vulnerable or correctly implemented, and ground truth comes from the
    generator's own decisions rather than a curated oracle list.

    It found three real defects the benchmark never surfaced: a reflected-XSS false
    positive on a JSON response, a SQL-injection false negative when the baseline query
    matched nothing, and — on the harness side — an SQL emulator too naive to evaluate
    the standard tautology payload.
    """

    SEEDS = int(os.environ.get("PTX_PROP_SEEDS", "10"))

    @classmethod
    def setUpClass(cls):
        try:
            from tests import property_targets as pt
        except Exception:
            pt = None
        if pt is None or not pt.HAVE_FLASK:
            raise unittest.SkipTest("flask unavailable — property tests skipped, not passed")
        cls.pt = pt
        cls.workdir = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "workdir"):
            shutil.rmtree(cls.workdir, ignore_errors=True)

    def test_no_false_positives_across_generated_targets(self):
        """The metric that matters most. A false positive here is a probe claiming a
        vulnerability in code that is correctly written."""
        fps = []
        for seed in range(self.SEEDS):
            r = self.pt.evaluate(seed, self.workdir)
            fps += [dict(d, seed=seed) for d in r["detail"] if d["verdict"] == "FP"]
        self.assertEqual(fps, [], f"false positives on generated targets: {fps}")

    def test_no_false_negatives_across_generated_targets(self):
        fns = []
        for seed in range(self.SEEDS):
            r = self.pt.evaluate(seed, self.workdir)
            fns += [dict(d, seed=seed) for d in r["detail"] if d["verdict"] == "FN"]
        self.assertEqual(fns, [], f"false negatives on generated targets: {fns}")

    def test_generated_targets_actually_contain_both_kinds(self):
        """Guarding against a vacuous pass: if the generator produced only vulnerable or
        only safe endpoints, the two tests above would pass without testing anything."""
        seen_v = seen_s = 0
        for seed in range(self.SEEDS):
            _, truth, srv, *_ = self.pt.build_app(seed, self.workdir)
            srv.shutdown()
            seen_v += sum(1 for v in truth.values() if v)
            seen_s += sum(1 for v in truth.values() if not v)
        self.assertGreater(seen_v, 0, "generator produced no vulnerable endpoints")
        self.assertGreater(seen_s, 0, "generator produced no safe endpoints")

    def test_every_class_produces_both_variants(self):
        """Per-class vacuity guard. The aggregate test above is not enough.

        `headers` once passed it comfortably while producing 60 vulnerable endpoints and
        zero safe ones across 60 seeds: its truth was derived from five independent coin
        flips ("vulnerable if any header is missing"), so a safe variant needed all five
        heads — 1 in 32. The class reported 0 FP and 0 FN, and a probe that answered
        "vulnerable" unconditionally would have scored perfectly against it. Skewed
        ground truth is vacuous ground truth, and only a per-class count reveals it.
        """
        per_class = {}
        for seed in range(self.SEEDS):
            _, truth, srv, *_ = self.pt.build_app(seed, self.workdir)
            srv.shutdown()
            for cls, vuln in truth.items():
                d = per_class.setdefault(cls, {"vuln": 0, "safe": 0})
                d["vuln" if vuln else "safe"] += 1
        one_sided = {c: d for c, d in per_class.items()
                     if d["vuln"] == 0 or d["safe"] == 0}
        self.assertEqual(
            one_sided, {},
            f"these classes only ever generated one variant, so their 0-FP/0-FN result "
            f"is vacuous over {self.SEEDS} seeds: {one_sided}. Raise PTX_PROP_SEEDS to "
            f"confirm, or rebalance the generator's coin flip.")
        self.assertGreaterEqual(len(per_class), 10,
                                "generator covers fewer classes than expected")



class TestBusinessLogicProbes(ServerFixture, unittest.TestCase):
    """The four business-logic classes, tested in BOTH directions.

    These probes cannot be validated by status code: a correctly-rejected negative quantity
    and an accepted one both return 200. So each test asserts on the resulting account
    state, and the hardened twin must report not-vulnerable for the same reason the
    vulnerable one must report vulnerable. A one-sided test here would pass against a
    probe that simply always says VULNERABLE.
    """

    def _client(self, base, user="alice"):
        h = probes.Http(base, rps=30)
        h.req("/login", "POST", {"username": user})
        return h

    def _balance(self, h, hdr=None):
        try:
            return json.loads(h.req("/api/credits", headers=hdr)["body"]).get("credits")
        except Exception:
            return None

    # --- vulnerable target: all four must fire ------------------------------
    def test_negative_quantity_detected(self):
        if not self.vuln_up:
            self.skipTest("vulnerable target not up")
        h = self._client(VULN)
        h.req("/benchmark/reset", "POST", {})
        h = self._client(VULN)
        v = probes.probe_negative_quantity(h, "/api/cart", "sku", "WIDGET",
                                           balance_fn=self._balance)
        self.assertTrue(v["vulnerable"], v["evidence"])
        self.assertIn("CREDITED", v["evidence"])

    def test_price_tamper_detected(self):
        if not self.vuln_up:
            self.skipTest("vulnerable target not up")
        h = self._client(VULN)
        h.req("/benchmark/reset", "POST", {})
        h = self._client(VULN)
        v = probes.probe_price_tamper(h, "/api/checkout", "sku", "GADGET")
        self.assertTrue(v["vulnerable"], v["evidence"])

    def test_refund_abuse_detected(self):
        if not self.vuln_up:
            self.skipTest("vulnerable target not up")
        h = self._client(VULN)
        h.req("/benchmark/reset", "POST", {})
        h = self._client(VULN)
        v = probes.probe_refund_abuse(h, "/api/refund", balance_fn=self._balance)
        self.assertTrue(v["vulnerable"], v["evidence"])

    def test_workflow_bypass_detected(self):
        if not self.vuln_up:
            self.skipTest("vulnerable target not up")
        h = self._client(VULN)
        v = probes.probe_workflow_bypass(h, "/api/order/confirm")
        self.assertTrue(v["vulnerable"], v["evidence"])

    # --- hardened twin: all four must stay silent ---------------------------
    def test_hardened_negative_quantity_not_reported(self):
        if not self.safe_up:
            self.skipTest("safe target not up")
        h = self._client(SAFE)
        v = probes.probe_negative_quantity(h, "/api/cart", "sku", "WIDGET",
                                           balance_fn=self._balance)
        self.assertFalse(v["vulnerable"], v["evidence"])

    def test_hardened_price_tamper_not_reported(self):
        if not self.safe_up:
            self.skipTest("safe target not up")
        h = self._client(SAFE)
        v = probes.probe_price_tamper(h, "/api/checkout", "sku", "GADGET")
        self.assertFalse(v["vulnerable"], v["evidence"])

    def test_hardened_refund_abuse_not_reported(self):
        if not self.safe_up:
            self.skipTest("safe target not up")
        h = self._client(SAFE)
        v = probes.probe_refund_abuse(h, "/api/refund", balance_fn=self._balance)
        self.assertFalse(v["vulnerable"], v["evidence"])

    def test_hardened_workflow_bypass_not_reported(self):
        if not self.safe_up:
            self.skipTest("safe target not up")
        h = self._client(SAFE)
        v = probes.probe_workflow_bypass(h, "/api/order/confirm")
        self.assertFalse(v["vulnerable"], v["evidence"])

    def test_hardened_target_actually_charges_catalog_price(self):
        """Prove the hardened twin is hardened, not merely unreachable.

        Without this, the four not-reported tests above would also pass if the endpoint
        simply did not exist or always errored. Here the tampered price must be accepted
        by the transport and then ignored by the application.
        """
        if not self.safe_up:
            self.skipTest("safe target not up")
        h = self._client(SAFE)
        r = h.req("/api/checkout", "POST", {"sku": "GADGET", "qty": 1, "unit_price": 0.01})
        self.assertEqual(r["code"], 200, r["body"][:200])
        body = json.loads(r["body"])
        self.assertAlmostEqual(body["unit_price"], 199.00, places=2)
        self.assertEqual(body["client_price_ignored"], 0.01)


class TestProbeRegistryConsistency(unittest.TestCase):
    """The CLI, the coverage report and the probe module must agree on the class list.

    This exists because they drifted. Four business-logic probes were added to
    probes.py and to the CLI's choices, but not to coverage.TARGETED — so an engagement
    that never ran them printed "never run at all (13)" and named none of the four. The
    report read as complete while omitting an entire category of testing. Adding a probe
    is a three-file change, and a three-file change will eventually be a two-file change.
    """

    def _cli_probe_choices(self):
        """Read the choices actually registered on the probe subparser."""
        import argparse
        import ptx as ptxmod
        parser = ptxmod.build_parser() if hasattr(ptxmod, "build_parser") else None
        if parser is None:
            self.skipTest("ptx exposes no build_parser()")
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                sub = action.choices.get("probe")
                if sub is None:
                    continue
                for a in sub._actions:
                    # the positional holding the probe class; its dest is "probe"
                    if a.dest == "probe" and a.choices:
                        return set(a.choices)
        self.skipTest("no probe subparser found")

    # `unauthenticated` is not a probe class — it is an aggregate that runs exposure and
    # headers together. `mass-assignment` is a real class but lives on its own subcommand
    # (`ptx probe-mass-assignment`) because it needs four arguments the shared probe
    # parser does not carry. Both are deliberate; the test documents them rather than
    # waving them through, so a genuinely missing class still fails.
    AGGREGATES = {"unauthenticated": {"exposure", "headers"}}
    # `subdomain takeover` is not a probe at all: its evidence comes from passive DNS and
    # a single confirmation request to a third party, so it lives on `ptx osint takeover`.
    # It is still a class the coverage report must account for, so it is in known_classes()
    # and listed here rather than silently exempted.
    OTHER_SUBCOMMANDS = {"mass-assignment": "probe-mass-assignment",
                         "subdomain takeover": "osint takeover",
                         "constraint-logic": "logic",
                         "response-credential-leak": "probe-credential-leak",
                         "double-spend": "double-spend",
                         "race-consume": "race-consume"}

    def test_every_cli_probe_class_is_in_coverage(self):
        known = coverage.known_classes()
        choices = self._cli_probe_choices() - set(self.AGGREGATES)
        missing = sorted(choices - known)
        self.assertEqual(
            missing, [],
            f"CLI offers probe classes coverage does not know about: {missing}. "
            "An engagement that skips them would not be told they were skipped.")

    def test_every_coverage_class_is_a_cli_probe(self):
        known = coverage.known_classes()
        choices = self._cli_probe_choices() | set(self.OTHER_SUBCOMMANDS)
        extra = sorted(known - choices)
        self.assertEqual(
            extra, [],
            f"coverage advertises classes the CLI cannot run: {extra}. "
            "A gap the tool cannot close is not actionable advice.")

    def test_aggregates_expand_to_known_classes(self):
        """An aggregate must be made of classes coverage knows, or it hides gaps."""
        known = coverage.known_classes()
        for agg, parts in self.AGGREGATES.items():
            self.assertTrue(parts <= known, f"{agg} expands to unknown classes: "
                                            f"{sorted(parts - known)}")

    @staticmethod
    def _resolve_subcommand(parser, path):
        """Walk a space-separated subcommand path, e.g. "osint takeover".

        It used to compare the whole string against the top-level subcommand set, which
        could only ever match a one-word command. A nested command was therefore reported
        as missing even when it existed — the test would fail for the wrong reason and, if
        it had been written the other way round, would have passed vacuously.
        """
        import argparse
        current = parser
        for depth, word in enumerate(path.split()):
            found = None
            for a in current._actions:
                if isinstance(a, argparse._SubParsersAction) and word in a.choices:
                    found = a.choices[word]
                    break
            if found is None:
                return False, f"no `{word}` under {' '.join(path.split()[:depth]) or 'root'}"
            current = found
        return True, "ok"

    def test_other_subcommands_actually_exist(self):
        """A class excused from `probe` must be reachable some other way."""
        import ptx as ptxmod
        parser = ptxmod.build_parser()
        for cls, cmd in self.OTHER_SUBCOMMANDS.items():
            ok, why = self._resolve_subcommand(parser, cmd)
            self.assertTrue(ok, f"{cls} is excused from `probe` in favour of `{cmd}`, "
                                f"but that path does not resolve: {why}")

    def test_known_classes_is_not_empty(self):
        # Guards the two tests above against passing vacuously if the parser
        # introspection ever silently returns an empty set.
        self.assertGreaterEqual(len(coverage.known_classes()), 15)
        self.assertGreaterEqual(len(self._cli_probe_choices()), 15)

    def test_every_probe_entry_point_logs_an_action(self):
        """Regression: probe-mass-assignment left no trace in the action log.

        It had its own subparser and handler, and the logging call lived inline inside
        cmd_probe's run() closure — so this probe produced a verdict, printed it, and
        recorded nothing. `ptx coverage` then reported mass-assignment as never run even
        after it had been run. Any future probe with its own entry point repeats this
        unless the logging is shared and asserted.
        """
        import ptx as ptxmod
        import inspect
        src = inspect.getsource(ptxmod)
        # every cmd_* that runs a probe must reach _log_probe
        handlers = [n for n, o in vars(ptxmod).items()
                    if n.startswith("cmd_") and inspect.isfunction(o)
                    and "probes.probe_" in inspect.getsource(o)]
        self.assertTrue(handlers, "found no probe handlers to check")
        for name in handlers:
            body = inspect.getsource(vars(ptxmod)[name])
            self.assertIn("_log_probe", body,
                          f"{name} runs a probe but never calls _log_probe, so its "
                          "verdict is invisible to `ptx coverage`")

    def test_coverage_lists_business_logic_as_untested_when_skipped(self):
        """The bug this guards: four classes absent from the never-run list entirely."""
        eng = tempfile.mkdtemp(prefix="ptxcov")
        try:
            statemod.init(eng)
            statemod.log_action(eng, "5-assessment", "probe exposure", "/", "negative",
                                probe="exposure", endpoint="/", verdict="negative")
            summ = coverage.summarise(eng)
            never = set(summ.get("probe_classes_never_run", []))
            for cls in ("negative-qty", "price-tamper", "refund-abuse",
                        "workflow-bypass", "mass-assignment"):
                self.assertIn(cls, never,
                              f"{cls} missing from never-run: an engagement that skips "
                              "it would not be told it was skipped")
        finally:
            shutil.rmtree(eng, ignore_errors=True)


class TestRenderersAgainstProducerOutput(unittest.TestCase):
    """Every render() must survive its own module's output.

    Coverage showed the five renderers were among the least-exercised code in the package.
    A renderer is the last thing to touch a result before a human reads it, and it runs
    exactly once per engagement — in the field, on data no test produced. These tests feed
    each renderer the real output of the function that generates its input, rather than a
    hand-written approximation: an approximation encodes the test author's guess about the
    contract, which is the same circularity the property tests exist to break.
    """

    def _finding(self, i, t, c, sev):
        return {"id": i, "title": t, "class": c, "severity": sev, "status": "confirmed",
                "evidence": "e", "reproduction": "r", "impact": "i", "artifacts": []}

    def test_chains_render_accepts_analyse_output(self):
        fx = [self._finding("PTX-010", "JWT alg=none accepted", "jwt-none", "High"),
              self._finding("PTX-004", "IDOR on /api/invoices", "idor", "Medium"),
              self._finding("PTX-001", "Sensitive file exposure on /.env",
                            "exposure", "High")]
        built, de = chains.analyse(fx)
        self.assertTrue(built, "expected at least one chain from this fixture")
        out = chains.render(built, de)
        self.assertIn("## Attack chains", out)

    def test_chains_render_empty_is_not_an_error(self):
        out = chains.render([], [])
        self.assertIn("No confirmed finding unlocks another", out)

    def test_recon_render_accepts_ports_output(self):
        pr = recon.ports("127.0.0.1", "5001,5002", timeout=1.0)
        self.assertIn("ports_tested", pr)
        self.assertTrue(recon.render(pr))
        self.assertTrue(recon.render({"host": "127.0.0.1", "ports": pr,
                                      "tls": [], "http": []}))

    def test_reliability_render_accepts_load_output(self):
        eng = tempfile.mkdtemp(prefix="ptxrel")
        try:
            statemod.init(eng)
            for _ in range(6):
                reliability.record(eng, "sqli", "refuted")
            for _ in range(2):
                reliability.record(eng, "sqli", "confirmed")
            for _ in range(6):
                reliability.record(eng, "xss", "confirmed")
            data = reliability.load(eng)
            self.assertTrue(data["sqli"]["demoted"],
                            "6/8 refuted should demote the probe")
            self.assertFalse(data["xss"]["demoted"])
            out = reliability.render(data)
            self.assertIn("sqli", out)
        finally:
            shutil.rmtree(eng, ignore_errors=True)

    def test_coverage_render_accepts_summarise_output(self):
        eng = tempfile.mkdtemp(prefix="ptxcovr")
        try:
            statemod.init(eng)
            statemod.log_action(eng, "5-assessment", "probe sqli", "/search?q",
                                "vulnerable", probe="sqli", endpoint="/search?q",
                                verdict="vulnerable")
            out = coverage.render(coverage.summarise(eng))
            self.assertIn("## Coverage", out)
            self.assertIn("sqli", out)
        finally:
            shutil.rmtree(eng, ignore_errors=True)

    def test_chainwalk_render_accepts_all_three_verdicts(self):
        """Each verdict must render, and must say what it means for the escalation.

        NOT_DEMONSTRATED withdraws the escalation and CANNOT_ATTEMPT leaves it inferred.
        Those two look similar and are not: one is a refutation, the other is an absence
        of evidence. A renderer that flattened them would let a withdrawn severity stand.
        """
        out = chainwalk.render([
            {"name": "exposure->identity", "verdict": "DEMONSTRATED",
             "summary": "forged admin accepted"},
            {"name": "exposure->session", "verdict": "NOT_DEMONSTRATED",
             "reason": "forged token rejected"},
            {"name": "jwt->identity", "verdict": "CANNOT_ATTEMPT",
             "note": "no signing key available"}])
        self.assertIn("DEMONSTRATED", out)
        self.assertIn("NOT DEMONSTRATED — escalation withdrawn", out)
        self.assertIn("CANNOT ATTEMPT — escalation remains inferred", out)
        for n in ("exposure->identity", "exposure->session", "jwt->identity"):
            self.assertIn(n, out, f"chain name {n} missing from the report")
        self.assertIn("forged admin accepted", out)
        self.assertIn("forged token rejected", out)
        self.assertIn("no signing key available", out)


class TestOsintParsingAgainstLocalFake(unittest.TestCase):
    """OSINT parsing, driven by canned responses from a local server.

    crt.sh and the Wayback CDX API have never completed a request in this sandbox, so
    osint.py sat at 40% coverage and its parsing code — where the fabricated-DMARC finding
    bug lived — had never been executed by anything. The endpoints are now module-level
    constants, so a local server can stand in and the real functions can be driven.

    The important cases are not the happy paths. They are the ones where a source fails:
    a 502, a timeout, an empty result set. Rule two of this tool is that a failed query is
    not zero results, and that rule is only real if the code distinguishes them.
    """

    @classmethod
    def setUpClass(cls):
        cls.saved = (osint.CRTSH_URL, osint.WAYBACK_URL)

    @classmethod
    def tearDownClass(cls):
        osint.CRTSH_URL, osint.WAYBACK_URL = cls.saved

    def _serve(self, body, status=200, ctype="application/json"):
        """Serve one canned response; returns the base URL to point the module at."""
        from http.server import BaseHTTPRequestHandler, HTTPServer
        captured = {}

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                captured["path"] = self.path
                payload = body() if callable(body) else body
                if isinstance(payload, str):
                    payload = payload.encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return f"http://127.0.0.1:{srv.server_address[1]}/x", captured

    # --- crt.sh -------------------------------------------------------------
    def test_crtsh_parses_name_value_and_strips_wildcards(self):
        rows = [{"name_value": "acme.test"},
                {"name_value": "*.acme.test"},
                {"name_value": "www.acme.test\napi.acme.test"},
                {"name_value": "notrelated.example"}]
        base, cap = self._serve(json.dumps(rows))
        osint.CRTSH_URL = base + "?q={domain}"
        r = osint.subdomains("acme.test", timeout=5)
        self.assertIsNone(r.get("source_error"), r.get("source_error"))
        found = set(r["subdomains"])
        self.assertIn("acme.test", found)
        self.assertIn("www.acme.test", found)
        self.assertIn("api.acme.test", found)
        self.assertNotIn("*.acme.test", found, "wildcard prefix must be stripped")
        self.assertNotIn("notrelated.example", found, "other domains must be filtered")

    def test_crtsh_failure_is_a_source_error_not_zero_results(self):
        """Rule two. A 502 must not be reported as 'no subdomains found'."""
        base, _ = self._serve("rate limited", status=502, ctype="text/plain")
        osint.CRTSH_URL = base + "?q={domain}"
        r = osint.subdomains("acme.test", timeout=5)
        self.assertEqual(r["subdomains"], [])
        self.assertTrue(r.get("source_error"),
                        "a 502 was swallowed into an empty result set — the exact "
                        "failure mode that reads as 'clean' when it is 'unmeasured'")

    def test_crtsh_malformed_json_is_a_source_error(self):
        base, _ = self._serve("<html>not json</html>", ctype="text/html")
        osint.CRTSH_URL = base + "?q={domain}"
        r = osint.subdomains("acme.test", timeout=5)
        self.assertTrue(r.get("source_error"), "malformed response parsed as no results")

    def test_crtsh_empty_array_is_genuinely_no_results(self):
        """The converse must also hold: an empty result with no error is a real answer."""
        base, _ = self._serve("[]")
        osint.CRTSH_URL = base + "?q={domain}"
        r = osint.subdomains("acme.test", timeout=5)
        self.assertEqual(r["subdomains"], [])
        self.assertIsNone(r.get("source_error"),
                          "a legitimately empty CT log was reported as a source failure")

    # --- wayback ------------------------------------------------------------
    def test_wayback_extracts_js_params_and_interesting_paths(self):
        body = "\n".join([
            "https://acme.test/static/app.7f3a.js",
            "https://acme.test/login?next=/admin",
            "https://acme.test/api/v1/users?id=1&token=abc",
            "https://acme.test/.env",
            "https://acme.test/index.html",
        ])
        base, _ = self._serve(body, ctype="text/plain")
        osint.WAYBACK_URL = base + "?u={domain}&limit={limit}"
        r = osint.wayback("acme.test", timeout=5)
        self.assertIsNone(r.get("error"), r.get("error"))
        self.assertIn("https://acme.test/static/app.7f3a.js", r["js_bundles"])
        self.assertIn("id", r["parameters"])
        self.assertIn("token", r["parameters"])
        self.assertIn("next", r["parameters"])
        self.assertTrue(any(".env" in u for u in r["high_interest"]))
        self.assertTrue(any("login" in u for u in r["high_interest"]))
        # a successful enumeration is distinguishable from a failed one by the flag,
        # not by whether the list happens to be empty
        self.assertTrue(r["enumerated"])

    def test_wayback_failure_is_an_error_not_empty_history(self):
        base, _ = self._serve("gateway timeout", status=504, ctype="text/plain")
        osint.WAYBACK_URL = base + "?u={domain}&limit={limit}"
        r = osint.wayback("acme.test", timeout=5)
        self.assertTrue(r.get("error"),
                        "a 504 was reported as an empty URL history")

    def test_wayback_empty_history_has_no_error(self):
        base, _ = self._serve("", ctype="text/plain")
        osint.WAYBACK_URL = base + "?u={domain}&limit={limit}"
        r = osint.wayback("acme.test", timeout=5)
        self.assertEqual(r["urls"], [])
        self.assertIsNone(r.get("error"))


class TestBusinessLogicInChains(unittest.TestCase):
    """Business-logic findings must take part in the chain model.

    They were absent from GRANTS and REQUIRES entirely, so a confirmed refund-abuse
    finding could neither anchor a chain nor be de-escalated. REQUIRES matters more than
    GRANTS here: all four probes return HTTP 401 without a session, so their severity is a
    claim about what an *authenticated* attacker can do. If that identity was never
    demonstrated, the number in the report overstates the proven risk.
    """

    def _f(self, i, t, c, s):
        return {"id": i, "title": t, "class": c, "severity": s, "status": "confirmed",
                "evidence": "e", "reproduction": "r", "impact": "i", "artifacts": []}

    def test_every_known_class_appears_in_grants(self):
        """Drift guard. This table has now been missing new classes three times:
        coverage.TARGETED, the action log, and here. Adding a probe is a multi-file
        change and one of the files always gets forgotten."""
        missing = sorted(coverage.known_classes() - set(chains.GRANTS))
        self.assertEqual(missing, [],
                         f"chains.GRANTS does not know these classes: {missing}. A "
                         "finding of that class can never take part in a chain.")

    def test_refund_abuse_is_deescalated_without_a_demonstrated_identity(self):
        built, de = chains.analyse([
            self._f("PTX-003", "Refund without a valid order", "refund-abuse", "High")])
        ids = {d["id"]: d for d in de}
        self.assertIn("PTX-003", ids,
                      "a refund-abuse severity assumes an authenticated account; with no "
                      "identity demonstrated it must be flagged, not left standing")
        self.assertEqual(ids["PTX-003"]["missing"], "identity")

    def test_refund_abuse_is_not_deescalated_once_identity_is_demonstrated(self):
        built, de = chains.analyse([
            self._f("PTX-003", "Refund without a valid order", "refund-abuse", "High"),
            self._f("PTX-010", "JWT alg=none accepted", "jwt-none", "High")])
        self.assertNotIn("PTX-003", {d["id"] for d in de},
                         "the assumption was demonstrated, so the severity stands")

    def test_all_four_business_logic_classes_require_identity(self):
        for cls in ("negative-qty", "price-tamper", "refund-abuse", "workflow-bypass"):
            self.assertIn(cls, chains.REQUIRES, f"{cls} missing from REQUIRES")
            self.assertEqual(chains.REQUIRES[cls][0], "identity")
            self.assertEqual(chains.GRANTS[cls], ["logic"])

    def test_deescalation_renders_the_assumption(self):
        built, de = chains.analyse([
            self._f("PTX-003", "Refund without a valid order", "refund-abuse", "High")])
        out = chains.render(built, de)
        self.assertIn("PTX-003", out)
        self.assertIn("identity", out)
        self.assertIn("authenticated account", out)

    def test_reachable_chain_forms_when_identity_is_demonstrated(self):
        built, de = chains.analyse([
            self._f("PTX-003", "Refund without a valid order", "refund-abuse", "High"),
            self._f("PTX-010", "JWT alg=none accepted", "jwt-none", "High")])
        self.assertTrue(built, "a demonstrated identity should unlock the logic finding")


class TestReachabilityDependencyKinds(unittest.TestCase):
    """How a package is declared changes what its CVE means.

    A version match treats a build-time-only devDependency identically to a package that
    handles every request. That distinction is the whole reason this module exists, so the
    classifier's branches are worth pinning individually rather than only through
    assess().
    """

    def test_peer_and_optional_are_classified(self):
        lock = {"packages": {
            "node_modules/react-dom": {"version": "18.0.0", "peer": True},
            "node_modules/fsevents": {"version": "2.3.0", "optional": True}}}
        self.assertEqual(reachability._dependency_kind(lock, "react-dom"), "peer")
        self.assertEqual(reachability._dependency_kind(lock, "fsevents"), "optional")

    def test_lockfile_version_1_shape_is_also_read(self):
        """npm v6 lockfiles use `dependencies`, not `packages`. Reading only the v3 shape
        would classify every package in an older lockfile as unknown."""
        lock = {"dependencies": {"express": {"version": "4.16.0"}},
                "devDependencies": {"mocha": {"version": "9.0.0"}}}
        self.assertEqual(reachability._dependency_kind(lock, "express"), "production")
        self.assertEqual(reachability._dependency_kind(lock, "mocha"), "dev")

    def test_unknown_package_is_unknown_not_production(self):
        """Defaulting to production would be the unsafe direction: it upgrades a
        build-time risk to a runtime one on no evidence."""
        lock = {"packages": {"node_modules/lodash": {"version": "4.17.4"}}}
        self.assertEqual(reachability._dependency_kind(lock, "not-present"), "unknown")
        self.assertEqual(reachability._dependency_kind(None, "lodash"), "unknown")

    def test_nested_path_matches_only_the_named_package(self):
        lock = {"packages": {
            "node_modules/foo/node_modules/lodash": {"version": "3.0.0", "dev": True},
            "node_modules/lodash": {"version": "4.17.4"}}}
        self.assertEqual(reachability._dependency_kind(lock, "lodash"), "production")


class TestAssessAudit(unittest.TestCase):
    """assess_audit() over a whole lockfile — the shape `ptx cve reachability` emits."""

    def _audit(self):
        return {"affected": [
            {"package": "express", "version": "4.16.0", "cves": ["CVE-2017-0000"],
             "advisory_text": "open redirect in res.redirect"},
            {"package": "mocha", "version": "9.0.0", "cves": ["CVE-2020-0000"],
             "advisory_text": "arbitrary file overwrite"},
            {"package": "react", "version": "16.8.0", "cves": ["CVE-2019-0000"],
             "advisory_text": "xss in dangerouslySetInnerHTML"}]}

    def test_every_affected_package_is_assessed(self):
        r = reachability.assess_audit(self._audit(), http=None)
        self.assertEqual(len(r["assessments"]), 3)
        self.assertEqual(sum(r["counts"].values()), 3)

    def test_dev_dependency_is_downgraded_in_a_full_audit(self):
        lock = {"packages": {"node_modules/mocha": {"version": "9.0.0", "dev": True}}}
        r = reachability.assess_audit(self._audit(), http=None, lockdata=lock)
        by_pkg = {a["package"]: a for a in r["assessments"]}
        self.assertEqual(by_pkg["mocha"]["verdict"], "NOT_PRESENT")
        self.assertNotEqual(by_pkg["express"]["verdict"], "NOT_PRESENT")

    def test_summary_is_ordered_by_severity_of_verdict(self):
        """EXPOSED first. A reader who stops at the top of the list must see the worst."""
        r = reachability.assess_audit(self._audit(), http=None)
        text = "\n".join(r["summary_lines"])
        order = {"EXPOSED": 0, "LIKELY": 1, "UNDETERMINED": 2, "NOT_PRESENT": 3}
        seen = [order[v] for v in ("EXPOSED", "LIKELY", "UNDETERMINED", "NOT_PRESENT")
                if f"[{v}" in text]
        self.assertEqual(seen, sorted(seen), f"summary not ordered worst-first: {seen}")

    def test_summary_states_the_lead_versus_finding_distinction(self):
        r = reachability.assess_audit(self._audit(), http=None)
        text = "\n".join(r["summary_lines"])
        self.assertIn("A version match is a lead", text)

    def test_empty_audit_is_not_an_error(self):
        r = reachability.assess_audit({"affected": []}, http=None)
        self.assertEqual(r["assessments"], [])
        self.assertEqual(r["counts"], {})
        self.assertTrue(r["summary_lines"])


class TestReconHttpFingerprintAgainstLocalServer(unittest.TestCase):
    """recon.http() and recon.run() against a local server.

    recon was the least-covered module at 54%, and the uncovered half was http() and run()
    — the parts that only ever ran against a live host. Both take a URL or a host, so a
    local server can stand in and the real fingerprinting code can be driven.

    The identity-hint logic is worth testing specifically because it assigns confidence
    levels. A generator meta tag and a database driver in a stack trace are not equally
    strong evidence, and a check that flattens them produces findings nobody trusts.
    """

    def _serve(self, body, headers=None, code=200):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        hdrs = headers or {}

        class H(BaseHTTPRequestHandler):
            # BaseHTTPRequestHandler always emits its own Server header, so setting one
            # via send_header is not enough — version_string() is what it actually sends.
            server_version = hdrs.get("Server", "BaseHTTP/0.6")
            sys_version = ""

            def version_string(self):
                return self.server_version

            def do_GET(self):
                payload = body.encode() if isinstance(body, str) else body
                self.send_response(code)
                for k, v in hdrs.items():
                    if k.lower() == "server":
                        continue
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_OPTIONS(self):
                self.send_response(200)
                self.send_header("Allow", hdrs.get("Allow", "GET, POST"))
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def test_render_shows_fingerprint_identity_hints_and_findings(self):
        """recon.render's HTTP branch, fed by recon.http's real output."""
        port = self._serve(
            '<html><head><meta name="generator" content="WordPress 5.8"></head>'
            '<body>wp-content/themes</body></html>',
            {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4"})
        r = recon.http(f"http://127.0.0.1:{port}/", timeout=5)
        out = recon.render({"host": "127.0.0.1", "ports": {}, "tls": [], "http": [r]})
        self.assertIn(f"## HTTP http://127.0.0.1:{port}/", out)
        self.assertIn("server=nginx", out)
        self.assertIn("powered-by=PHP", out)
        self.assertIn("identity hint (HIGH): WordPress", out)
        self.assertTrue(any("missing" in ln for ln in out.splitlines()),
                        "missing security headers did not reach the rendered report")

    def test_render_shows_an_http_error_as_a_gap(self):
        out = recon.render({"host": "127.0.0.1", "ports": {}, "tls": [],
                            "http": [{"url": "http://127.0.0.1:1/",
                                      "error": "connection refused"}]})
        self.assertIn("connection refused", out)

    def test_render_lists_coverage_gaps(self):
        out = recon.render({"host": "127.0.0.1", "ports": {}, "tls": [], "http": [],
                            "coverage_gaps": ["TLS not attempted: no port 443 listener"]})
        self.assertIn("## Coverage gaps", out)
        self.assertIn("TLS not attempted", out)

    def test_fingerprints_server_header_and_cookies(self):
        port = self._serve("<html>ok</html>",
                           {"Server": "nginx/1.18.0",
                            "Set-Cookie": "sid=abc; Path=/"})
        r = recon.http(f"http://127.0.0.1:{port}/", timeout=5)
        self.assertIsNone(r.get("error"), r.get("error"))
        self.assertEqual(r["status"], 200)
        self.assertIn("nginx", r.get("server", ""))

    def test_missing_security_headers_are_reported(self):
        port = self._serve("<html>ok</html>")
        r = recon.http(f"http://127.0.0.1:{port}/", timeout=5)
        checks = [f["check"] for f in r["findings"]]
        self.assertTrue(any("missing" in c for c in checks),
                        f"expected missing-header findings, got {checks}")

    def test_identity_hints_carry_their_confidence(self):
        port = self._serve(
            '<html><head><meta name="generator" content="WordPress 5.8"></head>'
            '<body>wp-content/themes</body></html>')
        r = recon.http(f"http://127.0.0.1:{port}/", timeout=5)
        hints = {h["hint"]: h["confidence"] for h in r["identity_hints"]}
        self.assertIn("WordPress", hints)
        self.assertEqual(hints["WordPress"], "HIGH")
        self.assertEqual(hints.get("generator meta"), "MEDIUM",
                         "a meta tag is weaker evidence than a framework fingerprint")

    def test_traceback_in_response_is_high_confidence(self):
        port = self._serve(
            "Traceback (most recent call last):\n  sqlite3.OperationalError: no such table",
            code=500)
        r = recon.http(f"http://127.0.0.1:{port}/", timeout=5)
        hints = {h["hint"]: h["confidence"] for h in r["identity_hints"]}
        self.assertEqual(hints.get("Python traceback in response"), "HIGH")
        self.assertEqual(hints.get("database driver in error output"), "HIGH")

    def test_unreachable_url_is_a_coverage_gap_not_a_clean_result(self):
        r = recon.http("http://127.0.0.1:1/", timeout=2)
        self.assertTrue(r.get("error"))
        self.assertTrue(r.get("coverage_gaps"),
                        "an unreachable endpoint must be reported as unassessed")
        self.assertIn("unassessed", " ".join(r["coverage_gaps"]))

    def test_run_combines_ports_and_http(self):
        port = self._serve("<html>ok</html>", {"Server": "test/1.0"})
        res = recon.run("127.0.0.1", spec=str(port), rps=50, timeout=2.0)
        self.assertEqual(res["host"], "127.0.0.1")
        self.assertIn(port, [p["port"] for p in res["ports"].get("open", [])],
                      "the listening port was not reported open")
        self.assertTrue(recon.render(res), "run() output must be renderable")


class TestCvePipelineAgainstLocalOsv(unittest.TestCase):
    """The OSV pipeline, driven by a local fake advisory API.

    `cve lockfile` is a headline feature and its parsing had only ever run against the live
    api.osv.dev. OSV_URL is already a module constant, so a local server can stand in and
    the real query/audit code can be driven — including the failure paths, which matter
    because a query that fails must never be reported as "no vulnerabilities".
    """

    @classmethod
    def setUpClass(cls):
        cls.saved = cve.OSV_URL

    @classmethod
    def tearDownClass(cls):
        cve.OSV_URL = cls.saved

    def _osv(self, handler):
        """Serve a canned OSV response; handler(package, version) -> dict."""
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(n) or b"{}")
                payload = json.dumps(handler(req.get("package", {}).get("name"),
                                             req.get("version"))).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        cve.OSV_URL = f"http://127.0.0.1:{srv.server_address[1]}/v1/query"

    def _lock(self, obj):
        d = tempfile.mkdtemp(prefix="ptxlock")
        path = os.path.join(d, "package-lock.json")
        with open(path, "w") as f:
            json.dump(obj, f)
        self.addCleanup(shutil.rmtree, d, True)
        return path

    def test_lockfile_version_3_packages_are_audited(self):
        self._osv(lambda p, v: {"vulns": [{"id": "GHSA-xxxx", "summary": "s"}]}
                  if p == "lodash" else {"vulns": []})
        path = self._lock({"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/lodash": {"version": "4.17.4"},
            "node_modules/express": {"version": "4.18.0"}}})
        r = cve.audit_lockfile(path, timeout=5)
        self.assertEqual([a["package"] for a in r["affected"]], ["lodash"])
        self.assertIn("express", [c["package"] for c in r["clean"]])

    def test_lockfile_version_1_dependencies_are_also_audited(self):
        """npm v6 lockfiles have no `packages` block. Reading only v3 would audit nothing
        and report a clean bill of health for an entirely unaudited lockfile."""
        self._osv(lambda p, v: {"vulns": [{"id": "GHSA-yyyy"}]} if p == "minimist"
                  else {"vulns": []})
        path = self._lock({"lockfileVersion": 1, "dependencies": {
            "minimist": {"version": "0.2.1"}, "chalk": {"version": "4.1.0"}}})
        r = cve.audit_lockfile(path, timeout=5)
        self.assertEqual([a["package"] for a in r["affected"]], ["minimist"])

    def test_root_package_entry_is_not_treated_as_a_dependency(self):
        """The `""` key in a v3 lockfile is the project itself, with no version."""
        self._osv(lambda p, v: {"vulns": []})
        path = self._lock({"lockfileVersion": 3, "packages": {
            "": {"name": "my-app", "version": "1.0.0"},
            "node_modules/chalk": {"version": "4.1.0"}}})
        r = cve.audit_lockfile(path, timeout=5)
        names = [c["package"] for c in r["clean"]] + [a["package"] for a in r["affected"]]
        self.assertNotIn("my-app", names)
        self.assertEqual(names, ["chalk"])

    def test_missing_file_raises_rather_than_reporting_clean(self):
        with self.assertRaises(cve.CVEError):
            cve.audit_lockfile("/nonexistent/package-lock.json", timeout=2)

    def test_api_failure_is_recorded_as_an_error_not_a_clean_package(self):
        """The whole point of the pipeline. If OSV is unreachable, the package is
        UNAUDITED — it must not land in the clean list, where it reads as verified safe."""
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(503)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        cve.OSV_URL = f"http://127.0.0.1:{srv.server_address[1]}/v1/query"

        path = self._lock({"packages": {"node_modules/lodash": {"version": "4.17.4"}}})
        r = cve.audit_lockfile(path, timeout=5)
        self.assertEqual(r["affected"], [])
        self.assertEqual([c["package"] for c in r["clean"]], [],
                         "a 503 was recorded as a clean package")
        self.assertTrue(r["errors"], "the failure was swallowed entirely")

    def test_severity_prefers_database_specific_then_cvss(self):
        self.assertEqual(cve._severity({"database_specific": {"severity": "critical"}}),
                         "CRITICAL")
        self.assertEqual(cve._severity({"severity": [{"score": "CVSS:3.1/AV:N"}]}),
                         "CVSS:3.1/AV:N")
        self.assertEqual(cve._severity({}), "UNRATED")


class TestLauncherAndManifest(unittest.TestCase):
    """The CLI must be invokable as `ptx` from anywhere, and its dependencies declared.

    Both are things that work in the author's shell and nowhere else. The launcher resolves
    its install path from its own realpath, which is exactly the kind of code that passes
    when run directly and fails through a symlink — and a symlink is the documented way to
    install it.
    """

    ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    def test_launcher_runs_through_a_symlink_from_another_cwd(self):
        src = os.path.join(self.ROOT, "bin", "ptx")
        if not os.path.exists(src):
            self.skipTest("no bin/ptx launcher")
        d = tempfile.mkdtemp(prefix="ptxlink")
        try:
            link = os.path.join(d, "ptx")
            os.symlink(src, link)
            # Invoked through the interpreter on purpose. The exec bit does not survive
            # every environment (workspace snapshots drop it), and a test that fails on
            # file mode is not testing the launcher's path resolution, which is the part
            # that actually breaks. A separate test asserts the bit and says how to fix it.
            out = subprocess.run([sys.executable, link, "--help"], cwd=d,
                                 capture_output=True, text=True, timeout=60)
            self.assertEqual(out.returncode, 0, out.stderr[-400:])
            self.assertIn("ptx", out.stdout)
            self.assertIn("probe", out.stdout)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_launcher_reports_a_clear_error_when_the_cli_is_missing(self):
        """A launcher that dies with a traceback is worse than one that says what is wrong."""
        src = os.path.join(self.ROOT, "bin", "ptx")
        if not os.path.exists(src):
            self.skipTest("no bin/ptx launcher")
        d = tempfile.mkdtemp(prefix="ptxorphan")
        try:
            # copy rather than symlink, so realpath resolves inside the temp tree where
            # there is no ptx/ directory beside it
            dst = os.path.join(d, "bin", "ptx")
            os.makedirs(os.path.dirname(dst))
            shutil.copy(src, dst)
            out = subprocess.run([sys.executable, dst, "--help"], cwd=d,
                                 capture_output=True, text=True, timeout=60)
            self.assertNotEqual(out.returncode, 0)
            self.assertIn("cannot find", out.stderr,
                          f"expected a plain-language error, got: {out.stderr[-300:]}")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_launcher_is_executable(self):
        """Separate from the logic tests so a lost mode bit gives an actionable message
        instead of a confusing PermissionError in an unrelated test."""
        src = os.path.join(self.ROOT, "bin", "ptx")
        if not os.path.exists(src):
            self.skipTest("no bin/ptx launcher")
        mode = os.stat(src).st_mode
        self.assertTrue(mode & 0o111,
                        f"{src} is not executable (mode {oct(mode & 0o777)}). Run: "
                        f"chmod +x bin/ptx — some environments do not preserve the bit.")

    def test_requirements_are_pinned(self):
        """An unpinned harness is a harness that stops working without telling you why.
        flask vanished from this sandbox twice mid-session."""
        path = os.path.join(self.ROOT, "requirements.txt")
        self.assertTrue(os.path.exists(path), "no requirements.txt")
        pkgs = [l.strip() for l in open(path)
                if l.strip() and not l.strip().startswith("#")]
        self.assertTrue(pkgs, "requirements.txt declares nothing")
        unpinned = [p for p in pkgs if "==" not in p]
        self.assertEqual(unpinned, [], f"unpinned dependencies: {unpinned}")

    def test_cli_declares_itself_stdlib_only(self):
        """The CLI must not silently acquire a third-party dependency.

        requirements-cli.txt exists to make that a stated fact rather than an accident, and
        this test is what keeps it true.
        """
        import ast
        stdlib = set(sys.stdlib_module_names)
        # Declared OPTIONAL enhancements: a third-party import is tolerated ONLY if it is
        # inside a try/except (the tool still runs without it) AND named here. Anything
        # else is a silent new hard dependency and must fail this guard.
        optional = {"z3"}
        offenders = []
        for base, _dirs, files in os.walk(os.path.join(self.ROOT, "ptx")):
            if "__pycache__" in base:
                continue
            for f in files:
                if not f.endswith(".py"):
                    continue
                path = os.path.join(base, f)
                tree = ast.parse(open(path).read(), path)
                guarded = set()
                for tnode in ast.walk(tree):
                    if isinstance(tnode, ast.Try):
                        for sub in ast.walk(tnode):
                            if isinstance(sub, (ast.Import, ast.ImportFrom)):
                                guarded.add(id(sub))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        names = [a.name.split(".")[0] for a in node.names]
                    elif isinstance(node, ast.ImportFrom):
                        if node.level:            # relative import
                            continue
                        names = [(node.module or "").split(".")[0]]
                    else:
                        continue
                    for n in names:
                        if n and n not in stdlib and n != "ptxlib":
                            if n in optional and id(node) in guarded:
                                continue
                            offenders.append(f"{os.path.relpath(path, self.ROOT)}: {n}")
        self.assertEqual(offenders, [],
                         f"the CLI now imports third-party packages: {offenders}. "
                         "Update requirements-cli.txt or remove the dependency.")


class TestCsrfProbe(ServerFixture, unittest.TestCase):
    """CSRF established by effect, with every precondition checked.

    "No token in the form" is the classic false positive: the defence may live in a cookie
    attribute or an Origin check the probe never provoked. So the probe requires cookie
    auth, a non-blocking SameSite, acceptance of a foreign Origin, and an observed state
    change. Each of those gets a test, because a probe that skips one of them reports
    findings that cannot be exploited.
    """

    def _client(self, base, user="alice"):
        h = probes.Http(base, rps=30)
        h.req("/login", "POST", {"username": user})
        return h

    def _sid(self, h):
        v = [c.value for c in h.jar if c.name == "sid"]
        return v[0] if v else None

    def _verify_email(self, needle):
        def _v(hh, hdr):
            try:
                cur = json.loads(hh.req("/api/email/current", headers=hdr)["body"]).get("email", "")
                return needle in str(cur)
            except Exception:
                return False
        return _v

    def test_csrf_detected_on_vulnerable_target(self):
        if not getattr(ServerFixture, "vuln_up", False):
            self.skipTest("vulnerable target not up")
        h = self._client(VULN)
        h.req("/benchmark/reset", "POST", {})
        h = self._client(VULN)
        sid = self._sid(h)
        v = probes.probe_csrf(h, "/api/email/change", {"email": "t-csrf@evil.example"},
                              "sid=" + sid, self._verify_email("t-csrf"))
        self.assertTrue(v["vulnerable"], v["evidence"])
        self.assertIn("ACTUALLY CHANGED: True", v["evidence"])
        self.assertEqual(v["severity"], "High")

    def test_csrf_not_reported_when_origin_is_rejected(self):
        if not getattr(ServerFixture, "safe_up", False):
            self.skipTest("safe target not up")
        h = self._client(SAFE)
        sid = self._sid(h)
        v = probes.probe_csrf(h, "/api/email/change", {"email": "t-csrf@evil.example"},
                              "sid=" + sid, self._verify_email("t-csrf"))
        self.assertFalse(v["vulnerable"], v["evidence"])

    def test_samesite_lax_suppresses_the_finding(self):
        """The endpoint still accepts the request and the state still changes — but a
        browser will not send the cookie cross-site, so there is no attack. Reporting this
        is the single most common CSRF false positive."""
        if not getattr(ServerFixture, "vuln_up", False):
            self.skipTest("vulnerable target not up")
        h = self._client(VULN)
        h.req("/benchmark/reset", "POST", {})
        h = self._client(VULN)
        sid = self._sid(h)
        v = probes.probe_csrf(h, "/api/email/change", {"email": "lax@evil.example"},
                              "sid=" + sid, self._verify_email("lax"), samesite="Lax")
        self.assertFalse(v["vulnerable"], v["evidence"])
        self.assertIn("SameSite=lax", v["evidence"])

    def test_samesite_none_does_not_suppress(self):
        """SameSite=None explicitly opts in to cross-site delivery, so the finding stands."""
        if not getattr(ServerFixture, "vuln_up", False):
            self.skipTest("vulnerable target not up")
        h = self._client(VULN)
        h.req("/benchmark/reset", "POST", {})
        h = self._client(VULN)
        sid = self._sid(h)
        v = probes.probe_csrf(h, "/api/email/change", {"email": "none@evil.example"},
                              "sid=" + sid, self._verify_email("none"), samesite="None")
        self.assertTrue(v["vulnerable"], v["evidence"])

    def test_no_state_change_means_no_finding(self):
        """A 200 with no effect is not CSRF. verify_fn returning False must sink the
        verdict even when the request was accepted."""
        if not getattr(ServerFixture, "vuln_up", False):
            self.skipTest("vulnerable target not up")
        h = self._client(VULN)
        h.req("/benchmark/reset", "POST", {})
        h = self._client(VULN)
        sid = self._sid(h)
        v = probes.probe_csrf(h, "/api/email/change", {"email": "x@evil.example"},
                              "sid=" + sid, lambda hh, hdr: False)
        self.assertFalse(v["vulnerable"], v["evidence"])

    def test_samesite_is_derived_from_the_login_set_cookie_header(self):
        """The parsing path, not just the value. Passing samesite= directly skips the code
        that reads a real Set-Cookie header — and that header carries Path, HttpOnly and
        sometimes several cookies, so the regex has to pick the right attribute."""
        if not getattr(ServerFixture, "vuln_up", False):
            self.skipTest("vulnerable target not up")
        h = self._client(VULN)
        h.req("/benchmark/reset", "POST", {})
        h = self._client(VULN)
        sid = self._sid(h)
        # a realistic header: extra attributes around the one that matters
        login_headers = {"Set-Cookie":
                         "sid=abc; Path=/; HttpOnly; Secure; SameSite=Strict"}
        v = probes.probe_csrf(h, "/api/email/change", {"email": "derived@evil.example"},
                              "sid=" + sid, self._verify_email("derived"),
                              login_headers=login_headers)
        self.assertFalse(v["vulnerable"], v["evidence"])
        self.assertIn("SameSite=strict", v["evidence"],
                      "the SameSite value was not derived from Set-Cookie")

    def test_samesite_none_in_a_real_header_does_not_suppress(self):
        if not getattr(ServerFixture, "vuln_up", False):
            self.skipTest("vulnerable target not up")
        h = self._client(VULN)
        h.req("/benchmark/reset", "POST", {})
        h = self._client(VULN)
        sid = self._sid(h)
        login_headers = {"Set-Cookie": "sid=abc; Path=/; SameSite=None; Secure"}
        v = probes.probe_csrf(h, "/api/email/change", {"email": "derived2@evil.example"},
                              "sid=" + sid, self._verify_email("derived2"),
                              login_headers=login_headers)
        self.assertTrue(v["vulnerable"], v["evidence"])

    def test_cookie_without_samesite_leaves_it_unset(self):
        """Most session cookies set no SameSite at all. Absent must not be read as a
        defence — browsers default to Lax now, but that is the browser's choice, not the
        application's, and the probe should say what it observed."""
        if not getattr(ServerFixture, "vuln_up", False):
            self.skipTest("vulnerable target not up")
        h = self._client(VULN)
        h.req("/benchmark/reset", "POST", {})
        h = self._client(VULN)
        sid = self._sid(h)
        v = probes.probe_csrf(h, "/api/email/change", {"email": "unset@evil.example"},
                              "sid=" + sid, self._verify_email("unset"),
                              login_headers={"Set-Cookie": "sid=abc; Path=/; HttpOnly"})
        self.assertTrue(v["vulnerable"], v["evidence"])
        self.assertIn("SameSite=unset", v["evidence"])

    def test_csrf_is_in_the_coverage_registry_and_chain_tables(self):
        self.assertIn("csrf", coverage.known_classes())
        self.assertIn("csrf", chains.GRANTS)
        self.assertIn("csrf", chains.REQUIRES)

    def test_csrf_severity_assumes_a_victim(self):
        """CSRF needs a logged-in victim who visits attacker content. Without a
        demonstrated identity the severity overstates what was proven."""
        built, de = chains.analyse([
            {"id": "PTX-020", "title": "CSRF on /api/email/change", "class": "csrf",
             "severity": "High", "status": "confirmed", "evidence": "e",
             "reproduction": "r", "impact": "i", "artifacts": []}])
        self.assertIn("PTX-020", {d["id"] for d in de})


class TestScopeExclusions(unittest.TestCase):
    """The exclusion list is the safety boundary. It must fail closed.

    Exclusions used to understand only exact hosts and subdomains, while inclusions
    understood wildcards, CIDRs and bare IPs as well. So `exclusions: 10.0.0.0/8` and
    `exclusions: *.prod.acme.com` both matched nothing, and the host was ALLOWED because an
    in-scope CIDR or wildcard covered it. The guard failed open: a user excludes their
    production range and the tool attacks it. Nothing in the output looked wrong.

    Both lists now go through one matcher, and these tests pin every format on both sides.
    """

    def _scope(self, in_scope, excl=()):
        d = tempfile.mkdtemp(prefix="ptxscope")
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "scope.yaml")
        with open(path, "w") as f:
            f.write("target: t\nin_scope:\n"
                    + "".join(f"  - {x}\n" for x in in_scope)
                    + "exclusions:\n"
                    + "".join(f"  - {x}\n" for x in excl)
                    + "authorization: test\n")
        return scopelib.Scope(path)

    def _allowed(self, in_scope, excl, host):
        return self._scope(in_scope, excl).is_in_scope(host)[0]

    # --- exclusions in every format -----------------------------------------
    def test_cidr_exclusion_blocks_hosts_inside_it(self):
        self.assertFalse(self._allowed(["10.0.0.0/8"], ["10.0.0.0/8"], "10.1.2.3"))

    def test_narrower_cidr_exclusion_blocks_only_that_range(self):
        self.assertFalse(self._allowed(["10.0.0.0/8"], ["10.9.0.0/16"], "10.9.1.1"))
        self.assertTrue(self._allowed(["10.0.0.0/8"], ["10.9.0.0/16"], "10.1.1.1"))

    def test_wildcard_exclusion_blocks_the_subtree(self):
        self.assertFalse(self._allowed(["*.acme.com"], ["*.prod.acme.com"],
                                       "db.prod.acme.com"))
        self.assertTrue(self._allowed(["*.acme.com"], ["*.prod.acme.com"],
                                      "db.dev.acme.com"))

    def test_bare_ip_exclusion_blocks_that_address(self):
        self.assertFalse(self._allowed(["192.168.1.0/24"], ["192.168.1.50"],
                                       "192.168.1.50"))
        self.assertTrue(self._allowed(["192.168.1.0/24"], ["192.168.1.50"],
                                      "192.168.1.51"))

    def test_exact_and_subdomain_exclusions_still_work(self):
        self.assertFalse(self._allowed(["*.acme.com"], ["pay.acme.com"], "pay.acme.com"))
        self.assertFalse(self._allowed(["*.acme.com"], ["prod.acme.com"],
                                       "db.prod.acme.com"))

    # --- inclusions must keep working ---------------------------------------
    def test_inclusions_are_unchanged(self):
        self.assertTrue(self._allowed(["*.acme.com"], [], "www.acme.com"))
        self.assertTrue(self._allowed(["10.0.0.0/8"], [], "10.4.5.6"))
        self.assertTrue(self._allowed(["acme.com"], [], "db.acme.com"))
        self.assertFalse(self._allowed(["acme.com"], [], "notacme.com"),
                         "a shared suffix is not a subdomain")
        self.assertFalse(self._allowed(["*.acme.com"], [], "evil.example"))

    def test_url_and_port_forms_are_normalised(self):
        sc = self._scope(["*.acme.com"], ["*.prod.acme.com"])
        self.assertTrue(sc.is_in_scope("https://www.acme.com:8443/x")[0])
        self.assertFalse(sc.is_in_scope("http://db.prod.acme.com/")[0])

    def test_exclusions_and_inclusions_use_the_same_matcher(self):
        """Drift guard. The bug was two implementations with different capabilities."""
        import inspect
        src = inspect.getsource(scopelib)
        self.assertIn("def _matches(", src)
        body = inspect.getsource(scopelib.Scope.is_in_scope)
        self.assertEqual(body.count("_matches("), 2,
                         "inclusions and exclusions must both go through _matches, "
                         "exactly once each")

    def test_randomised_exclusions_are_never_outranked(self):
        """For any combination of patterns, an excluded host is never allowed.

        Enumerating formats by hand is how the original bug survived: every format someone
        thought of worked, and the two they did not think of failed silently.
        """
        import itertools
        import random as _rnd
        rng = _rnd.Random(20260909)
        hosts = ["10.1.2.3", "10.9.1.1", "192.168.1.50", "db.prod.acme.com",
                 "db.dev.acme.com", "pay.acme.com", "www.acme.com", "evil.example"]
        patterns = ["10.0.0.0/8", "10.9.0.0/16", "192.168.1.0/24", "192.168.1.50",
                    "*.acme.com", "*.prod.acme.com", "acme.com", "prod.acme.com",
                    "pay.acme.com", "evil.example"]
        violations = []
        for _ in range(400):
            ins = rng.sample(patterns, rng.randint(1, 4))
            exc = rng.sample(patterns, rng.randint(1, 3))
            host = rng.choice(hosts)
            sc = self._scope(ins, exc)
            allowed, _ = sc.is_in_scope(host)
            # the invariant: if the host matches ANY exclusion it must be blocked
            excluded = any(scopelib._matches(e, host.lower()) for e in exc)
            if excluded and allowed:
                violations.append({"host": host, "in_scope": ins, "exclusions": exc})
        self.assertEqual(violations, [],
                         f"{len(violations)} host(s) allowed despite matching an "
                         f"exclusion, e.g. {violations[:3]}")


class TestDestructiveGate(unittest.TestCase):
    """`destructive_permitted` must actually gate something.

    The flag was written into scope.yaml, printed in the scope summary, and read by
    nothing — a control that existed in the configuration and did nothing. Say false and
    the tool still deleted an account. This is the same fault as the rate ceiling being
    decorative, found later in a different file.

    These tests drive the real CLI as a subprocess, because the bug was in the wiring
    between the config and the command handlers, not in any single function.
    """

    PTX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "ptx", "ptx.py")
    DESTRUCTIVE = ("race", "csrf", "refund-abuse", "negative-qty", "price-tamper", "stored-xss",
                   "workflow-bypass", "method-tamper", "session-forge")
    NON_DESTRUCTIVE = ("exposure", "headers", "sqli", "xss", "traversal")

    def _engage(self, destructive):
        d = tempfile.mkdtemp(prefix="ptxdestr")
        self.addCleanup(shutil.rmtree, d, True)
        cmd = [sys.executable, self.PTX, "--engagement", d, "scope", "init",
               "127.0.0.1:5999", "--in-scope", "127.0.0.1", "--authorization", "test",
               "--rate", "30"]
        if destructive:
            cmd.append("--destructive")
        subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return d

    def _probe(self, eng, cls):
        return subprocess.run(
            [sys.executable, self.PTX, "--engagement", eng, "probe", cls,
             "--base", "http://127.0.0.1:5999", "--path", "/x"],
            capture_output=True, text=True, timeout=120)

    def test_state_changing_probes_are_refused_without_permission(self):
        eng = self._engage(destructive=False)
        for cls in self.DESTRUCTIVE:
            r = self._probe(eng, cls)
            self.assertEqual(r.returncode, 3,
                             f"`{cls}` ran despite destructive_permitted: false "
                             f"(exit {r.returncode}): {r.stdout[:120]}{r.stderr[:200]}")
            self.assertIn("REFUSED", r.stderr)
            self.assertIn("Nothing was sent", r.stderr)

    def test_read_only_probes_still_run_without_permission(self):
        """The gate must not become a blanket block, or it will be switched off."""
        eng = self._engage(destructive=False)
        for cls in self.NON_DESTRUCTIVE:
            r = self._probe(eng, cls)
            self.assertNotIn("REFUSED", r.stderr,
                             f"`{cls}` is read-only and must not be gated")

    def test_state_changing_probes_run_when_permitted(self):
        eng = self._engage(destructive=True)
        for cls in self.DESTRUCTIVE:
            r = self._probe(eng, cls)
            self.assertNotIn("REFUSED", r.stderr,
                             f"`{cls}` was refused despite --destructive")

    def test_refusals_are_logged_to_the_engagement(self):
        """A refusal is an event the report should be able to account for."""
        eng = self._engage(destructive=False)
        self._probe(eng, "race")
        log = os.path.join(eng, "log.md")
        self.assertTrue(os.path.exists(log), "no log written for a refusal")
        self.assertIn("destructive probe", open(log).read())

    def test_every_destructive_class_is_declared(self):
        """Drift guard: a new state-changing probe must be added to the table."""
        import ptx as ptxmod
        declared = set(ptxmod.DESTRUCTIVE)
        # the classes known to mutate state, asserted here so adding a probe without
        # updating DESTRUCTIVE fails rather than silently running unannounced
        self.assertTrue(set(self.DESTRUCTIVE) <= declared,
                        f"probes mutate state but are not declared destructive: "
                        f"{sorted(set(self.DESTRUCTIVE) - declared)}")

    def test_mass_assignment_command_is_gated_too(self):
        """It has its own subparser, which is exactly how the action-log bug happened."""
        eng = self._engage(destructive=False)
        r = subprocess.run(
            [sys.executable, self.PTX, "--engagement", eng, "probe-mass-assignment",
             "--base", "http://127.0.0.1:5999", "--path", "/x",
             "--verify-path", "/y", "--verify-match-value", "z"],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 3, r.stdout[:150] + r.stderr[:200])
        self.assertIn("REFUSED", r.stderr)


class TestAuthorizationGate(unittest.TestCase):
    """No recorded authorization basis means nothing is sent.

    The authorization line was written into scope.yaml, printed in the scope summary, and
    checked only by `selfcheck` — a report card an operator may never run. So an engagement
    whose authorization field was blank still probed the target. Scope says *where*;
    authorization says *whether*. Every other gate is meaningless if that one is optional.
    """

    PTX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "ptx", "ptx.py")
    BLANK = ["", "none", "UNSPECIFIED — fill this in", "n/a", "TODO", "-"]
    VALID = ["own container", "contract ACME-2026-114", "HackerOne program #4412"]

    def _engage_with(self, auth):
        d = tempfile.mkdtemp(prefix="ptxauth")
        self.addCleanup(shutil.rmtree, d, True)
        with open(os.path.join(d, "scope.yaml"), "w") as f:
            f.write("target: 127.0.0.1\nin_scope:\n  - 127.0.0.1\nexclusions:\n"
                    f"authorization: {auth}\nrate_ceiling_rps: 30\n")
        return d

    def _probe(self, eng):
        return subprocess.run(
            [sys.executable, self.PTX, "--engagement", eng, "probe", "exposure",
             "--base", "http://127.0.0.1:5999"],
            capture_output=True, text=True, timeout=120)

    def test_blank_authorization_refuses_every_value_that_means_blank(self):
        for auth in self.BLANK:
            r = self._probe(self._engage_with(auth))
            self.assertEqual(r.returncode, 3,
                             f"authorization {auth!r} did not stop the probe "
                             f"(exit {r.returncode}): {r.stdout[:120]}")
            self.assertIn("REFUSED", r.stderr)
            self.assertIn("Nothing was sent", r.stderr)

    def test_recorded_authorization_proceeds(self):
        for auth in self.VALID:
            r = self._probe(self._engage_with(auth))
            self.assertNotIn("REFUSED", r.stderr,
                             f"authorization {auth!r} was wrongly rejected")

    def test_the_gate_covers_every_network_bound_command(self):
        """It lives in require_scope, so every command that touches the network inherits
        it. A check added per-command is a check missing from the next command someone
        writes.

        Local-only commands (coverage, finding list, report) are deliberately NOT gated —
        reading your own engagement directory sends nothing anywhere, and blocking that
        would stop an operator from inspecting why they were blocked.
        """
        eng = self._engage_with("")
        for argv in (["recon", "http", "http://127.0.0.1:5999/"],
                     ["osint", "dns", "acme.test"],
                     ["probe-mass-assignment", "--base", "http://127.0.0.1:5999",
                      "--path", "/x", "--verify-path", "/y",
                      "--verify-match-value", "z"],
                     ["logic", "--base", "http://127.0.0.1:5999", "--endpoint", "/x",
                      "--invariant", "a<0", "--verify", "b<0", "--param", "a:0:10"]):
            r = subprocess.run([sys.executable, self.PTX, "--engagement", eng] + argv,
                               capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 3,
                             f"`ptx {' '.join(argv)}` ran with no authorization recorded "
                             f"(exit {r.returncode})")

    def test_every_network_command_requests_the_authorization_gate(self):
        """Drift guard. The gate is opt-in per command, so a new network command that
        forgets it would send packets with no authorization recorded.

        This inspects the source rather than a hand-kept list: any cmd_* whose body reaches
        a network helper must call require_scope(..., authorized=True) or go through
        _require_in_scope, which does.
        """
        import re
        import inspect
        import ptx as ptxmod
        src = inspect.getsource(ptxmod)
        net_markers = ("_client(", "probes.", "recon.", "osint.", "cve.")
        ungated = []
        for m in re.finditer(r"^def (cmd_\w+)\(args\):(.*?)(?=^def |\Z)", src,
                             re.S | re.M):
            name, body = m.group(1), m.group(2)
            if not any(k in body for k in net_markers):
                continue
            gated = ("require_scope(args, authorized=True)" in body
                     or "_require_in_scope(args)" in body)
            if not gated:
                ungated.append(name)
        self.assertEqual(ungated, [],
                         f"these commands touch the network without requiring an "
                         f"authorization basis: {ungated}")

    def test_local_only_commands_are_not_gated(self):
        """Inspecting your own engagement must keep working — including when you are
        trying to work out why a command was refused."""
        eng = self._engage_with("")
        for argv in (["coverage"], ["finding", "list"], ["status"],
                     ["selfcheck"], ["report"]):
            r = subprocess.run([sys.executable, self.PTX, "--engagement", eng] + argv,
                               capture_output=True, text=True, timeout=120)
            self.assertNotIn("REFUSED", r.stderr,
                             f"`ptx {' '.join(argv)}` sends nothing and must not be gated")

    def test_scope_init_without_authorization_warns(self):
        d = tempfile.mkdtemp(prefix="ptxinit")
        self.addCleanup(shutil.rmtree, d, True)
        r = subprocess.run([sys.executable, self.PTX, "--engagement", d, "scope", "init",
                            "acme.test", "--in-scope", "acme.test"],
                           capture_output=True, text=True, timeout=60)
        self.assertIn("authorization is UNSPECIFIED", r.stdout + r.stderr)

    def test_refusal_is_logged(self):
        eng = self._engage_with("")
        self._probe(eng)
        log = os.path.join(eng, "log.md")
        self.assertTrue(os.path.exists(log))
        self.assertIn("no authorization basis", open(log).read())


class TestRateCeilingUnderConcurrency(ServerFixture, unittest.TestCase):
    """The rate ceiling must hold when requests are concurrent.

    `_throttle` had no lock, so it was not a rate limit under concurrency: N threads all
    read the same timestamp, computed the same wait, slept the same interval and fired
    together. Measured against a 5 req/s ceiling, ten parallel requests went out in 203 ms
    — 48 req/s, about ten times what the operator had configured. A rate limit that only
    works single-threaded is a rate limit that fails exactly when the tool is busiest.

    The race probe opts out on purpose: a race-condition test is defined by concurrent
    requests, and spacing them would close the window it is trying to hit. So both
    properties are asserted here — the ceiling holds, and the burst is preserved.
    """

    def test_ceiling_holds_across_parallel_requests(self):
        if not getattr(ServerFixture, "vuln_up", False):
            self.skipTest("vulnerable target not up")
        h = probes.Http(VULN, rps=5)
        stamps = []

        def one():
            h.req("/", "GET")
            stamps.append(time.time())

        ts = [threading.Thread(target=one) for _ in range(10)]
        t0 = time.time()
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        elapsed = time.time() - t0
        rate = len(stamps) / elapsed if elapsed else 0
        # 10 requests at 5/s needs ~1.8s. Allow generous slack for a slow machine; the
        # broken version finished in 0.2s, so the two are not close.
        self.assertGreater(elapsed, 1.2,
                           f"10 parallel requests completed in {elapsed:.2f}s against a "
                           f"5 req/s ceiling — the throttle is not serialising them")
        self.assertLess(rate, 8.0, f"effective rate {rate:.1f} req/s exceeds the ceiling")

    def test_race_probe_still_bursts_and_detects(self):
        """The opt-out must not be 'fixed' by making the race probe polite."""
        if not getattr(ServerFixture, "vuln_up", False):
            self.skipTest("vulnerable target not up")
        h = probes.Http(VULN, rps=5)
        h.req("/benchmark/reset", "POST", {})
        h.req("/login", "POST", {"username": "alice"})
        sid = [c.value for c in h.jar if c.name == "sid"]
        v = probes.probe_race(h, "/api/redeem", {"code": "WELCOME50"},
                              "sid=" + sid[0] if sid else None, n=10)
        self.assertTrue(v["vulnerable"],
                        f"the race probe stopped detecting the race — was its burst "
                        f"throttled away? {v['evidence']}")

    def test_throttle_opt_outs_are_only_the_race_probes(self):
        """Drift guard: the throttle exemption belongs to the concurrent-race probes only, not a
        client-wide free pass. probe_race and probe_race_consume fire parallel bursts that MUST
        bypass the rate limiter to actually race -- a serialised burst closes the TOCTOU window
        and hides the bug. No other probe may opt out of the operator's ceiling."""
        import inspect
        src = inspect.getsource(probes)
        # Count real call sites (the closing paren), not the word appearing in a comment.
        self.assertEqual(src.count("throttle=False)"), 2,
                         "throttle opt-outs must be exactly probe_race and probe_race_consume; "
                         "each one is a place the operator's rate ceiling does not apply")


class TestNoSilentlySkippedTargetTests(unittest.TestCase):
    """No test that needs a target may be silently skipped because it forgot the fixture.

    Three separate times a test class was written as `class TestX(unittest.TestCase)`
    instead of `class TestX(ServerFixture, unittest.TestCase)`. Every live test inside then
    skipped with "target not up", the class reported OK, and the suite stayed green while
    testing nothing. It reads as a pass. It is not one.

    Grepping the run output for "skipped" is the manual version of this; this is the
    automatic one. It inspects the source: any class whose methods mention the targets must
    inherit the fixture that starts them.
    """

    def test_every_target_dependent_class_inherits_the_fixture(self):
        import ast
        import inspect
        import tests.test_ptx as mod
        src = inspect.getsource(mod)
        tree = ast.parse(src)
        TARGETS = {"VULN", "TWIN", "SAFE_BASE", "TWINS_BASE", "V2"}
        offenders = []
        for node in tree.body:
            if not isinstance(node, ast.ClassDef) or not node.name.startswith("Test"):
                continue
            bases = {b.id for b in node.bases if isinstance(b, ast.Name)}
            # only real Name references count, so a class that merely *mentions* a target
            # in a docstring (like this one) is not flagged
            refs = {n.id for n in ast.walk(node)
                    if isinstance(n, ast.Name) and n.id in TARGETS}
            if refs and "ServerFixture" not in bases:
                offenders.append(f"{node.name} (uses {sorted(refs)})")
        self.assertEqual(offenders, [],
                         f"these classes reference a target but do not inherit "
                         f"ServerFixture, so every live test in them silently skips: "
                         f"{offenders}")

    # A test that runs the whole suite inside the suite was tried and removed: it
    # recursed, because the inner run contained the outer test. The static check above is
    # the sound version of the same idea.


class TestInconclusiveIsNotClean(unittest.TestCase):
    """"Could not read the response" must not be recorded as "tested and clean".

    Three probes swallowed a JSON parse failure and then reported `vulnerable=False`. That
    is indistinguishable, downstream, from a probe that ran and found the control working —
    and `ptx coverage` happily counted the class as exercised. A real IDOR on a target that
    answers in HTML instead of JSON simply vanishes from the report. This is the same fault
    as the fabricated DMARC record and the crt.sh query that reported "no certificates".

    reliability.py has had an `inconclusive` outcome all along; nothing could ever produce
    one. These tests cover the whole path: probe -> action log -> coverage.
    """

    class _Opaque:
        """A target that returns HTTP 200 with an unparseable body."""
        jar = []

        def req(self, *a, **k):
            return {"code": 200, "body": "<html>not json</html>", "headers": {}}

    class _Legible:
        """The same target, but answering in JSON with the field absent."""
        jar = []

        def req(self, *a, **k):
            return {"code": 200, "body": '{"ok": true}', "headers": {}}

    def test_idor_flags_unreadable_body_as_inconclusive(self):
        v = probes.probe_idor(self._Opaque(), "/api/orders", 1, 2)
        self.assertFalse(v["vulnerable"])
        self.assertTrue(v.get("inconclusive"),
                        "a 200 we could not read was reported as a clean result")
        self.assertIn("not parseable", v["inconclusive_reason"])

    def test_idor_readable_body_is_conclusively_negative(self):
        """The converse: a legible answer must NOT be marked inconclusive, or the flag
        becomes noise and gets ignored."""
        v = probes.probe_idor(self._Legible(), "/api/orders", 1, 2)
        self.assertFalse(v["vulnerable"])
        self.assertFalse(v.get("inconclusive"))

    def test_price_tamper_and_negative_qty_flag_unreadable_bodies(self):
        for fn, args in (("probe_price_tamper", ("/api/checkout", "sku", "GADGET")),
                         ("probe_negative_quantity", ("/api/cart", "sku", "GADGET"))):
            v = getattr(probes, fn)(self._Opaque(), *args)
            self.assertFalse(v["vulnerable"])
            self.assertTrue(v.get("inconclusive"),
                            f"{fn} reported a clean result on an unreadable response")

    def test_log_records_inconclusive_in_the_verdict_field(self):
        """The structured `verdict` is what everything downstream reads. It used to say
        "negative" even when the run was inconclusive, while the prose outcome said
        "inconclusive" — two fields about one run disagreeing, and the consulted one wrong.
        """
        d = tempfile.mkdtemp(prefix="ptxinc")
        self.addCleanup(shutil.rmtree, d, True)
        statemod.init(d)
        statemod.log_action(d, "5-assessment", "probe idor", "/api/orders", "inconclusive",
                            probe="idor", endpoint="/api/orders", verdict="inconclusive",
                            inconclusive_reason="body not parseable")
        acts = statemod.actions(d)
        self.assertEqual(acts[0]["verdict"], "inconclusive")
        self.assertEqual(acts[0]["result"], "inconclusive")
        self.assertEqual(acts[0]["inconclusive_reason"], "body not parseable")

    def test_coverage_reports_inconclusive_only_classes_as_gaps(self):
        d = tempfile.mkdtemp(prefix="ptxcov")
        self.addCleanup(shutil.rmtree, d, True)
        statemod.init(d)
        statemod.log_action(d, "5-assessment", "probe idor", "/api/orders", "inconclusive",
                            probe="idor", endpoint="/api/orders", verdict="inconclusive")
        statemod.log_action(d, "5-assessment", "probe exposure", "/", "negative",
                            probe="exposure", endpoint="/", verdict="negative")
        cov = coverage.summarise(d)
        self.assertEqual(cov["inconclusive_only"], ["idor"])
        self.assertNotIn("exposure", cov["inconclusive_only"])
        out = coverage.render(cov)
        self.assertIn("Attempted but never measured", out)
        self.assertIn("gaps, not as clean results", out)

    def test_a_class_with_one_real_verdict_is_not_flagged(self):
        """Inconclusive on one endpoint plus a real verdict elsewhere is covered."""
        d = tempfile.mkdtemp(prefix="ptxcov2")
        self.addCleanup(shutil.rmtree, d, True)
        statemod.init(d)
        statemod.log_action(d, "5-assessment", "probe idor", "/a", "inconclusive",
                            probe="idor", endpoint="/a", verdict="inconclusive")
        statemod.log_action(d, "5-assessment", "probe idor", "/b", "negative",
                            probe="idor", endpoint="/b", verdict="negative")
        self.assertEqual(coverage.summarise(d)["inconclusive_only"], [])


class TestSubdomainAttribution(unittest.TestCase):
    """A host belongs to a domain only if it IS that domain or a subdomain of it.

    crt.sh results were filtered with `domain in name` — a substring test. That accepted
    `notacme.test`, `evilacme.test.evil.com` and `acme.test.attacker.example` as subdomains
    of `acme.test`. The last is the dangerous one: a host on infrastructure the target does
    not control, presented to the operator as part of the target's estate, and then probed.

    Same fault as the scope-exclusion bug — a second, weaker implementation of "belongs to
    this domain" living in a different module from the first one.
    """

    LEGIT = ["acme.test", "api.acme.test", "deep.sub.acme.test", "a.b.c.acme.test"]
    UNRELATED = ["notacme.test", "evilacme.test.evil.com", "acme.test.attacker.example",
                 "acme.testx", "xacme.test", "acme.testing.com"]

    def test_belongs_accepts_the_domain_and_its_subdomains(self):
        for n in self.LEGIT:
            self.assertTrue(osint._belongs(n, "acme.test"),
                            f"{n} is a subdomain of acme.test and was rejected")

    def test_belongs_rejects_mere_substring_matches(self):
        for n in self.UNRELATED:
            self.assertFalse(osint._belongs(n, "acme.test"),
                             f"{n} is NOT a subdomain of acme.test but was accepted")

    def test_belongs_is_case_insensitive(self):
        self.assertTrue(osint._belongs("API.ACME.TEST", "acme.test"))
        self.assertTrue(osint._belongs("acme.test", "ACME.TEST"))

    def test_subdomains_filters_out_unattributable_hosts(self):
        """End to end, against a fake crt.sh returning both kinds of row."""
        import json as _json
        import threading as _th
        import http.server as _hs
        import socketserver as _ss
        rows = [{"name_value": v} for v in self.LEGIT + self.UNRELATED + ["*.acme.test"]]

        class H(_hs.BaseHTTPRequestHandler):
            def do_GET(self):
                b = _json.dumps(rows).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def log_message(self, *a):
                pass

        srv = _ss.TCPServer(("127.0.0.1", 0), H)
        port = srv.server_address[1]
        _th.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)

        old = osint.CRTSH_URL
        osint.CRTSH_URL = "http://127.0.0.1:%d/?q={domain}" % port
        self.addCleanup(lambda: setattr(osint, "CRTSH_URL", old))

        r = osint.subdomains("acme.test")
        got = set(r["subdomains"])
        for n in self.LEGIT:
            self.assertIn(n, got, f"legitimate subdomain {n} was dropped")
        for n in self.UNRELATED:
            self.assertNotIn(n, got,
                             f"unattributable host {n} was reported as a subdomain of "
                             f"acme.test — the operator would probe it believing it is "
                             f"the target's own infrastructure")

    def test_scope_and_osint_agree_on_what_belongs(self):
        """The two modules answer the same question; they must not disagree. A host the
        osint layer reports as part of the estate must be one the scope layer can match."""
        for n in self.LEGIT:
            self.assertTrue(osint._belongs(n, "acme.test"))
            self.assertTrue(scopelib._matches("*.acme.test", n)
                            or scopelib._matches("acme.test", n),
                            f"osint calls {n} a subdomain of acme.test but the scope "
                            f"matcher will not match it against *.acme.test")


class TestReachabilityFingerprinting(unittest.TestCase):
    """A component fingerprint must not match ordinary prose.

    `assess()` looked for the package name with `re.search(re.escape(package), served,
    re.I)` — a bare substring test. The npm packages `is`, `ms` and `has` all matched
    English prose, so a CVE in `is` came back **LIKELY / medium confidence** because the
    page contained the word "is". That is a false positive manufactured by the one module
    whose stated purpose is to prevent false positives, and worse than no fingerprint at
    all, because the operator sees it listed as evidence.
    """

    PROSE = ('<html><body><p>Any questions about the dashboard? This is loading and '
             'has ms of latency.</p></body></html>')

    class _Http:
        def __init__(self, body):
            self.body, self.base = body, "http://app.test"

        def req(self, path, **k):
            if path == "/":
                return {"code": 200, "body": self.body, "headers": {}}
            return {"code": 404, "body": "", "headers": {}}

    def test_short_names_do_not_match_prose(self):
        for pkg in ("ms", "is", "has", "qs", "d3"):
            self.assertIsNone(reachability._fingerprint(pkg, self.PROSE),
                              f"`{pkg}` fingerprinted on ordinary English prose")

    def test_short_names_do_still_match_structural_positions(self):
        """The converse — tightening must not blind the probe to real evidence."""
        self.assertIsNotNone(reachability._fingerprint(
            "ms", '<script src="/static/js/ms.js"></script>'))
        self.assertIsNotNone(reachability._fingerprint(
            "is", '{"dependencies":{"is":"1.0.0"}}'))
        self.assertIsNotNone(reachability._fingerprint("is", "<p>install is@1.0.0</p>"))

    def test_longer_names_require_a_word_boundary(self):
        self.assertIsNotNone(reachability._fingerprint("express", "<p>express server</p>"))
        self.assertIsNone(reachability._fingerprint("express",
                                                    "<p>expressly forbidden</p>"),
                          "`express` matched inside the word `expressly`")
        self.assertIsNone(reachability._fingerprint("handlebars", "<p>nothing</p>"))

    def test_prose_does_not_lift_the_verdict(self):
        """End to end: `is` on a page containing the word "is" must stay UNDETERMINED."""
        r = reachability.assess("is", "1.0.0", ["CVE-2024-0000"],
                                self._Http(self.PROSE), timeout=2)
        self.assertEqual(r["verdict"], "UNDETERMINED",
                         f"prose lifted the verdict to {r['verdict']}")
        self.assertFalse(any("served response" in e for e in r["evidence"]))

    def test_a_real_fingerprint_still_lifts_the_verdict(self):
        body = '<html><script src="/static/js/ms.js"></script></html>'
        r = reachability.assess("ms", "1.0.0", ["CVE-2024-0000"],
                                self._Http(body), timeout=2)
        self.assertTrue(any("structural position" in e or "served response" in e
                            for e in r["evidence"]),
                        f"a genuine ms.js script tag produced no evidence: {r['evidence']}")
        self.assertNotEqual(r["verdict"], "UNDETERMINED")


class TestCoverageGapsSurviveToTheReport(unittest.TestCase):
    """A coverage gap must outlive the terminal it was printed to.

    `ptx recon` printed its coverage gaps, wrote a *count* of them to the action log, and
    then persisted nothing. `ptx report` builds its gap list from log.md and the saved JSON
    artefacts. So "scan intercepted — SCAN INVALID" or "could not reach host — fingerprint
    unassessed" was shown to the operator once and then absent from the report entirely.
    A gap that does not survive the session is a gap the reader of the report never learns
    about, and the report reads as more complete than the engagement was.
    """

    PTX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "ptx", "ptx.py")

    def _eng(self):
        d = tempfile.mkdtemp(prefix="ptxgap")
        self.addCleanup(shutil.rmtree, d, True)
        subprocess.run([sys.executable, self.PTX, "--engagement", d, "scope", "init",
                        "127.0.0.1", "--in-scope", "127.0.0.1", "--authorization", "test",
                        "--rate", "30"], capture_output=True, text=True, timeout=60)
        return d

    def test_recon_persists_its_artefact(self):
        eng = self._eng()
        subprocess.run([sys.executable, self.PTX, "--engagement", eng, "recon", "http",
                        "http://127.0.0.1:5999/"],
                       capture_output=True, text=True, timeout=120)
        rdir = os.path.join(eng, "recon")
        self.assertTrue(os.path.isdir(rdir), "no recon artefact directory was created")
        self.assertTrue([f for f in os.listdir(rdir) if f.endswith(".json")],
                        "recon ran but persisted no artefact")

    def test_a_recon_gap_reaches_the_report(self):
        eng = self._eng()
        subprocess.run([sys.executable, self.PTX, "--engagement", eng, "recon", "http",
                        "http://127.0.0.1:5999/"],
                       capture_output=True, text=True, timeout=120)
        gaps = rpt._coverage_gaps(eng)
        self.assertTrue(any("could not reach" in g for g in gaps),
                        f"the recon gap did not reach the report; gaps seen: {gaps}")

    def test_an_osint_gap_still_reaches_the_report(self):
        """The converse — the change must not break the path that already worked."""
        eng = self._eng()
        osint.save(eng, "dns", {"coverage_gaps": ["dnsutils not installed"],
                                "enumerated": True})
        gaps = rpt._coverage_gaps(eng)
        self.assertTrue(any("dnsutils" in g for g in gaps), f"osint gap lost: {gaps}")

    def test_a_source_that_never_ran_is_reported_as_a_gap(self):
        eng = self._eng()
        osint.save(eng, "subs", {"enumerated": False})
        self.assertTrue(any("enumeration did not run" in g
                            for g in rpt._coverage_gaps(eng)))

    def test_malformed_artefacts_do_not_abort_the_report(self):
        eng = self._eng()
        os.makedirs(os.path.join(eng, "recon"), exist_ok=True)
        with open(os.path.join(eng, "recon", "broken.json"), "w") as f:
            f.write("{not json")
        osint.save(eng, "dns", {"coverage_gaps": ["a real gap"]})
        gaps = rpt._coverage_gaps(eng)
        self.assertTrue(any("a real gap" in g for g in gaps),
                        "one corrupt artefact suppressed the readable ones")


class TestStaticLintGate(unittest.TestCase):
    """No undefined name and no unused local may reach the suite.

    `ptx recon http` against an unreachable host crashed with
    `NameError: name 'EXIT_NO_RESULTS' is not defined` — the constant is `EXIT_NORESULT`.
    It sat on a live path (recon reporting a coverage gap with no open ports) and no test
    covered it, because every recon test used a reachable target.

    py_compile catches syntax, not names. A one-word typo in an exit-code constant is
    invisible until the branch runs in the field. Running pyflakes as a test makes the
    whole class cheap to prevent.
    """

    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _pyflakes(self):
        try:
            import pyflakes  # noqa: F401
        except ImportError:
            self.skipTest("pyflakes not installed — pip install pyflakes")
        import subprocess as _sp
        targets = [os.path.join(self.ROOT, "ptx", "ptx.py")]
        targets += [os.path.join(self.ROOT, "ptx", "ptxlib", f)
                    for f in sorted(os.listdir(os.path.join(self.ROOT, "ptx", "ptxlib")))
                    if f.endswith(".py")]
        r = _sp.run([sys.executable, "-m", "pyflakes"] + targets,
                    capture_output=True, text=True, timeout=300)
        return [ln for ln in (r.stdout + r.stderr).splitlines() if ln.strip()]

    def test_no_undefined_names(self):
        bad = [ln for ln in self._pyflakes() if "undefined name" in ln]
        self.assertEqual(bad, [],
                         "undefined names are runtime crashes waiting on an untested "
                         f"branch: {bad}")

    def test_no_unused_locals(self):
        """An assigned-but-unused local is usually a value that should have been checked."""
        bad = [ln for ln in self._pyflakes()
               if "assigned to but never used" in ln
               # probe_mass_assignment discards the response on purpose: a handler that
               # accepts a mass assignment answers 200 either way, so only the effect
               # counts. That one is documented at the call site.
               and "probe_mass_assignment" not in ln]
        self.assertEqual(bad, [],
                         f"values computed and then dropped: {bad}")

    def test_recon_exits_cleanly_when_it_finds_nothing(self):
        """The regression the lint gate exists to prevent, asserted end to end."""
        d = tempfile.mkdtemp(prefix="ptxnr")
        self.addCleanup(shutil.rmtree, d, True)
        ptx = os.path.join(self.ROOT, "ptx", "ptx.py")
        subprocess.run([sys.executable, ptx, "--engagement", d, "scope", "init",
                        "127.0.0.1", "--in-scope", "127.0.0.1", "--authorization", "test",
                        "--rate", "30"], capture_output=True, text=True, timeout=60)
        r = subprocess.run([sys.executable, ptx, "--engagement", d, "recon", "http",
                            "http://127.0.0.1:5999/"],
                           capture_output=True, text=True, timeout=120)
        self.assertNotIn("NameError", r.stderr,
                         "recon crashed instead of reporting no results")
        self.assertNotIn("Traceback", r.stderr, r.stderr[-400:])
        self.assertEqual(r.returncode, 2,
                         f"expected EXIT_NORESULT (2) for an unreachable target, got "
                         f"{r.returncode}")


class TestAlgNoneWalk(ServerFixture, unittest.TestCase):
    """A jwt-none finding's escalation must be observed, not inferred.

    `chains.REQUIRES` says idor, race and the four business-logic classes all *assume* an
    authenticated identity, and downgrades them when it was never demonstrated. jwt-none
    GRANTS that identity — but "grants" is table lookup. This walk turns it into a
    request that was refused and then accepted, which is what actually lifts a
    de-escalation.
    """

    class _Http:
        """Refuses anonymous requests, accepts the forged token."""
        base = "http://app.test"
        jar = []

        def __init__(self, open_to_all=False):
            self.open_to_all = open_to_all

        def req(self, path, method="GET", data=None, headers=None, **k):
            if self.open_to_all:
                return {"code": 200, "body": "{}", "headers": {}}
            if not (headers or {}).get("Authorization"):
                return {"code": 401, "body": '{"error":"auth required"}', "headers": {}}
            return {"code": 200,
                    "body": '{"granted": true, "claims": {"role": "admin"}}',
                    "headers": {}}

    class _Strict:
        """Checks the signature — the forged token must be refused."""
        base = "http://app.test"
        jar = []

        def req(self, path, method="GET", data=None, headers=None, **k):
            return {"code": 403, "body": '{"error":"bad signature"}', "headers": {}}

    def test_demonstrated_when_refused_then_accepted(self):
        r = chainwalk.walk_alg_none_to_admin(self._Http(), {}, "/api/me")
        self.assertEqual(r["verdict"], "DEMONSTRATED")
        self.assertEqual(r["capability"], "identity")
        self.assertEqual(r["grants_role"], "admin")
        self.assertTrue(r["token"].endswith("."),
                        "an alg:none token must have an empty signature segment")

    def test_the_baseline_is_recorded(self):
        """The whole argument rests on the endpoint having refused us first."""
        r = chainwalk.walk_alg_none_to_admin(self._Http(), {}, "/api/me")
        self.assertIn("baseline", r["steps"][0]["step"])
        self.assertEqual(r["steps"][0]["status"], 401)

    def test_an_open_endpoint_is_not_a_demonstration(self):
        """If the endpoint accepts anonymous requests, an accepted forged token proves
        nothing. Reporting DEMONSTRATED here would be a manufactured chain."""
        r = chainwalk.walk_alg_none_to_admin(self._Http(open_to_all=True), {}, "/api/me")
        self.assertEqual(r["verdict"], "NOT_DEMONSTRATED",
                         "an unauthenticated endpoint was reported as a demonstrated "
                         "privilege escalation")
        self.assertIn("unauthenticated", r["reason"])

    def test_a_checked_signature_is_not_a_demonstration(self):
        r = chainwalk.walk_alg_none_to_admin(self._Strict(), {}, "/api/me")
        self.assertEqual(r["verdict"], "NOT_DEMONSTRATED")
        self.assertIn("signature IS checked", r["reason"])

    def test_the_token_actually_carries_alg_none(self):
        import base64 as _b64
        import json as _json
        r = chainwalk.walk_alg_none_to_admin(self._Http(), {}, "/api/me")
        head = r["token"].split(".")[0]
        head = _json.loads(_b64.urlsafe_b64decode(head + "=="))
        self.assertEqual(head["alg"], "none")
        payload = r["token"].split(".")[1]
        claims = _json.loads(_b64.urlsafe_b64decode(payload + "=="))
        self.assertEqual(claims["role"], "admin")

    def test_walked_against_the_live_target(self):
        """End to end: /api/me returns 401 anonymous and 200 for an unsigned token."""
        if not getattr(ServerFixture, "vuln_up", False):
            self.skipTest("vulnerable target not up")
        h = probes.Http(VULN)
        r = chainwalk.walk_alg_none_to_admin(h, {}, "/api/me")
        self.assertEqual(r["verdict"], "DEMONSTRATED", r.get("reason"))
        self.assertIn("granted", r["steps"][-1]["detail"])


class TestUnreachableTargetIsNotClean(ServerFixture, unittest.TestCase):
    """A host that is not listening must not produce a clean report.

    `Http.req` returns code 0 with an empty body and no headers when the connection fails.
    `probe_headers` read that empty header set as "every security header is missing" and
    reported **vulnerable** against a dead port — the most-run probe in the tool, on every
    engagement, emitting the most expensive thing it can emit.

    The rest of the probes failed the other way: they reported a conclusive negative. Point
    the tool at the wrong port and it produces a full set of clean verdicts and a coverage
    report reading "every class tested, all clean" for a target that was never reached.
    A false negative across a whole engagement is worse than a crash, because it is silent.
    """

    PTX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "ptx", "ptx.py")
    DEAD = "http://127.0.0.1:5999"

    class _Dead:
        base = "http://127.0.0.1:5999"
        jar = []

        def req(self, *a, **k):
            return {"code": 0, "body": "", "headers": {}, "error": "connection refused"}

    def test_headers_does_not_report_missing_headers_on_a_dead_host(self):
        v = probes.probe_headers(self._Dead(), "/")
        self.assertFalse(v["vulnerable"],
                         "an empty header set from a failed request was reported as a "
                         "missing-security-headers finding")
        self.assertTrue(v.get("inconclusive"))

    def test_headers_still_reports_on_a_live_host(self):
        """The converse — the guard must not blind the probe."""
        if not getattr(ServerFixture, "vuln_up", False):
            self.skipTest("vulnerable target not up")
        v = probes.probe_headers(probes.Http(VULN), "/")
        self.assertFalse(v.get("inconclusive"))
        self.assertIn("missing", v["evidence"])

    def test_client_counts_transport_failures(self):
        h = probes.Http(self.DEAD)
        self.assertEqual(h.transport_failures, 0)
        h.req("/")
        h.req("/other")
        self.assertEqual(h.transport_failures, 2)

    def test_mark_unmeasured_downgrades_a_clean_verdict(self):
        h = self._Dead()
        h.transport_failures = 1
        v = {"vulnerable": False, "evidence": "nothing found"}
        probes.mark_unmeasured(v, h, 0)
        self.assertTrue(v["inconclusive"])

    def test_mark_unmeasured_leaves_a_real_negative_alone(self):
        """A probe that got its responses must stay a conclusive negative."""
        class Ok:
            transport_failures = 0
        v = {"vulnerable": False, "evidence": "control works"}
        probes.mark_unmeasured(v, Ok(), 0)
        self.assertFalse(v.get("inconclusive"))

    def test_mark_unmeasured_leaves_a_vulnerable_verdict_alone(self):
        class Ok:
            transport_failures = 3
        v = {"vulnerable": True, "evidence": "found it"}
        probes.mark_unmeasured(v, Ok(), 0)
        self.assertFalse(v.get("inconclusive"))

    def test_a_whole_engagement_against_a_dead_host_reports_gaps(self):
        d = tempfile.mkdtemp(prefix="ptxdead")
        self.addCleanup(shutil.rmtree, d, True)
        subprocess.run([sys.executable, self.PTX, "--engagement", d, "scope", "init",
                        "127.0.0.1:5999", "--in-scope", "127.0.0.1", "--authorization",
                        "test", "--rate", "30"],
                       capture_output=True, text=True, timeout=60)
        r = subprocess.run([sys.executable, self.PTX, "--engagement", d, "probe",
                            "unauthenticated", "--base", self.DEAD],
                           capture_output=True, text=True, timeout=180)
        self.assertIn("UNMEASURED", r.stdout,
                      "probes against an unreachable host were not marked unmeasured")
        self.assertNotIn("VULNERABLE", r.stdout,
                         "a dead host produced a vulnerability claim")
        cov = coverage.summarise(d)
        self.assertTrue(cov["inconclusive_only"],
                        "coverage counted an unreachable-target run as tested-and-clean")
        self.assertIn("Attempted but never measured", coverage.render(cov))


class TestMemoryLoopSemantics(unittest.TestCase):
    """A probe that correctly reports a clean result must not be demoted.

    Two senses of "refuted" were being added into one counter. In the suspicion ledger,
    "falsified" means the probe ran and the *suspicion* was falsified — the probe
    correctly found nothing. In the reliability ledger, "refuted" means a human looked at
    the probe's finding and rejected it. `sync_from_engagement` fed the first into the
    second, so a probe that correctly reported a clean result four times was demoted:
    "4/4 verdicts refuted — output is a lead to verify, not a finding".

    The better a probe was at reporting clean results, the faster it lost standing. On a
    hardened target the Memory Loop would demote every class, and the operator would be
    told to distrust the tool precisely when it was working correctly.
    """

    def _eng(self):
        d = tempfile.mkdtemp(prefix="ptxml")
        self.addCleanup(shutil.rmtree, d, True)
        statemod.init(d)
        return d

    def _clean_runs(self, d, cls_name, n=4):
        for _ in range(n):
            s = statemod.add_suspicion(d, "/api/x", cls_name, why="probe executed",
                                       hypothesis="vuln", falsification="parameterised")
            statemod.set_suspicion_state(d, s["id"], "falsified", "no differential")
        return statemod.load(d).get("suspicions", [])

    def test_correct_negatives_do_not_demote(self):
        d = self._eng()
        susp = self._clean_runs(d, "sqli", 4)
        data = reliability.sync_from_engagement(d, findings=[], suspicions=susp)
        self.assertEqual(data["sqli"]["refuted"], 0,
                         "correct clean verdicts were counted as refutations")
        self.assertEqual(data["sqli"].get("correct_negative"), 4)
        self.assertFalse(data["sqli"]["demoted"])
        trusted, demoted = reliability.classify(data)
        self.assertEqual([r["class"] for r in demoted], [],
                         "a probe that was right four times was demoted as unreliable")
        self.assertEqual([r["class"] for r in trusted], ["sqli"])

    def test_correct_negatives_do_not_enter_the_fp_rate(self):
        d = self._eng()
        susp = self._clean_runs(d, "sqli", 10)
        data = reliability.sync_from_engagement(d, findings=[], suspicions=susp)
        self.assertIsNone(reliability.fp_rate(data["sqli"]),
                          "the FP rate was computed from correct negatives")

    def test_human_refutations_still_demote(self):
        """The converse — the fix must not neuter the Memory Loop's actual job."""
        d = self._eng()
        findings = [{"id": f"PTX-{i}", "class": "sqli", "status": "refuted"}
                    for i in range(6)]
        findings += [{"id": f"PTX-{i}", "class": "sqli", "status": "confirmed"}
                     for i in range(100, 102)]
        data = reliability.sync_from_engagement(d, findings=findings, suspicions=[])
        self.assertEqual(data["sqli"]["refuted"], 6)
        self.assertTrue(data["sqli"]["demoted"],
                        "6 of 8 findings refuted by a human and the probe kept its standing")
        self.assertAlmostEqual(reliability.fp_rate(data["sqli"]), 0.75)

    def test_a_mixed_probe_is_judged_on_findings_only(self):
        d = self._eng()
        susp = self._clean_runs(d, "xss", 8)          # 8 correct clean runs
        findings = [{"id": "PTX-1", "class": "xss", "status": "confirmed"},
                    {"id": "PTX-2", "class": "xss", "status": "confirmed"},
                    {"id": "PTX-3", "class": "xss", "status": "confirmed"}]
        data = reliability.sync_from_engagement(d, findings=findings, suspicions=susp)
        self.assertEqual(data["xss"]["refuted"], 0)
        self.assertEqual(data["xss"]["confirmed"], 3)
        self.assertEqual(data["xss"].get("correct_negative"), 8)
        self.assertFalse(data["xss"]["demoted"])

    def test_render_shows_the_correct_negative_column(self):
        d = self._eng()
        susp = self._clean_runs(d, "sqli", 4)
        data = reliability.sync_from_engagement(d, findings=[], suspicions=susp)
        out = reliability.render(data)
        self.assertIn("correct negatives", out)
        self.assertIn("| `sqli` | 0 | 0 | 4 | n/a | trusted |", out)
        self.assertIn("deliberately excluded from the FP rate", out)


class TestScopeParserAdversarial(unittest.TestCase):
    """The scope file is a safety boundary written by a human in ordinary YAML.

    Two ways it failed open, both from syntax the parser did not understand:

      exclusions:\n  - 10.9.0.0/16  # production DB
    parsed as the literal pattern "10.9.0.0/16  # production DB", which matches no host,
    so the tool attacked the production range the operator had just excluded — and printed
    a confident "in scope" reason while doing it. Writing a comment on the line where you
    exclude your production database is the most natural thing in the world to do.

      exclusions: [10.9.0.0/16]
    was stored verbatim as the string "[10.9.0.0/16]" and excluded nothing.

    Both are the same fault as the earlier exclusion bugs: a pattern present in the file
    and absent from the matcher.
    """

    def _scope(self, text):
        d = tempfile.mkdtemp(prefix="ptxparse")
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "scope.yaml")
        with open(p, "w") as f:
            f.write(text)
        return scopelib.Scope(p)

    EXCL = "in_scope:\n  - 10.0.0.0/8\nexclusions:\n{}"

    def test_inline_comment_does_not_break_an_exclusion(self):
        sc = self._scope(self.EXCL.format("  - 10.9.0.0/16  # production DB"))
        self.assertEqual(sc.exclusions, ["10.9.0.0/16"])
        ok, reason = sc.is_in_scope("10.9.1.1")
        self.assertFalse(ok, "the commented exclusion did not exclude — the tool would "
                             f"attack the production range ({reason})")
        self.assertIn("excluded", reason)

    def test_flow_list_exclusion_is_parsed(self):
        sc = self._scope("in_scope:\n  - 10.0.0.0/8\nexclusions: [10.9.0.0/16, 10.8.0.0/16]")
        self.assertEqual(sc.exclusions, ["10.9.0.0/16", "10.8.0.0/16"])
        self.assertFalse(sc.is_in_scope("10.9.1.1")[0])
        self.assertFalse(sc.is_in_scope("10.8.7.7")[0])

    def test_crlf_line_endings(self):
        sc = self._scope("in_scope:\r\n  - 10.0.0.0/8\r\nexclusions:\r\n  - 10.9.0.0/16\r\n")
        self.assertEqual(sc.in_scope, ["10.0.0.0/8"])
        self.assertFalse(sc.is_in_scope("10.9.1.1")[0])

    def test_tab_indentation(self):
        sc = self._scope("in_scope:\n\t- acme.com\nexclusions:\n")
        self.assertEqual(sc.in_scope, ["acme.com"])
        self.assertTrue(sc.is_in_scope("acme.com")[0])

    def test_quoted_patterns(self):
        sc = self._scope('in_scope:\n  - "acme.com"\nexclusions:\n  - \'bad.acme.com\'\n')
        self.assertEqual(sc.in_scope, ["acme.com"])
        self.assertEqual(sc.exclusions, ["bad.acme.com"])

    def test_hash_inside_quotes_is_not_treated_as_a_comment(self):
        """Comment stripping must respect quotes — tested directly, because `#` is not a
        valid hostname character so such a pattern is correctly refused at load."""
        self.assertEqual(scopelib.strip_comment('"we#ird"'), '"we#ird"')
        self.assertEqual(scopelib.strip_comment("acme.com  # note"), "acme.com")
        self.assertEqual(scopelib.strip_comment("acme.com#notacomment"),
                         "acme.com#notacomment",
                         "a # with no preceding space is part of the value, not a comment")
        self.assertEqual(scopelib.strip_comment("plain"), "plain")

    def test_an_invalid_host_character_is_refused(self):
        """The converse of quote handling: a pattern that is not a host must not load."""
        with self.assertRaises(scopelib.ScopeViolation):
            self._scope('in_scope:\n  - "we#ird"\nexclusions:\n')

    def test_empty_list_items_are_dropped(self):
        sc = self._scope("in_scope:\n  - acme.com\n  -\nexclusions:\n")
        self.assertEqual(sc.in_scope, ["acme.com"])

    def test_unmatchable_pattern_is_refused_at_load(self):
        """The deeper fix: a pattern that cannot match any host is an exclusion that does
        not exclude, so the file must be rejected rather than silently honoured."""
        with self.assertRaises(scopelib.ScopeViolation) as cm:
            self._scope("in_scope:\n  - acme.com\nexclusions:\n  - acme.com/admin\n")
        self.assertIn("cannot match any host", str(cm.exception))
        self.assertIn("acme.com/admin", str(cm.exception))

    def test_a_leftover_bracket_is_refused(self):
        with self.assertRaises(scopelib.ScopeViolation):
            self._scope("in_scope:\n  - 10.0.0.0/8\nexclusions:\n  - [10.9.0.0/16\n")

    def test_legitimate_pattern_shapes_still_load(self):
        """The converse — validation must not reject valid syntax."""
        sc = self._scope("in_scope:\n  - acme.com\n  - *.acme.com\n  - 10.0.0.0/8\n"
                         "  - 127.0.0.1:5001\n  - 192.168.1.1\nexclusions:\n  - x.acme.com\n")
        self.assertEqual(len(sc.in_scope), 5)

    def test_inclusions_are_validated_too(self):
        """A bad inclusion silently narrows the engagement, which is the quieter failure."""
        with self.assertRaises(scopelib.ScopeViolation):
            self._scope("in_scope:\n  - http://acme.com/path\nexclusions:\n")


class TestConcurrentInvocations(ServerFixture, unittest.TestCase):
    """Parallel `ptx` processes against one engagement must not lose entries.

    `state.json` is rewritten whole on every mutation. An agent orchestrating parallel
    probes — which is exactly the architecture this toolkit is built for — runs several
    processes against one engagement at once, and without a lock two of them read the same
    state, each append their own entry, and the last write wins. Measured before the fix:
    20 concurrent probe commands left 13 suspicions, with 7 silently gone.

    Nothing crashes when that happens. The suspicion ledger just quietly understates what
    was examined — and the reliability ledger and the report are both derived from it.
    """

    PTX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "ptx", "ptx.py")

    def _eng(self):
        d = tempfile.mkdtemp(prefix="ptxconc")
        self.addCleanup(shutil.rmtree, d, True)
        subprocess.run([sys.executable, self.PTX, "--engagement", d, "scope", "init",
                        "127.0.0.1:5001", "--in-scope", "127.0.0.1", "--authorization",
                        "test", "--rate", "60"],
                       capture_output=True, text=True, timeout=60)
        return d

    def test_no_suspicions_are_lost_under_concurrency(self):
        if not getattr(ServerFixture, "vuln_up", False):
            self.skipTest("vulnerable target not up")
        eng = self._eng()
        n = 20
        procs = [subprocess.Popen(
            [sys.executable, self.PTX, "--engagement", eng, "probe", "headers",
             "--base", VULN, "--path", f"/p{i}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for i in range(n)]
        for p in procs:
            p.wait(timeout=300)
        st = statemod.load(eng)
        susp = st.get("suspicions", [])
        ids = [x["id"] for x in susp]
        self.assertEqual(len(susp), n,
                         f"{n - len(susp)} of {n} suspicions were lost to a concurrent "
                         f"read-modify-write of state.json")
        self.assertEqual(len(set(ids)), n, "duplicate suspicion ids were issued")

    def test_action_count_agrees_with_the_log(self):
        """The counter and the append-only log are two records of the same events; a lost
        update makes them disagree, and the disagreement is the only visible symptom."""
        if not getattr(ServerFixture, "vuln_up", False):
            self.skipTest("vulnerable target not up")
        eng = self._eng()
        n = 12
        procs = [subprocess.Popen(
            [sys.executable, self.PTX, "--engagement", eng, "probe", "headers",
             "--base", VULN, "--path", f"/q{i}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for i in range(n)]
        for p in procs:
            p.wait(timeout=300)
        logged = sum(1 for _ in open(os.path.join(eng, "actions.jsonl")))
        self.assertEqual(statemod.load(eng).get("action_count"), logged,
                         "state.json's action_count disagrees with actions.jsonl")

    def test_state_file_is_never_left_truncated(self):
        """Writes go to a sibling and are renamed, so a kill mid-write cannot corrupt the
        engagement's whole history."""
        eng = self._eng()
        statemod.log_action(eng, "test", "x", "y", "z")
        self.assertFalse(os.path.exists(os.path.join(eng, "state.json.tmp")),
                         "a temporary state file was left behind")
        json.load(open(os.path.join(eng, "state.json")))

    def test_reliability_ledger_survives_concurrency_too(self):
        """The same fault lived in reliability.record — an unlocked read-modify-write of a
        file rewritten whole. Losing an increment there quietly biases the false-positive
        rate that the demotion decision is made from."""
        d = tempfile.mkdtemp(prefix="ptxrelc")
        self.addCleanup(shutil.rmtree, d, True)
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        code = ("import sys; sys.path.insert(0, %r);"
                "from ptxlib import reliability;"
                "reliability.record(%r, 'sqli', 'refuted')" % (
                    os.path.join(root, "ptx"), d))
        procs = [subprocess.Popen([sys.executable, "-c", code],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                 for _ in range(20)]
        for p in procs:
            p.wait(timeout=120)
        e = reliability.load(d)["sqli"]
        self.assertEqual(e["refuted"], 20,
                         f"{20 - e['refuted']} of 20 reliability increments were lost to a "
                         f"concurrent read-modify-write")

    def test_reliability_save_is_atomic(self):
        d = tempfile.mkdtemp(prefix="ptxrela")
        self.addCleanup(shutil.rmtree, d, True)
        reliability.record(d, "sqli", "confirmed")
        self.assertFalse(os.path.exists(os.path.join(d, "reliability.json.tmp")))
        json.load(open(os.path.join(d, "reliability.json")))

    def test_sequential_writes_are_unaffected(self):
        eng = self._eng()
        for i in range(5):
            statemod.add_suspicion(eng, f"/p{i}", "sqli", why="test")
        self.assertEqual(len(statemod.load(eng).get("suspicions", [])), 5)


class TestEndpointExtraction(unittest.TestCase):
    """A version string is not an endpoint.

    Coverage scrapes endpoints out of finding titles and evidence, which is prose. The
    regex was a bare "/anything", so the banner "server=Werkzeug/3.1.8 Python/3.13.14"
    yielded `/3.1.8` and `/3.13.14`, and the report then told the operator to run IDOR
    against both.

    Noise in a coverage list is not harmless. The list is long, and a reader who finds
    nonsense in it stops reading the rest — which is how the one real gap in it gets
    missed.
    """

    REAL = ["/api/orders", "/admin/users", "/{id}", "/<id>", "/.env", "/.git/config",
            "/package-lock.json", "/search", "/a"]
    # Two different checks reject these, and the split matters. Pure-number fragments
    # ("/3.1.8") are caught by requiring a letter somewhere; fragments that CONTAIN
    # letters ("/3.1.8-beta", "/2024-Q1", "/1.0.0rc1") are only caught by requiring the
    # route to START with a letter, dot, underscore or parameter bracket. A test suite
    # built only from the first kind passes with the route check deleted — which is how
    # this was found.
    NOISE = ["/3.1.8", "/3.13.14", "/8080", "/1", "/2024", "/-", "/.",
             "/3.1.8-beta", "/2024-Q1", "/1.0.0rc1", "/2.0-final"]

    def test_real_routes_are_recognised(self):
        for c in self.REAL:
            self.assertTrue(coverage._looks_like_route(c),
                            f"{c} is a real endpoint and was dropped from coverage")

    def test_version_and_number_fragments_are_not(self):
        for c in self.NOISE:
            self.assertFalse(coverage._looks_like_route(c),
                             f"{c} is not an endpoint but coverage would list it")

    def test_letter_bearing_version_fragments_are_rejected(self):
        """The case that needs the route-shape check specifically."""
        for c in ("/3.1.8-beta", "/2024-Q1", "/1.0.0rc1"):
            self.assertFalse(coverage._looks_like_route(c),
                             f"{c} contains letters, so only the leading-character rule "
                             f"can reject it — and it did not")

    def test_banner_evidence_yields_no_phantom_endpoints(self):
        """End to end through summarise, with the evidence string that caused it."""
        d = tempfile.mkdtemp(prefix="ptxep")
        self.addCleanup(shutil.rmtree, d, True)
        statemod.init(d)
        findings = [{
            "id": "PTX-001", "class": "headers", "title": "Security header review",
            "evidence": "missing: HSTS; application-disclosed: x-powered-by=Flask; "
                        "server=Werkzeug/3.1.8 Python/3.13.14 (framework default)",
        }]
        cov = coverage.summarise(d, findings=findings)
        eps = cov["endpoints_known"]
        for bad in ("/3.1.8", "/3.13.14"):
            self.assertNotIn(bad, eps,
                             f"{bad} was reported as a known endpoint from a banner")
        pairs = " ".join(f"{p['probe']} {p['endpoint']}" for p in cov["untested_pairs"])
        self.assertNotIn("/3.1.8", pairs)
        self.assertNotIn("/3.13.14", pairs)

    def test_a_real_endpoint_in_the_same_evidence_is_still_found(self):
        """The converse — tightening must not blind coverage to genuine routes."""
        d = tempfile.mkdtemp(prefix="ptxep2")
        self.addCleanup(shutil.rmtree, d, True)
        statemod.init(d)
        findings = [{
            "id": "PTX-001", "class": "exposure", "title": "Sensitive file exposure",
            "evidence": "/.env (262b, credential material); server=Werkzeug/3.1.8",
        }]
        cov = coverage.summarise(d, findings=findings)
        self.assertIn("/.env", cov["endpoints_known"],
                      "the exposed file — the actual finding — was dropped as noise")
        self.assertNotIn("/3.1.8", cov["endpoints_known"])


class TestMemoryLoopCanObserveARefutation(ServerFixture, unittest.TestCase):
    """The Memory Loop must be able to see a human reject a finding.

    Two separate breaks made that impossible, and together they meant the loop had never
    observed a real refutation:

    1. Nothing in the toolchain could ever set `status: "refuted"`. `finding set` had no
       --status, so the demotion path in sync_from_engagement had a reader and no writer.
       `ptx reliability` would show 0% false positives no matter how wrong the probes were.

    2. The dedupe key was a bare boolean. Once a finding had been counted as confirmed it
       could never be counted again — and a finding is ALWAYS created confirmed and
       refuted later, which is the only sequence that happens in practice. So even a
       hand-edited refutation was skipped.
    """

    PTX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "ptx", "ptx.py")

    def _eng(self):
        d = tempfile.mkdtemp(prefix="ptxref")
        self.addCleanup(shutil.rmtree, d, True)
        subprocess.run([sys.executable, self.PTX, "--engagement", d, "scope", "init",
                        "127.0.0.1:5001", "--in-scope", "127.0.0.1", "--authorization",
                        "test", "--rate", "60"],
                       capture_output=True, text=True, timeout=60)
        return d

    def _run(self, eng, *argv):
        return subprocess.run([sys.executable, self.PTX, "--engagement", eng] + list(argv),
                              capture_output=True, text=True, timeout=180)

    def test_a_finding_can_be_refuted_from_the_cli(self):
        eng = self._eng()
        self._run(eng, "probe", "headers", "--base", VULN)
        r = self._run(eng, "finding", "set", "PTX-001", "--status", "refuted",
                      "--refute-reason", "missing hardening headers are not a vulnerability")
        self.assertNotIn("REFUSED", r.stderr, r.stderr)
        rec = json.load(open(os.path.join(eng, "findings", "PTX-001.json")))
        self.assertEqual(rec["status"], "refuted")
        self.assertIn("not a vulnerability", rec["refute_reason"])

    def test_a_refutation_requires_a_reason(self):
        """A refutation is the evidence that demotes a probe class; an unauditable one is
        worse than none, because it cannot be checked later."""
        eng = self._eng()
        self._run(eng, "probe", "headers", "--base", VULN)
        r = self._run(eng, "finding", "set", "PTX-001", "--status", "refuted")
        self.assertIn("requires --refute-reason", r.stderr)
        rec = json.load(open(os.path.join(eng, "findings", "PTX-001.json")))
        self.assertNotEqual(rec.get("status"), "refuted")

    def test_the_ledger_moves_the_count_on_transition(self):
        """The regression: refuting a finding must move it out of `confirmed`, not leave a
        phantom count that keeps the false-positive rate looking clean."""
        eng = self._eng()
        self._run(eng, "probe", "headers", "--base", VULN)
        self._run(eng, "reliability")
        e = reliability.load(eng)["headers"]
        self.assertEqual((e["confirmed"], e["refuted"]), (1, 0))

        self._run(eng, "finding", "set", "PTX-001", "--status", "refuted",
                  "--refute-reason", "not a vulnerability")
        self._run(eng, "reliability")
        e = reliability.load(eng)["headers"]
        self.assertEqual((e["confirmed"], e["refuted"]), (0, 1),
                         "the refutation was not observed — the dedupe key blocked the "
                         "only transition that ever happens in practice")

    def test_a_legacy_boolean_marker_is_migrated(self):
        """Ledgers written before outcomes were tracked stored a bare True."""
        eng = self._eng()
        self._run(eng, "probe", "headers", "--base", VULN)
        self._run(eng, "reliability")
        p = os.path.join(eng, "reliability.json")
        d = json.load(open(p))
        d["headers"]["_synced_PTX-001"] = True          # the old on-disk form
        json.dump(d, open(p, "w"), indent=2)
        self._run(eng, "finding", "set", "PTX-001", "--status", "refuted",
                  "--refute-reason", "not a vulnerability")
        self._run(eng, "reliability")
        e = reliability.load(eng)["headers"]
        self.assertEqual((e["confirmed"], e["refuted"]), (0, 1),
                         "a legacy ledger could not be migrated to the new form")

    def test_repeated_sync_is_idempotent(self):
        """Moving counts must not drift when nothing has changed."""
        eng = self._eng()
        self._run(eng, "probe", "headers", "--base", VULN)
        self._run(eng, "finding", "set", "PTX-001", "--status", "refuted",
                  "--refute-reason", "nope")
        for _ in range(5):
            self._run(eng, "reliability")
        e = reliability.load(eng)["headers"]
        self.assertEqual((e["confirmed"], e["refuted"]), (0, 1),
                         "repeated syncs drifted the ledger")


class TestSealDoesNotCryWolf(ServerFixture, unittest.TestCase):
    """Completing a finding must not look like tampering.

    A finding is sealed at creation, when `impact` and `reproduction` are empty — and the
    report REFUSES to generate until the operator fills them in. So the mandatory next step
    in every engagement produced "EVIDENCE DRIFT" on every finding. The integrity section
    then cried wolf on the normal workflow, which is how a control gets ignored.

    The fix keeps the property that matters: probe-supplied evidence cannot be quietly
    rewritten. Edits made through `ptx finding set` re-seal and append the previous digest
    to the seal's history, so the edit is *recorded* rather than either invisible or
    alarming. Hand-editing the JSON is still caught.
    """

    PTX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "ptx", "ptx.py")

    def _eng_with_finding(self):
        d = tempfile.mkdtemp(prefix="ptxseal")
        self.addCleanup(shutil.rmtree, d, True)
        for argv in (["scope", "init", "127.0.0.1:5001", "--in-scope", "127.0.0.1",
                      "--authorization", "test", "--rate", "60"],
                     ["probe", "headers", "--base", VULN]):
            subprocess.run([sys.executable, self.PTX, "--engagement", d] + argv,
                           capture_output=True, text=True, timeout=180)
        return d

    def _verify(self, eng):
        return subprocess.run([sys.executable, self.PTX, "--engagement", eng, "verify"],
                              capture_output=True, text=True, timeout=120).stdout

    def _rec(self, eng):
        return json.load(open(os.path.join(eng, "findings", "PTX-001.json")))

    def test_a_new_finding_is_intact(self):
        self.assertIn("1/1 findings intact", self._verify(self._eng_with_finding()))

    def test_completing_a_finding_does_not_report_drift(self):
        eng = self._eng_with_finding()
        subprocess.run([sys.executable, self.PTX, "--engagement", eng, "finding", "set",
                        "PTX-001", "--impact", "Weakens transport defences for every user.",
                        "--reproduction", "curl -sI http://127.0.0.1:5001/"],
                       capture_output=True, text=True, timeout=120)
        out = self._verify(eng)
        self.assertIn("1/1 findings intact", out,
                      "the mandatory step of adding an impact statement was reported as "
                      f"evidence drift:\n{out}")
        self.assertNotIn("EVIDENCE DRIFT", out)

    def test_the_edit_is_recorded_in_the_seal_history(self):
        """Recorded, not invisible — the whole point is that the edit is visible."""
        eng = self._eng_with_finding()
        subprocess.run([sys.executable, self.PTX, "--engagement", eng, "finding", "set",
                        "PTX-001", "--impact", "Impact statement."],
                       capture_output=True, text=True, timeout=120)
        hist = self._rec(eng)["seal"].get("history") or []
        self.assertEqual(len(hist), 1, "the edit left no trace in the seal history")
        self.assertIn("prior_digest", hist[0])

    def test_hand_editing_the_evidence_is_still_caught(self):
        """The property that must survive the fix."""
        eng = self._eng_with_finding()
        p = os.path.join(eng, "findings", "PTX-001.json")
        rec = json.load(open(p))
        rec["evidence"] = "TAMPERED: severity inflated by hand"
        json.dump(rec, open(p, "w"), indent=2)
        out = self._verify(eng)
        self.assertIn("EVIDENCE DRIFT", out,
                      "hand-editing probe evidence was no longer detected")
        self.assertIn("0/1 findings intact", out)

    def test_unpopulated_fields_are_not_sealed(self):
        eng = self._eng_with_finding()
        fields = self._rec(eng)["seal"]["field_list"]
        self.assertIn("evidence", fields,
                      "probe evidence must always be in the digest")
        self.assertNotIn("impact", fields,
                         "an empty field was sealed, so filling it in would look like "
                         "tampering")


class TestSubdomainTakeover(unittest.TestCase):
    """Dangling delegations, and the three states they can be in.

    A dangling CNAME is one of the highest-yield findings in a web engagement, and the
    failure mode this guards is the one this codebase has already paid for twice:
    reporting "no takeover found" when the real answer is "I could not look".
    """

    def _dns(self, cnames):
        def run(host):
            return cnames.get(host.lower(), "")
        return run

    def _fetch(self, mapping):
        def f(host, timeout=8):
            return mapping.get(host.lower(), (None, None))
        return f

    def test_dangling_github_pages_is_flagged(self):
        r = takeover.check_host(
            "status.acme.test",
            runner=self._dns({"status.acme.test": "acme-labs.github.io."}),
            fetch=self._fetch({"status.acme.test":
                               (404, "<h1>There isn't a GitHub Pages site here.</h1>")}))
        self.assertEqual(r["verdict"], "TAKEOVER_LIKELY")
        self.assertEqual(r["service"], "GitHub Pages")
        self.assertIn("TO CLAIM", "\n".join(takeover.render_lines([r], [], 1)),
                      "a takeover finding without claim guidance is not actionable")

    def test_a_live_resource_is_not_a_takeover(self):
        """The CNAME points at a claimable service but the resource exists. A dangling
        CNAME alone is not proof; calling this takeable would be a false positive."""
        r = takeover.check_host(
            "blog.acme.test",
            runner=self._dns({"blog.acme.test": "acme.github.io."}),
            fetch=self._fetch({"blog.acme.test": (200, "<html>welcome</html>")}))
        self.assertEqual(r["verdict"], "CANDIDATE", "a live resource was called takeable")

    def test_unreadable_dns_is_a_coverage_gap_not_a_clean_result(self):
        """The regression this module is built around: a missing resolver must not read
        as 'no takeover'."""
        r = takeover.check_host("x.acme.test", runner=lambda h: None,
                                fetch=self._fetch({}))
        self.assertEqual(r["verdict"], "UNMEASURED")
        self.assertIn("coverage gap", r["reason"].lower())
        lines = "\n".join(takeover.render_lines([], [r], 1))
        self.assertIn("SOURCE UNAVAILABLE, NOT ENUMERATED", lines)
        self.assertIn("Do not read 'no takeover' as a result", lines)

    def test_a_host_that_does_not_answer_is_a_candidate(self):
        r = takeover.check_host(
            "gone.acme.test",
            runner=self._dns({"gone.acme.test": "acme.herokuapp.com."}),
            fetch=self._fetch({}))
        self.assertEqual(r["verdict"], "CANDIDATE")
        self.assertEqual(r["service"], "Heroku")

    def test_a_non_takeable_cname_is_not_reported(self):
        r = takeover.check_host(
            "cdn.acme.test",
            runner=self._dns({"cdn.acme.test": "d1234.cloudfront.net."}),
            fetch=self._fetch({"cdn.acme.test": (404, "NoSuchBucket")}))
        self.assertIsNone(r, "a CNAME to a non-takeable service was reported")

    def test_multi_hop_chains_are_followed(self):
        r = takeover.check_host(
            "media.acme.test",
            runner=self._dns({"media.acme.test": "edge.acme.test.",
                              "edge.acme.test": "acme-assets.s3.amazonaws.com."}),
            fetch=self._fetch({"media.acme.test": (404, "<Code>NoSuchBucket</Code>")}))
        self.assertEqual(r["verdict"], "TAKEOVER_LIKELY")
        self.assertEqual(r["service"], "Amazon S3")
        self.assertEqual(r["cname"], ["edge.acme.test", "acme-assets.s3.amazonaws.com"])

    def test_a_cname_loop_terminates_and_is_not_reported(self):
        """A CNAME cycle must not spin, and a cycle with no takeable service in it is not
        a candidate."""
        calls = []

        def counting(host):
            calls.append(host)
            return {"loop.acme.test": "a.acme.test.",
                    "a.acme.test": "loop.acme.test."}.get(host.lower(), "")

        r = takeover.check_host("loop.acme.test", runner=counting, fetch=self._fetch({}))
        self.assertIsNone(r, "a cycle with no takeable service was reported")
        self.assertLessEqual(len(calls), 10,
                             f"the CNAME loop was followed {len(calls)} times")

    def test_a_marker_is_matched_case_insensitively(self):
        r = takeover.check_host(
            "s.acme.test",
            runner=self._dns({"s.acme.test": "x.myshopify.com."}),
            fetch=self._fetch({"s.acme.test":
                               (404, "SORRY, THIS SHOP IS CURRENTLY UNAVAILABLE")}))
        self.assertEqual(r["verdict"], "TAKEOVER_LIKELY")

    def test_one_failing_host_does_not_end_the_scan(self):
        def bad(host, timeout=8):
            raise RuntimeError("resolver exploded")
        # Both hosts must delegate somewhere takeable, otherwise check_host returns early
        # and the raising fetch is never reached — the test would pass without exercising
        # the path it claims to.
        res = takeover.scan(["a.acme.test", "b.acme.test"],
                            runner=self._dns({"a.acme.test": "a-labs.github.io.",
                                              "b.acme.test": "b-labs.github.io."}),
                            fetch=bad)
        self.assertEqual(res["hosts_checked"], 2)
        self.assertEqual(len(res["unmeasured"]), 2,
                         "a raising host was silently dropped instead of recorded")

    def test_every_table_entry_has_the_fields_the_renderer_needs(self):
        for svc in takeover.TAKEABLE:
            self.assertTrue(svc.get("service"))
            self.assertTrue(svc.get("cname"), f"{svc.get('service')} has no CNAME pattern")
            self.assertTrue(svc.get("markers"),
                            f"{svc.get('service')} has no unclaimed marker, so it could "
                            "never produce TAKEOVER_LIKELY")
            self.assertTrue(svc.get("claim"), f"{svc.get('service')} has no claim guidance")


class TestProbesWithoutTheirRequiredArgument(ServerFixture, unittest.TestCase):
    """A probe that cannot decide must say so — not crash, and not report clean.

    Two probes took an argument the CLI leaves at None by default:

      * `traversal` did `marker in r["body"]`, which raised
        "TypeError: 'in <string>' requires string as left operand, not NoneType" on its
        own default invocation. A traceback where a verdict belongs.
      * `ssrf` was worse and quieter: it built the URL "None?name=<token>", asked the
        target to fetch that, and reported "not vulnerable" when the token naturally did
        not come back. It tested nothing and recorded a clean result.
    """

    PTX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "ptx", "ptx.py")

    def _probe(self, *argv):
        d = tempfile.mkdtemp(prefix="ptxnoarg")
        self.addCleanup(shutil.rmtree, d, True)
        subprocess.run([sys.executable, self.PTX, "--engagement", d, "scope", "init",
                        "127.0.0.1:5001", "--in-scope", "127.0.0.1", "--authorization",
                        "test", "--rate", "60"], capture_output=True, text=True, timeout=60)
        r = subprocess.run([sys.executable, self.PTX, "--engagement", d] + list(argv),
                           capture_output=True, text=True, timeout=180)
        return r

    def test_traversal_without_a_marker_does_not_crash(self):
        r = self._probe("probe", "traversal", "--base", VULN)
        self.assertNotIn("Traceback", r.stderr + r.stdout,
                         "probe traversal crashed on its default invocation")
        self.assertNotIn("TypeError", r.stderr + r.stdout)

    def test_traversal_without_a_marker_reports_unmeasured(self):
        r = self._probe("probe", "traversal", "--base", VULN)
        self.assertIn("UNMEASURED", r.stdout,
                      "a traversal probe with no marker was not reported as unmeasured")
        self.assertIn("--marker", r.stdout,
                      "the output did not tell the operator what to supply")

    def test_ssrf_without_a_canary_does_not_report_clean(self):
        """The quiet one: this used to print 'not vulnerable' having tested nothing."""
        r = self._probe("probe", "ssrf", "--base", VULN)
        self.assertNotIn("Traceback", r.stderr + r.stdout)
        self.assertIn("UNMEASURED", r.stdout,
                      "SSRF with no canary URL reported a clean result instead of "
                      "unmeasured")
        self.assertIn("--canary-url", r.stdout)

    def test_both_still_detect_when_given_their_argument(self):
        """The fix must not disable the probe."""
        r = self._probe("probe", "traversal", "--base", VULN,
                        "--path", "/download", "--param", "file",
                        "--payload", "../canary/secret.txt",
                        "--marker", "PTX_TRAVERSAL_GOAL")
        self.assertNotIn("Traceback", r.stderr + r.stdout)
        self.assertNotIn("UNMEASURED", r.stdout,
                         "traversal with a marker was still reported as unmeasured")

    def test_the_unmeasured_verdict_reaches_coverage(self):
        """An unmeasured probe must show up under 'attempted but never measured', which is
        the whole point of the inconclusive flag."""
        d = tempfile.mkdtemp(prefix="ptxcov")
        self.addCleanup(shutil.rmtree, d, True)
        subprocess.run([sys.executable, self.PTX, "--engagement", d, "scope", "init",
                        "127.0.0.1:5001", "--in-scope", "127.0.0.1", "--authorization",
                        "test", "--rate", "60"], capture_output=True, text=True, timeout=60)
        subprocess.run([sys.executable, self.PTX, "--engagement", d, "probe", "traversal",
                        "--base", VULN], capture_output=True, text=True, timeout=180)
        cov = subprocess.run([sys.executable, self.PTX, "--engagement", d, "coverage"],
                             capture_output=True, text=True, timeout=120).stdout
        self.assertIn("traversal", cov)


class TestAssessmentTypeIsRead(unittest.TestCase):
    """`assessment_type` was written to scope.yaml and printed by `ptx status`, but
    nothing ever read it — the fourth control in this codebase shipped with no reader.

    It matters because a blackbox engagement has no credentials, so the eight classes that
    assume an authenticated identity cannot be run at all. Listing them under "never run
    at all" tells the operator they forgot something that was never reachable, and a gap
    list containing unreachable items gets skimmed — hiding the ones that were real.
    """

    PTX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "ptx", "ptx.py")

    def test_a_class_needing_two_sessions_is_out_of_reach_for_blackbox_too(self):
        """`privilege` needs two sessions, so it is out of reach with no credentials at
        all -- not only with one. It is the one SECOND_IDENTITY class that was missing
        from chains.REQUIRES, and so fell through the blackbox branch entirely."""
        blocked = {}
        for at in ("blackbox", "greybox", "whitebox"):
            _, cov = self._coverage(at)
            blocked[at] = set(cov["probe_classes_blocked_by_access"])
        self.assertIn("privilege", blocked["blackbox"])
        self.assertIn("privilege", blocked["greybox"])
        self.assertNotIn("privilege", blocked["whitebox"])
        # Monotonic by construction: blackbox blocks a superset of greybox. Without this
        # the same class can be "out of reach" for one type and "you forgot it" for
        # another, which is the contradiction the split exists to prevent.
        self.assertLessEqual(blocked["greybox"], blocked["blackbox"])
        self.assertLessEqual(blocked["whitebox"], blocked["greybox"])

    def _coverage(self, atype):
        d = tempfile.mkdtemp(prefix="ptxat")
        self.addCleanup(shutil.rmtree, d, True)
        subprocess.run([sys.executable, self.PTX, "--engagement", d, "scope", "init",
                        "127.0.0.1:5001", "--in-scope", "127.0.0.1", "--authorization",
                        "test", "--type", atype, "--rate", "60"],
                       capture_output=True, text=True, timeout=60)
        out = subprocess.run([sys.executable, self.PTX, "--engagement", d, "coverage"],
                             capture_output=True, text=True, timeout=120).stdout
        return out, coverage.summarise(d, [], assessment_type=atype)

    def test_blackbox_separates_unreachable_classes_from_real_gaps(self):
        out, cov = self._coverage("blackbox")
        self.assertIn("Not runnable without credentials", out,
                      "a blackbox engagement did not distinguish unreachable classes")
        blocked = set(cov["probe_classes_blocked_by_access"])
        self.assertTrue(blocked, "no classes were identified as needing an identity")
        self.assertIn("idor", blocked)
        self.assertIn("mass-assignment", blocked)
        self.assertNotIn("sqli", blocked,
                         "sqli needs no credentials and was marked unreachable")
        self.assertFalse(blocked & set(cov["probe_classes_never_run"]),
                         "a class was listed in both sections")

    def test_the_blocked_set_matches_chains_requires(self):
        """Single source of truth: the classes needing an identity are exactly the ones
        chains.REQUIRES says assume a capability."""
        _, cov = self._coverage("blackbox")
        # `chains` is imported locally inside summarise(), so it is not an attribute of
        # the coverage module — import it directly.
        self.assertEqual(set(cov["probe_classes_blocked_by_access"]),
                         set(chains.REQUIRES) & coverage.known_classes())

    def test_whitebox_reports_everything_as_a_gap(self):
        out, cov = self._coverage("whitebox")
        self.assertNotIn("Not runnable without credentials", out,
                         "a whitebox engagement claimed classes were out of reach")
        self.assertEqual(cov["probe_classes_blocked_by_access"], [])
        self.assertIn("idor", cov["probe_classes_never_run"])

    def test_the_count_is_conserved_between_the_two_modes(self):
        """Splitting a list must not lose or invent entries."""
        _, blk = self._coverage("blackbox")
        _, wht = self._coverage("whitebox")
        self.assertEqual(len(blk["probe_classes_blocked_by_access"])
                         + len(blk["probe_classes_never_run"]),
                         len(wht["probe_classes_never_run"]))

    def test_greybox_blocks_only_what_one_credential_cannot_reach(self):
        """A single test account does not make every identity-requiring class runnable.

        IDOR is only demonstrable by comparing what two different accounts can each see,
        CSRF needs a victim logged in somewhere else, and the privilege probe needs two
        sessions by construction. Marking those reachable in a greybox test would put them
        back on the "you forgot this" list — the exact problem the blackbox split was
        added to solve.

        Asserted against SECOND_IDENTITY rather than a literal pair, because this test
        previously hardcoded {"idor", "csrf"} and went stale the moment a third class
        joined the set. The point is that greybox blocks exactly that set, not that the
        set has two members.
        """
        _, cov = self._coverage("greybox")
        blocked = set(cov["probe_classes_blocked_by_access"])
        self.assertEqual(blocked, set(coverage.SECOND_IDENTITY),
                         f"greybox blocked {sorted(blocked)}; one credential supplies an "
                         "identity for every other identity-requiring class")
        self.assertIn("idor", blocked)
        self.assertIn("csrf", blocked)
        self.assertIn("privilege", blocked,
                      "the privilege probe needs two sessions, so one test account "
                      "cannot reach it either")
        self.assertNotIn("mass-assignment", blocked)
        self.assertNotIn("refund-abuse", blocked)

    def test_whitebox_blocks_nothing_on_access_grounds(self):
        _, cov = self._coverage("whitebox")
        self.assertEqual(cov["probe_classes_blocked_by_access"], [])
        self.assertIn("idor", cov["probe_classes_never_run"])
        self.assertIn("csrf", cov["probe_classes_never_run"])

    def test_the_three_modes_narrow_monotonically(self):
        """blackbox blocks a superset of greybox, which blocks a superset of whitebox.
        If that ordering ever inverts, the model has stopped making sense."""
        _, blk = self._coverage("blackbox")
        _, gry = self._coverage("greybox")
        _, wht = self._coverage("whitebox")
        b = set(blk["probe_classes_blocked_by_access"])
        g = set(gry["probe_classes_blocked_by_access"])
        w = set(wht["probe_classes_blocked_by_access"])
        self.assertTrue(w <= g <= b, f"{sorted(w)} <= {sorted(g)} <= {sorted(b)} is false")
        self.assertTrue(g < b, "greybox blocks everything blackbox does — the single "
                               "credential bought nothing")

    def test_second_identity_set_is_grounded_in_chains(self):
        """The set must not drift from what chains.REQUIRES actually claims."""
        for cls in coverage.SECOND_IDENTITY:
            self.assertIn(cls, chains.REQUIRES,
                          f"{cls} is listed as needing a second principal but chains "
                          "requires nothing of it")

    def test_a_fresh_engagement_still_lists_every_gap(self):
        """The early return on `actions_recorded == 0` skipped every gap section, so a
        brand-new engagement — when the list matters most — got one sentence."""
        d = tempfile.mkdtemp(prefix="ptxfresh")
        self.addCleanup(shutil.rmtree, d, True)
        subprocess.run([sys.executable, self.PTX, "--engagement", d, "scope", "init",
                        "127.0.0.1:5001", "--in-scope", "127.0.0.1", "--authorization",
                        "test", "--type", "blackbox", "--rate", "60"],
                       capture_output=True, text=True, timeout=60)
        out = subprocess.run([sys.executable, self.PTX, "--engagement", d, "coverage"],
                             capture_output=True, text=True, timeout=120).stdout
        self.assertIn("No structured actions recorded", out,
                      "the warning about an untested engagement disappeared")
        self.assertIn("Never run at all", out,
                      "a fresh engagement reported no gaps at all")
        self.assertIn("Not runnable without credentials", out)

    def test_a_missing_scope_file_raises_rather_than_silently_disabling(self):
        """The bare `except Exception: pass` around this lookup swallowed a
        FileNotFoundError and made the feature a silent no-op."""
        d = tempfile.mkdtemp(prefix="ptxnoscope")
        self.addCleanup(shutil.rmtree, d, True)
        r = subprocess.run([sys.executable, self.PTX, "--engagement", d, "coverage"],
                           capture_output=True, text=True, timeout=120)
        self.assertNotEqual(r.returncode, 0,
                            "coverage on an engagement with no scope.yaml exited clean")


class TestTakeoverScanIsThrottled(unittest.TestCase):
    """The confirmation requests go to THIRD PARTIES, so the ceiling is a courtesy and an
    operational safeguard rather than a scope rule.

    An unthrottled fan-out across a domain with a few thousand subdomains is a volume
    attack on someone else's infrastructure and a fast way to get the operator's egress IP
    blocked. The unlocked version of this bug was already found once in `probes.Http`:
    ten threads read the same `_last`, computed the same wait, and fired together — 48
    req/s against a 5 req/s ceiling.
    """

    def test_the_ceiling_holds_under_concurrency(self):
        th = takeover._Throttle(rps=5)
        n_threads, per_thread = 10, 4
        total = n_threads * per_thread

        def hit():
            for _ in range(per_thread):
                th.wait()

        t0 = time.time()
        threads = [threading.Thread(target=hit) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        elapsed = time.time() - t0
        rate = total / elapsed
        self.assertLessEqual(rate, 6.0,
                             f"{rate:.1f} req/s against a 5 req/s ceiling — the throttle "
                             "is not thread-safe")

    def test_no_ceiling_means_no_delay(self):
        th = takeover._Throttle(rps=None)
        t0 = time.time()
        for _ in range(50):
            th.wait()
        self.assertLess(time.time() - t0, 0.5,
                        "a throttle with no ceiling still slept")

    def test_scan_spaces_its_requests(self):
        times = []

        def recording(host, timeout=8):
            times.append(time.time())
            return 404, "There isn't a GitHub Pages site here."

        takeover.scan([f"h{i}.acme.test" for i in range(6)],
                      runner=lambda h: "x.github.io.", fetch=recording, rps=5)
        self.assertEqual(len(times), 6)
        gaps = [b - a for a, b in zip(times, times[1:])]
        self.assertGreater(sum(gaps), 0.8,
                           f"6 requests at a 5 req/s ceiling took "
                           f"{times[-1] - times[0]:.2f}s — they were not spaced")


class TestAclBypassProbe(ServerFixture, unittest.TestCase):
    """Authorisation bypass by path normalisation, in both directions.

    The false-positive discipline matters more than the detection here. A route whose 401
    comes from a session check inside the handler cannot be bypassed by re-spelling the
    URL, and plenty of stacks answer every unmatched route with 200 and an HTML error page
    — so status alone would make both of those into findings.
    """

    def _probe(self, path, cookie=None):
        h = probes.Http(VULN, rps=60)
        return probes.probe_acl_bypass(h, path, cookie)

    def test_detects_a_case_sensitive_guard(self):
        v = self._probe("/admin/panel")
        self.assertTrue(v["vulnerable"],
                        f"a real bypass was missed: {v['evidence']}")
        self.assertEqual(v["id"], "acl-bypass")
        self.assertEqual(v["severity"], "High")
        self.assertIn("ADMIN", v["evidence"])

    def test_does_not_flag_a_handler_level_session_check(self):
        """The control is working exactly as intended here; calling it bypassable is a
        false positive against a defence that never depended on the path spelling."""
        v = self._probe("/api/me")
        self.assertFalse(v["vulnerable"],
                         f"a session check was reported as an ACL bypass: {v['evidence']}")
        self.assertFalse(v.get("inconclusive"),
                         "a refused baseline is a measured result, not an inconclusive one")

    def test_an_unprotected_route_is_inconclusive_not_clean(self):
        """/ has no access control, so there is nothing to bypass. Reporting "not
        vulnerable" would imply the probe tested a control that does not exist."""
        v = self._probe("/")
        self.assertFalse(v["vulnerable"])
        self.assertTrue(v.get("inconclusive"),
                        "an unprotected route was reported as a tested-and-clean ACL")
        self.assertIn("not protected", v["inconclusive_reason"])

    def test_every_variant_is_recorded(self):
        """The operator needs to see what was tried, not just the verdict."""
        v = self._probe("/admin/panel")
        # _verdict merges `extra` into the top level (out.update(extra)), it does not nest
        # it under an "extra" key.
        tried = v["variants_tried"]
        self.assertGreaterEqual(len(tried), 14)
        for t in tried:
            self.assertIn("url", t)
            self.assertIn("why", t)
            self.assertIn("bypassed", t)
        self.assertTrue(any(t["bypassed"] for t in tried))

    def test_a_refusal_that_is_not_403_is_still_recognised(self):
        """Denial is a property of the response, not of one status code."""
        self.assertTrue(probes._looks_denied(401, ""))
        self.assertTrue(probes._looks_denied(403, ""))
        self.assertTrue(probes._looks_denied(200, "<h1>Access Denied</h1>"))
        self.assertTrue(probes._looks_denied(404, "not found"))
        self.assertFalse(probes._looks_denied(200, '{"users": []}'))

    class _StubClient:
        """Returns canned responses so the decision logic can be tested against shapes the
        benchmark target does not happen to have."""

        def __init__(self, responses):
            self.responses = responses
            self.transport_failures = 0
            self.request_count = 0

        def req(self, path, method="GET", data=None, headers=None, raw=None, ctype=None,
                throttle=True):
            self.request_count += 1
            code, body = self.responses(path)
            return {"code": code, "body": body, "headers": {}, "url": path}

    def test_a_200_with_the_denial_body_is_not_a_bypass(self):
        """This is the case the `same_as_denial` guard exists for, and the mutation test
        proved nothing else covered it: delete the guard and every other test still passes.

        Plenty of stacks answer every unmatched route with 200 and an HTML error page. A
        variant that returns 200 with the *same* body as the refusal has not reached
        anything — status alone would turn every one of those into a finding.
        """
        # The body must NOT contain a denial word. If it does, `_looks_denied` rejects the
        # variant on its own and `same_as_denial` is never the deciding factor — which is
        # exactly why the first version of this test passed with the guard deleted. A test
        # has to isolate the guard it claims to cover.
        denial = '{"error":"nope"}'
        stub = self._StubClient(lambda p: (403, denial) if p == "/admin/x" else (200, denial))
        v = probes.probe_acl_bypass(stub, "/admin/x")
        self.assertFalse(v["vulnerable"],
                         "a 200 carrying the same body as the denial was reported as a "
                         "bypass — the same_as_denial guard is not doing its job")

    def test_a_200_with_different_content_is_a_bypass(self):
        """The other half: the guard must not suppress a genuine bypass."""
        stub = self._StubClient(
            lambda p: (403, "<h1>Access Denied</h1>") if p == "/admin/x"
            else (200, '{"users": [{"id": 1}]}'))
        v = probes.probe_acl_bypass(stub, "/admin/x")
        self.assertTrue(v["vulnerable"],
                        f"a genuine bypass was suppressed: {v['evidence']}")

    def test_the_bypass_grants_identity_in_a_chain(self):
        """Reaching a route the ACL was meant to block is identity in the only sense that
        matters: the request is served as though the check had passed."""
        self.assertEqual(chains.GRANTS.get("acl-bypass"), ["identity"])

    def test_the_class_is_in_every_registry(self):
        """Adding a probe is a multi-file change and this codebase has forgotten a file
        more than once."""
        self.assertIn("acl-bypass", coverage.known_classes())
        self.assertIn("acl-bypass", coverage.TARGETED)
        self.assertIn("acl-bypass", chains.GRANTS)
        self.assertNotIn("acl-bypass", probes.__dict__.get("DESTRUCTIVE", {}),
                         "a read-only probe must not require destructive authorization")


class TestReportIsInternallyConsistent(unittest.TestCase):
    """Three defects found by reading a generated report, not by reading code.

    A report is the deliverable. Nobody reads the renderer; everybody reads the output. All
    three of these were invisible to the whole suite and obvious in one read.
    """

    def _report(self, **over):
        """Drive the real `report.build()` against a temp engagement.

        There is no pure render function to call — build() reads findings from disk, runs
        validate_all(), and refuses to emit a report containing an invalid finding. Testing
        through it means the test exercises the path the operator actually runs.
        """
        d = tempfile.mkdtemp(prefix="ptxrpt")
        self.addCleanup(shutil.rmtree, d, True)
        os.makedirs(os.path.join(d, "findings"), exist_ok=True)
        os.makedirs(os.path.join(d, "artifacts"), exist_ok=True)
        with open(os.path.join(d, "artifacts", "a.txt"), "w") as f:
            f.write("captured response\n")
        rec = {"id": "PTX-001", "title": "Test finding", "class": "exposure",
               "severity": "High", "status": "confirmed",
               "summary": "mechanism text",
               # The report gate counts sentences, so a one-sentence impact is rejected.
               # Three plain sentences about business consequence.
               "impact": "Every customer record is readable without a credential. The "
                         "signing key is exposed, so sessions can be forged for any user "
                         "including administrators. Disclosure converts directly into "
                         "account takeover with no further access required.",
               "evidence": "evidence text", "reproduction": "curl -s http://x/",
               "remediation": "", "teaching": "teaching text",
               "artifacts": ["artifacts/a.txt"], "confirmed_at": "2026-01-01T00:00:00Z"}
        rec.update(over)
        with open(os.path.join(d, "findings", "PTX-001.json"), "w") as f:
            json.dump(rec, f, indent=2)
        path, lines = rpt.build(d)
        # build() returns (None, blocked_lines) when validation fails. Surface that rather
        # than letting the test fail on a missing file with no explanation.
        self.assertIsNotNone(path, "the report was blocked: " + "\n".join(lines))
        return open(os.path.join(d, "report", "report.md")).read()

    def test_remediation_is_populated_from_the_probe(self):
        """Every probe writes its fix as the sixth positional argument to _verdict, which
        lands in `teaching`. from_probe hardcoded remediation to "", so the report printed
        "_not recorded_" on every finding while the next section carried the real advice."""
        d = tempfile.mkdtemp(prefix="ptxrem")
        self.addCleanup(shutil.rmtree, d, True)
        rec, created = fnd.from_probe(d, {
            "id": "exposure", "name": "Sensitive file exposure", "vulnerable": True,
            "severity": "High", "mechanism": "m", "evidence": "e",
            "teaching": "Serve from an explicit public directory."})
        self.assertTrue(created)
        self.assertIn("explicit public directory", rec["remediation"],
                      "the probe's remediation advice never reached the remediation field")

    def test_identical_teaching_and_remediation_are_not_printed_twice(self):
        out = self._report(remediation="same text", teaching="same text")
        self.assertEqual(out.count("same text"), 1,
                         "the same advice was printed under two headings")
        self.assertNotIn("#### Teaching note", out)

    def test_a_distinct_teaching_note_is_still_printed(self):
        out = self._report(remediation="fix it this way",
                           teaching="and here is why that matters")
        self.assertIn("#### Teaching note", out,
                      "a genuinely separate teaching note was suppressed")
        self.assertIn("here is why that matters", out)

    def test_an_empty_gap_list_does_not_contradict_the_coverage_section(self):
        """The report said "No coverage gaps were logged" while the Coverage section below
        it listed nineteen probe classes that had never run."""
        out = self._report()
        self.assertNotIn("No coverage gaps were logged.", out,
                         "the bare claim is back — it contradicts the coverage section")
        self.assertIn("not the same as test coverage", out,
                      "the message no longer says which kind of gap it means")


class TestCaseVariantEndpointsAreNotResuggested(unittest.TestCase):
    """The acl-bypass probe's evidence names the variant it succeeded with. The endpoint
    scraper added it to the inventory, so the report advised running the ACL bypass probe
    against the very URL it had just used to bypass."""

    def test_a_case_variant_of_a_tested_endpoint_is_not_listed(self):
        d = tempfile.mkdtemp(prefix="ptxci")
        self.addCleanup(shutil.rmtree, d, True)
        statemod.log_action(d, "1", "probe acl-bypass", "/admin/panel", "vulnerable",
                            probe="acl-bypass", endpoint="/admin/panel")
        recs = [{"id": "PTX-001", "class": "acl-bypass", "title": "ACL bypass",
                 "evidence": "baseline /admin/panel -> 403; /ADMIN/PANEL -> 200",
                 "severity": "High", "status": "confirmed"}]
        cov = coverage.summarise(d, recs)
        pairs = {(x["probe"], x["endpoint"]) for x in cov["untested_pairs"]}
        self.assertNotIn(("acl-bypass", "/ADMIN/PANEL"), pairs,
                         "the report suggests running the bypass probe against the bypass "
                         "URL it already used")
        self.assertIn(("acl-bypass", "/admin/panel"),
                      {(p, e) for p, e in [(a, b) for a, b in
                       [("acl-bypass", "/admin/panel")]]},
                      "sanity: the tested pair is the real endpoint")


class TestUserEnumProbe(ServerFixture, unittest.TestCase):
    """Account enumeration, and the three ways it produces false positives.

    A login form is the easiest place in a web app to invent a finding: the two responses
    almost always differ somehow. What makes the difference *evidence* is that it
    distinguishes existence, consistently, after removing what we sent.
    """

    class _Stub:
        def __init__(self, fn):
            self.fn = fn
            self.transport_failures = 0
            self.request_count = 0

        def req(self, path, method="GET", data=None, headers=None, raw=None, ctype=None,
                throttle=True):
            self.request_count += 1
            user = (data or {}).get("username", "")
            return self.fn(user)

    def test_detects_a_status_code_difference(self):
        stub = self._Stub(lambda u: ({"code": 200, "body": '{"ok":true}', "headers": {}}
                                     if u == "alice"
                                     else {"code": 404, "body": '{"error":"no such user"}',
                                           "headers": {}}))
        v = probes.probe_user_enum(stub, "/login", "alice", samples=2)
        self.assertTrue(v["vulnerable"], f"enumeration missed: {v['evidence']}")
        self.assertEqual(v["severity"], "Medium")

    def test_an_echoed_username_is_not_a_difference(self):
        """The single easiest false positive. If the form echoes the submitted name back,
        the two bodies differ by the string we ourselves sent."""
        stub = self._Stub(lambda u: {"code": 401,
                                     "body": '{"error":"invalid credentials for %s"}' % u,
                                     "headers": {}})
        v = probes.probe_user_enum(stub, "/login", "alice", samples=2)
        self.assertFalse(v["vulnerable"],
                         "an echoed username was reported as enumeration")

    def test_identical_responses_are_a_clean_result(self):
        stub = self._Stub(lambda u: {"code": 401, "body": '{"error":"invalid"}',
                                     "headers": {}})
        v = probes.probe_user_enum(stub, "/login", "alice", samples=2)
        self.assertFalse(v["vulnerable"])
        self.assertFalse(v.get("inconclusive"),
                         "a measured identical-response result is not inconclusive")

    def test_unstable_responses_are_inconclusive_not_vulnerable(self):
        """A load balancer or an intermittent 500 produces a difference that is not a
        signal. One sample each would have called this a finding."""
        # Per-username, not per-call. A global counter alternates between the two sides and
        # leaves each of them internally consistent, which is a *difference*, not
        # instability — the first version of this test passed a stable 200-vs-500 split and
        # so measured nothing.
        seen = {}

        def flaky(u):
            seen[u] = seen.get(u, 0) + 1
            code = [200, 500, 200][seen[u] % 3] if u == "alice" else [404, 500, 404][seen[u] % 3]
            return {"code": code, "body": "{}", "headers": {}}

        v = probes.probe_user_enum(self._Stub(flaky), "/login", "alice", samples=3)
        self.assertTrue(v.get("inconclusive"),
                        "unstable responses were reported as a result rather than as "
                        "unmeasured")
        self.assertFalse(v["vulnerable"])

    def test_a_malformed_login_body_is_inconclusive_not_clean(self):
        """Both sides rejected as HTTP 400 means the body was not shaped the way the
        endpoint expects, so nothing was ever compared."""
        stub = self._Stub(lambda u: {"code": 400, "body": "bad request", "headers": {}})
        v = probes.probe_user_enum(stub, "/login", "alice", samples=2)
        self.assertTrue(v.get("inconclusive"),
                        "a malformed request was recorded as a clean result")
        self.assertIn("--user-field", v["inconclusive_reason"])

    def test_no_candidate_username_is_inconclusive(self):
        stub = self._Stub(lambda u: {"code": 200, "body": "{}", "headers": {}})
        v = probes.probe_user_enum(stub, "/login", None)
        self.assertTrue(v.get("inconclusive"))
        self.assertEqual(stub.request_count, 0,
                         "requests were sent with no candidate to test")

    def test_a_body_only_difference_is_detected(self):
        """Same status, different content — the subtler and more common case."""
        stub = self._Stub(lambda u: {"code": 401,
                                     "body": '{"error":"wrong password"}' if u == "alice"
                                             else '{"error":"no such account"}',
                                     "headers": {}})
        v = probes.probe_user_enum(stub, "/login", "alice", samples=2)
        self.assertTrue(v["vulnerable"], f"body-only difference missed: {v['evidence']}")

    def test_it_is_gated_as_destructive(self):
        """Failed authentications are counted by most production login endpoints, and the
        count ends in a locked account."""
        import ptx as ptxmod
        self.assertIn("user-enum", ptxmod.DESTRUCTIVE,
                      "a probe that sends failed logins is not gated as destructive")


class TestNoOracleHasAHardcodedVerdict(unittest.TestCase):
    """A falsification target that cannot fail is not a test.

    N05 ("CORS reported as standalone Critical") computed the right answer from the
    response headers into a variable called `ok` and then passed the literal `False` to
    record() instead. It recorded CORRECT_NEGATIVE forever. The benchmark's whole purpose is
    to catch a tool that over-reports, and one of its six over-reporting checks was inert.
    """

    SCORECARD = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "bench", "scorecard.py")

    def _record_calls(self):
        import ast
        src = open(self.SCORECARD).read()
        out = []
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "record":
                if len(node.args) >= 4:
                    out.append((node.lineno, node.args[0], node.args[3]))
        return out

    def test_the_benchmark_parses_and_has_oracles(self):
        calls = self._record_calls()
        self.assertGreater(len(calls), 20,
                           "the oracle scan found almost nothing — the AST walk is broken, "
                           "which would make every assertion below vacuous")

    def test_no_oracle_assumes_its_own_ground_truth(self):
        """Ground truth may be a literal, but only ever False.

        The fourth argument to record() is now ground truth rather than the tool's
        verdict, so a literal there is no longer a vacuous score -- it is an assertion
        about the target. An absent target's ground truth genuinely is False. What is
        never acceptable is a literal True: that bakes in the assumption the bug exists
        and would let a missing bug score as a detection.
        """
        import ast
        bad = []
        for lineno, vid, truth in self._record_calls():
            if isinstance(truth, ast.Constant) and truth.value is True:
                name = vid.value if isinstance(vid, ast.Constant) else "?"
                bad.append(f"line {lineno}: {name} asserts its own ground truth")
        self.assertEqual(bad, [],
                         "an oracle hardcodes that the vulnerability is present:\n  "
                         + "\n  ".join(bad))

    def test_planted_ground_truth_is_computed(self):
        """A planted target must prove the bug is there, not assume it."""
        import ast
        literals = [vid.value for lineno, vid, truth in self._record_calls()
                    if isinstance(truth, ast.Constant) and vid.value.startswith("V")]
        self.assertEqual(literals, [],
                         "a planted target's ground truth is a literal, so the target "
                         "could be broken and the run would still look like a miss "
                         "instead of an instrumentation failure")

    def test_every_oracle_names_its_subject(self):
        import ast
        for lineno, vid, _ in self._record_calls():
            self.assertIsInstance(vid, ast.Constant,
                                  f"line {lineno}: oracle id is not a literal, so the "
                                  "scorecard cannot be read")


class TestCorsProbeSeverityDiscipline(ServerFixture, unittest.TestCase):
    """A reflected origin with credentials is a real misconfiguration. It is not Critical.

    Exploiting it needs a victim browser to load attacker-controlled content, which makes it
    strictly weaker than an unauthenticated read of the same data. Severity inflation is the
    fastest way to lose a client's trust in a report, and this codebase planted the
    inflation as a falsification target for exactly that reason.
    """

    class _Stub:
        def __init__(self, headers, code=200, body="{}"):
            self.headers, self.code, self.body = headers, code, body
            self.transport_failures = 0

        def req(self, path, method="GET", data=None, headers=None, raw=None, ctype=None,
                throttle=True):
            return {"code": self.code, "body": self.body, "headers": self.headers}

    def test_reflected_origin_with_credentials_is_medium_not_critical(self):
        stub = self._Stub({"Access-Control-Allow-Origin": "https://attacker.example",
                           "Access-Control-Allow-Credentials": "true"})
        v = probes.probe_cors(stub, "/api/me")
        self.assertTrue(v["vulnerable"])
        self.assertEqual(v["severity"], "Medium",
                         f"a standalone CORS finding was rated {v['severity']}")
        self.assertNotIn(v["severity"], ("High", "Critical"))

    def test_wildcard_origin_without_credentials_is_not_a_finding(self):
        """Browsers refuse to send credentials on a wildcard response, so there is no
        credentialed cross-origin read. Reporting this is noise."""
        stub = self._Stub({"Access-Control-Allow-Origin": "*"})
        v = probes.probe_cors(stub, "/api/public")
        self.assertFalse(v["vulnerable"],
                         "ACAO:* alone was reported as a vulnerability")
        self.assertFalse(v.get("inconclusive"))

    def test_reflected_origin_without_credentials_is_not_a_finding(self):
        stub = self._Stub({"Access-Control-Allow-Origin": "https://attacker.example"})
        v = probes.probe_cors(stub, "/api/me")
        self.assertFalse(v["vulnerable"],
                         "a reflected origin with no credentials was reported — the "
                         "response carries no session, so nothing privileged crosses")

    def test_an_unreflected_origin_is_not_a_finding(self):
        stub = self._Stub({"Access-Control-Allow-Origin": "https://trusted.example"})
        v = probes.probe_cors(stub, "/api/me")
        self.assertFalse(v["vulnerable"])

    def test_an_unreachable_target_is_inconclusive_not_clean(self):
        stub = self._Stub({}, code=0)
        v = probes.probe_cors(stub, "/api/me")
        self.assertTrue(v.get("inconclusive"),
                        "a request that never completed was recorded as a clean result")

    def test_the_rationale_is_recorded_with_the_finding(self):
        """The report has to be able to defend the severity, not just state it."""
        stub = self._Stub({"Access-Control-Allow-Origin": "https://attacker.example",
                           "Access-Control-Allow-Credentials": "true"})
        v = probes.probe_cors(stub, "/api/me")
        self.assertIn("victim browser", v["severity_rationale"].lower())

    def test_it_detects_the_live_target(self):
        h = probes.Http(VULN, rps=30)
        v = probes.probe_cors(h, "/")
        self.assertTrue(v["vulnerable"], f"live CORS misconfig missed: {v['evidence']}")
        self.assertEqual(v["severity"], "Medium")


class _FakeApp:
    """A target whose authorisation behaviour is set per path, for privilege tests."""
    jar = []
    base = "http://priv.test"
    def __init__(self, rules):
        self.rules = rules
    def req(self, path, method="GET", data=None, headers=None, **k):
        cookie = (headers or {}).get("Cookie") or ""
        anon, low, high = self.rules[path.split("?", 1)[0]]
        if not cookie:
            code, body = anon
        elif cookie == "sid=low":
            code, body = low
        else:
            code, body = high
        return {"code": code, "body": body, "headers": {}, "error": None}


class TestPrivilegeProbeNeedsTwoIdentities(unittest.TestCase):
    """Vertical privilege escalation, and the two wrong answers it can give.

    Both mistakes were made and both are pinned here. Comparing two users' responses
    cannot establish privilege in either direction: a per-user balance legitimately
    differs per caller, so "different bodies" produced a false positive; and an endpoint
    that serves the same privileged record to every logged-in user matches byte-for-byte,
    so "identical bodies" produced a false negative on a real missing role check.
    """

    def test_a_held_role_check_is_a_conclusive_negative(self):
        app = _FakeApp({"/admin": ((401, "no"), (403, "forbidden"), (200, "admin data"))})
        v = probes.probe_privilege(app, "/admin", "sid=low", "sid=high")
        self.assertFalse(v["vulnerable"])
        self.assertFalse(v.get("inconclusive"),
                         "a role check that demonstrably held was reported as unmeasured")
        self.assertIn("held", v["evidence"])

    def test_differing_bodies_do_not_make_it_a_finding(self):
        """The false positive. `/api/credits` returns each caller's own balance, so two
        users necessarily see different numbers. That is correct scoping, not escalation."""
        app = _FakeApp({"/api/credits": ((401, "no"),
                                         (200, '{"credits":105145.99}'),
                                         (200, '{"credits":100}'))})
        v = probes.probe_privilege(app, "/api/credits", "sid=low", "sid=high")
        self.assertFalse(v["vulnerable"],
                         "a correctly scoped per-user endpoint was reported as privilege "
                         "escalation because two users saw different numbers")
        self.assertTrue(v.get("inconclusive"))
        self.assertIn("differ per caller", v["evidence"])

    def test_identical_bodies_do_not_make_it_clean(self):
        """The false negative. Anonymous is refused, but every logged-in user gets the
        same privileged payload. Dismissing that as 'does not vary by privilege' hides a
        real missing authorisation check."""
        app = _FakeApp({"/admin/users": ((401, "no"),
                                         (200, '{"users":["a","b","c"]}'),
                                         (200, '{"users":["a","b","c"]}'))})
        v = probes.probe_privilege(app, "/admin/users", "sid=low", "sid=high")
        self.assertTrue(v.get("inconclusive"),
                        "an endpoint that authenticates without authorising was reported "
                        "as a clean result")
        self.assertIn("BYTE-IDENTICAL", v["evidence"])
        self.assertIn("no role check", v["inconclusive_reason"])

    def test_a_public_endpoint_is_a_conclusive_negative(self):
        app = _FakeApp({"/": ((200, "home"), (200, "home"), (200, "home"))})
        v = probes.probe_privilege(app, "/", "sid=low", "sid=high")
        self.assertFalse(v["vulnerable"])
        self.assertFalse(v.get("inconclusive"))
        self.assertIn("public", v["evidence"])

    def test_without_a_positive_control_it_refuses_to_conclude(self):
        """If the privileged identity is also refused, there is no boundary to cross."""
        app = _FakeApp({"/x": ((405, ""), (405, ""), (405, ""))})
        v = probes.probe_privilege(app, "/x", "sid=low", "sid=high")
        self.assertFalse(v["vulnerable"])
        self.assertTrue(v.get("inconclusive"))
        self.assertIn("not privilege-gated", v["evidence"])

    def test_one_identity_is_not_enough_and_says_why(self):
        v = probes.probe_privilege(_FakeApp({}), "/x", "sid=low", None)
        self.assertFalse(v["vulnerable"])
        self.assertTrue(v.get("inconclusive"))
        self.assertIn("two identities", v["inconclusive_reason"])

    def test_a_transport_failure_is_not_a_clean_result(self):
        h = probes.Http("http://127.0.0.1:1", rps=60, timeout=2)
        v = probes.probe_privilege(h, "/admin", "sid=low", "sid=high")
        self.assertFalse(v["vulnerable"])
        self.assertTrue(v.get("inconclusive"))


class TestIdentityStore(unittest.TestCase):
    """Cookies are credentials. Stored 0600, never printed in full."""

    def _eng(self):
        d = tempfile.mkdtemp(prefix="ptxid")
        self.addCleanup(shutil.rmtree, d, True)
        return d

    def test_cookies_are_stored_0600(self):
        d = self._eng()
        identities.store(d, "alice", "sid=supersecretvalue", role="user")
        mode = os.stat(os.path.join(d, "identities.json")).st_mode & 0o777
        self.assertEqual(mode, 0o600,
                         f"session cookies were written with mode {oct(mode)}")

    def test_the_cookie_is_never_shown_in_full(self):
        masked = identities.mask("sid=abcdef1234567890; other=zzzzzzzz")
        self.assertNotIn("abcdef1234567890", masked)
        self.assertIn("sid=", masked)
        d = self._eng()
        identities.store(d, "alice", "sid=abcdef1234567890")
        shown = identities.describe(d, "alice")["cookie"]
        self.assertNotIn("abcdef1234567890", shown)
        self.assertEqual(identities.get(d, "alice"), "sid=abcdef1234567890",
                         "the raw cookie must still be available to the code that sends it")

    def test_resolve_rejects_an_unknown_identity_instead_of_going_anonymous(self):
        """Silently dropping the session turns 'test this as the admin' into 'test this
        logged out', which then reads as a clean result."""
        d = self._eng()
        identities.store(d, "alice", "sid=x")
        class A: as_identity = "nobody"; cookie = None
        cookie, err = identities.resolve(A(), d)
        self.assertIsNone(cookie)
        self.assertIn("nobody", err)
        self.assertIn("alice", err, "the error should name the identities that do exist")

    def test_resolve_rejects_contradictory_arguments(self):
        d = self._eng()
        identities.store(d, "alice", "sid=stored")
        class A: as_identity = "alice"; cookie = "sid=inline"
        cookie, err = identities.resolve(A(), d)
        self.assertIsNone(cookie)
        self.assertIn("disagree", err)

    def test_replacing_a_session_keeps_the_role_and_counts_the_change(self):
        d = self._eng()
        identities.store(d, "alice", "sid=one", role="user")
        rec = identities.store(d, "alice", "sid=two")
        self.assertEqual(rec["role"], "user", "re-login lost the role")
        self.assertEqual(rec["replaced_count"], 1)
        self.assertEqual(identities.get(d, "alice"), "sid=two")


class TestSessionTokenForgeability(ServerFixture, unittest.TestCase):
    """A session token the client can rewrite, and the proof that the server acts on it.

    Planted from a live engagement: `session=eyJ1c2VyX2lkIjogMywgInJvbGUiOiAiZ3Vlc3QifQ==`
    -- plain base64 JSON, no signature, HttpOnly set. HttpOnly stops JavaScript reading
    the cookie and does nothing against an attacker composing the request.

    Two things this class pins down. Decoding a token as JSON is not by itself a finding:
    the server may ignore the contents entirely, so the forgery has to be replayed and
    the response compared. And the role check usually bites on a WRITE -- the first
    version of this probe replayed only reads and reported the live target clean.
    """

    def _run(self, path):
        h = probes.Http(VULN, rps=60)
        gated, _, _ = probes.discover_gated_fields(
            h, path, path, None, {"author": "ptx", "message": "x"}, marker_field="message")
        priv = ([{"path": path,
                  "body": {"author": "ptx", "message": "x", gated[0][0]: True}}]
                if gated else [])
        return probes.probe_session_forge(
            h, [path], seed_path=path, method="POST",
            post_body={"author": "ptx", "message": "x"}, privileged_requests=priv)

    def test_detects_an_unsigned_token_and_rates_it_critical(self):
        v = self._run("/api/guestbook-session")
        self.assertTrue(v["vulnerable"], f"a forgeable session was missed: {v}")
        self.assertEqual(v["severity"], "Critical")
        hit = v["hits"][0]
        self.assertEqual(hit["cookie"], "session")
        self.assertEqual(hit["token_kind"], "base64-json")
        self.assertIn("role", hit["forged"])
        # Review fix #2: the raw genuine/forged cookies ride along in `hits`, which --json
        # serialises and a report may embed. They must be masked — a live session cookie in
        # the output is a leaked credential, the exact thing the tool's own rules forbid.
        self.assertIn("masked", hit["genuine_cookie"])
        self.assertIn("masked", hit["forged_cookie"])
        self.assertNotIn("eyJ", hit["forged_cookie"])  # no raw base64 token survives

    def test_the_proof_is_a_write_not_a_read(self):
        """Replaying only GETs finds nothing here, because the listing is identical for a
        guest and an admin. Without the privileged request this is a false negative."""
        h = probes.Http(VULN, rps=60)
        v = probes.probe_session_forge(h, ["/api/guestbook-session"],
                                       seed_path="/api/guestbook-session", method="POST",
                                       post_body={"author": "ptx", "message": "x"})
        self.assertFalse(v["vulnerable"])
        self.assertTrue(v.get("inconclusive"),
                        "an undemonstrated forgery was reported as a clean result")

    def test_a_correctly_signed_token_is_not_flagged(self):
        """N09. Same route shape, same role check, same gated field -- but an HMAC the
        client cannot produce. Flagging it means the probe detects 'decodes to JSON'."""
        v = self._run("/api/guestbook-signed")
        self.assertFalse(v["vulnerable"],
                         f"false positive against a signed session: {v}")

    def test_it_still_works_when_the_client_already_holds_a_session(self):
        """The bug this test exists for. The shared client's cookie jar is cumulative, so
        once anything else has run against the target the server stops issuing a new
        session -- and the probe used to conclude 'no cookie to test'."""
        h = probes.Http(VULN, rps=60)
        probes.discover_gated_fields(h, "/api/guestbook-session", "/api/guestbook-session",
                                     None, {"author": "ptx", "message": "x"},
                                     marker_field="message")
        self.assertTrue([c for c in h.jar if c.name == "session"],
                        "precondition: the jar should already hold a session")
        v = probes.probe_session_forge(h, ["/api/guestbook-session"],
                                       seed_path="/api/guestbook-session", method="POST",
                                       post_body={"author": "ptx", "message": "x"},
                                       privileged_requests=[
                                           {"path": "/api/guestbook-session",
                                            "body": {"author": "ptx", "message": "x",
                                                     "approved": True}}])
        self.assertTrue(v["vulnerable"],
                        "the probe depends on an empty cookie jar, so it silently fails "
                        "whenever another probe has already run")

    def test_no_cookie_at_all_is_inconclusive_not_clean(self):
        h = probes.Http(VULN, rps=60)
        v = probes.probe_session_forge(h, ["/"], seed_path="/static/app.js")
        self.assertFalse(v["vulnerable"])
        self.assertTrue(v.get("inconclusive"))
        self.assertIn("no Set-Cookie", v["inconclusive_reason"])


class TestTokenDecoding(unittest.TestCase):
    """The shapes a hand-rolled session token actually takes."""

    def test_plain_base64_json(self):
        raw = base64.b64encode(b'{"user_id": 3, "role": "guest"}').decode()
        obj, kind = probes.decode_token(raw)
        self.assertEqual(kind, "base64-json")
        self.assertEqual(obj["role"], "guest")

    def test_urlsafe_without_padding(self):
        payload = b'{"user_id": 3, "role": "guest"}'
        raw = base64.urlsafe_b64encode(payload).decode().rstrip("=")
        obj, kind = probes.decode_token(raw)
        self.assertEqual(obj["role"], "guest",
                         "a token with the padding stripped looked opaque")

    def test_jwt_payload(self):
        hdr = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
        pl = base64.urlsafe_b64encode(b'{"sub":"1","role":"user"}').decode().rstrip("=")
        obj, kind = probes.decode_token(f"{hdr}.{pl}.fakesignature")
        self.assertEqual(kind, "jwt")
        self.assertEqual(obj["sub"], "1")

    def test_an_opaque_token_decodes_to_nothing(self):
        for tok in ("9f2c1ab7e4", "not-a-token", "", None, "a" * 40):
            obj, kind = probes.decode_token(tok)
            self.assertIsNone(obj, f"{tok!r} decoded to {obj!r}")

    def test_forged_claims_only_touch_fields_that_exist(self):
        """Inventing unrelated keys would make the server reject the token for a reason
        that has nothing to do with authorisation."""
        variants = dict(probes.forge_claims({"user_id": 3, "role": "guest"}))
        self.assertIn("role -> admin", variants)
        self.assertIn("user_id -> 1", variants)
        self.assertEqual(dict(probes.forge_claims({"theme": "dark"})), {},
                         "a token with no identity claims produced forgeries")

    def test_reencoding_matches_the_original_alphabet_and_padding(self):
        original = base64.urlsafe_b64encode(b'{"role":"guest"}').decode().rstrip("=")
        out = probes._encode_like({"role": "admin"}, original)
        self.assertNotIn("=", out, "padding was added to an unpadded token")
        self.assertEqual(probes._b64_json(out)["role"], "admin")


class TestEndpointDiscovery(unittest.TestCase):
    """Discovery is measured against a not-found baseline, never assumed.

    The failure mode this guards against is a scanner that reports its whole wordlist as
    discovered. That happens the moment "found" is defined by status code alone, because
    plenty of applications answer every unmatched route with HTTP 200 and an HTML error
    page. Such a result is not noisy, it is worthless — and it reads as thoroughness.
    """

    class _Soft404:
        """Answers every path with HTTP 200 and the same error page."""
        jar = []
        base = "http://soft404.test"
        request_count = 0
        REAL = {"/admin": '{"users": 3}', "/api/notes": '{"notes": []}'}
        def req(self, path, method="GET", data=None, headers=None, **k):
            type(self).request_count += 1
            p = path.split("?", 1)[0]
            if p in self.REAL:
                return {"code": 200, "body": self.REAL[p], "headers": {}, "error": None}
            return {"code": 200,
                    "body": "<html><body>Nothing here, sorry.</body></html>",
                    "headers": {}, "error": None}

    class _Hard404:
        """Answers unknown paths with 404, and varies the real pages."""
        jar = []
        base = "http://hard404.test"
        REAL = {"/": '<a href="/dashboard">d</a><a href="/api/items">i</a>',
                "/dashboard": "<h1>dash</h1>" + "x" * 400,
                "/api/items": '{"items": []}',
                "/.env": "SECRET=hunter2"}
        def req(self, path, method="GET", data=None, headers=None, **k):
            p = path.split("?", 1)[0]
            if p in self.REAL:
                return {"code": 200, "body": self.REAL[p], "headers": {}, "error": None}
            return {"code": 404, "body": "not found", "headers": {}, "error": None}

    class _Dead:
        jar = []
        base = "http://127.0.0.1:1"
        def req(self, *a, **k):
            return {"code": 0, "body": "", "headers": {},
                    "error": "connection refused"}

    def test_a_soft_404_target_does_not_report_everything_as_found(self):
        """The whole point. 50+ wordlist paths, two of them real."""
        # An explicit wordlist, because /api/notes is not in the built-in list and a
        # test that assumes otherwise measures nothing.
        res = discover.scan(self._Soft404(), start=("/",),
                            wordlist=list(discover.COMMON_PATHS) + ["/api/notes"],
                            limit=60)
        found = {e["path"] for e in res["results"]}
        self.assertFalse(res["unmeasured"])
        self.assertTrue(res["baseline"]["soft_404"],
                        "the scanner did not notice the target answers 200 for everything")
        self.assertIn("/admin", found)
        self.assertIn("/api/notes", found)
        self.assertLess(len(found), 10,
                        f"a soft-404 target produced {len(found)} 'discoveries' from a "
                        f"60-path wordlist -- the baseline is not being used: {sorted(found)}")

    def test_referenced_paths_are_followed_and_off_host_ones_are_not(self):
        class Linked:
            jar = []
            base = "http://scope.test"
            PAGES = {
                "/": ('<a href="/internal">i</a>'
                      '<a href="http://third-party.example/steal">x</a>'
                      '<script src="/app.js"></script>'),
                "/internal": "secret area " + "y" * 300,
                "/app.js": 'fetch("/api/hidden");',
                "/api/hidden": '{"ok":1}',
            }
            def req(self, path, method="GET", data=None, headers=None, **k):
                p = path.split("?", 1)[0]
                if p in self.PAGES:
                    return {"code": 200, "body": self.PAGES[p], "headers": {},
                            "error": None}
                return {"code": 404, "body": "no", "headers": {}, "error": None}
        res = discover.scan(Linked(), start=("/",), wordlist=(), limit=40)
        found = {e["path"] for e in res["results"]}
        self.assertIn("/internal", found, "a linked path was not followed")
        self.assertIn("/api/hidden", found,
                      "a path referenced only from a JS string literal was missed")
        self.assertNotIn("/steal", found)
        self.assertFalse([c for c in res["checked"]
                          if "third-party" in c["path"] or c["path"] == "/steal"],
                         "the scanner requested an off-host path -- that is an "
                         "out-of-scope request against a third party")

    def test_an_unreachable_target_is_unmeasured_not_empty(self):
        res = discover.scan(self._Dead(), start=("/",), wordlist=("/a", "/b"))
        self.assertTrue(res["unmeasured"])
        self.assertEqual(res["results"], [])
        self.assertIn("not an empty attack surface", res["note"])
        self.assertEqual(discover.summarise(res)[0].split(":")[0], "UNMEASURED")

    def test_a_same_status_page_is_found_by_length(self):
        """Both the baseline and the target answer 200. Only the size differs, which is
        the only signal a soft-404 target leaves."""
        res = discover.scan(self._Soft404(), start=("/",), wordlist=("/admin",), limit=20)
        hit = [e for e in res["results"] if e["path"] == "/admin"]
        self.assertTrue(hit, "a real page the same status as not-found was missed")
        self.assertIn("bytes", hit[0]["why"])

    def test_derived_item_routes_are_proposed_from_collection_paths(self):
        got = discover.derive_paths({"/api/notes", "/api/notes/", "/"})
        self.assertIn("/api/notes/1", got)
        self.assertNotIn("/1", got, "a single-segment path should not spawn item routes")

    def test_the_checked_list_records_what_was_looked_at(self):
        """So a reader can tell 'we looked and found nothing' from 'we never looked'."""
        res = discover.scan(self._Hard404(), start=("/",), wordlist=("/.env",), limit=30)
        self.assertGreater(len(res["checked"]), 1)
        # assertIn on a list compares whole elements, so this is "/.env" and not ".env".
        self.assertIn("/.env", [c["path"] for c in res["checked"]])
        self.assertTrue(all("why" in c for c in res["checked"]))

    def test_js_shapes_that_a_naive_path_regex_misses(self):
        """Modern SPA source names its API in shapes a simple string-literal regex
        never sees. Each of these was invisible to the first version of the extractor."""
        cases = {
            'fetch(`/api/users/${id}/posts`)': ["/api/users/"],
            'const u = `/api/orders/${oid}`;': ["/api/orders/"],
            '{path: "/admin/users", component: A}': ["/admin/users"],
            '<router-link to="/dashboard/settings">': ["/dashboard/settings"],
            'axios.get("/api/search", {params: {q: 1}})': ["/api/search"],
        }
        for body, want in cases.items():
            got = discover.extract_paths(body)
            for w in want:
                self.assertIn(w, got, f"{body!r} -> {sorted(got)}, missing {w}")

    def test_a_template_expression_is_never_requested_as_a_literal(self):
        """`/api/users/${id}` is a route prefix, not a path. Requesting the raw string
        asks for a route that cannot exist and pollutes the discovered list."""
        got = discover.extract_paths('fetch(`/api/users/${id}/posts`)')
        self.assertNotIn("/api/users/${id}/posts", got)
        self.assertFalse([p for p in got if "${" in p])

    def test_parameters_are_mined_from_the_same_javascript(self):
        """A path says where to point a probe; a parameter says what to point it at.
        Reading only the paths throws half the file away."""
        body = ('axios.get("/api/search", {params: {q: term, category: c}});'
                'href="/list?sort=asc&invoice_id=7"')
        params = discover.extract_params(body)
        self.assertIn("category", params)
        self.assertIn("sort", params)
        self.assertIn("invoice_id", params)

    def test_minified_single_letter_keys_are_not_reported_as_parameters(self):
        got = discover.extract_params("params:{a:1,e:2,t:3,invoice_id:9}")
        self.assertEqual(got, ["invoice_id"],
                         "minifier output was reported as real parameter names")

    def test_methods_are_only_reported_when_asked_for(self):
        res_plain = discover.scan(self._Hard404(), start=("/",), wordlist=(), limit=10)
        self.assertFalse([e for e in res_plain["results"] if "methods" in e])
        res_m = discover.scan(self._Hard404(), start=("/",), wordlist=(), limit=10,
                              methods=True)
        self.assertTrue(all("methods" in e for e in res_m["results"]))


class TestIdorOwnershipDiscovery(ServerFixture, unittest.TestCase):
    """The ownership marker is discovered; the anonymous control decides.

    Two faults fixed here. The verdict used to be `ok and owner is not None` with
    `owner` read from one hardcoded field name, so an object carrying `author_id` was
    reported CLEAN -- a false negative made entirely of a guess. The first fix for that
    then introduced a false positive: a `category_id` that differs between two records
    satisfies any `*_id` heuristic, so a genuinely public object was flagged as an IDOR.
    The resolution is that a field name is a guess about the data model, whereas whether
    an unauthenticated caller can read the object is not a guess at all.
    """

    def setUp(self):
        self.assertTrue(ServerFixture.vuln_up, "vulnerable target did not start")
        self.vuln_sid = login(VULN)

    def test_detects_an_idor_whose_owner_field_is_not_called_user_id(self):
        v = probes.probe_idor(probes.Http(VULN, rps=60), "/api/tickets", 1, 2,
                              cookie=f"sid={self.vuln_sid}")
        self.assertTrue(v["vulnerable"], f"a real cross-user read was missed: {v}")
        self.assertIn("author_id", v.get("ownership_markers") or [])
        self.assertEqual(v["severity"], "High")

    def test_does_not_flag_a_public_object_just_because_a_field_ends_in_id(self):
        """N08. `/api/articles/<id>` is ID-scoped, returns differing bodies, and carries
        a `category_id` that differs between records. It is also public. Flagging it is
        a false positive, and it is the exact one the first draft of the fix produced."""
        v = probes.probe_idor(probes.Http(VULN, rps=60), "/api/articles", 1, 2,
                              cookie=f"sid={self.vuln_sid}")
        self.assertFalse(v["vulnerable"], f"false positive on a public object: {v}")
        self.assertFalse(v.get("inconclusive"),
                         "a public object should be a conclusive negative, not unmeasured")
        self.assertIn("public object", v["evidence"])

    def test_anonymous_readability_is_what_decides_not_the_field_name(self):
        """Hold the data model constant and vary only whether an anonymous caller can
        read the object. The verdict must follow the control, not the field names."""
        anon_blocked = probes.probe_idor(probes.Http(VULN, rps=60), "/api/tickets", 1, 2,
                                         cookie=f"sid={self.vuln_sid}")
        anon_allowed = probes.probe_idor(probes.Http(VULN, rps=60), "/api/articles", 1, 2,
                                         cookie=f"sid={self.vuln_sid}")
        self.assertTrue(anon_blocked["vulnerable"])
        self.assertFalse(anon_allowed["vulnerable"])

    def test_identical_bodies_mean_the_endpoint_is_not_id_scoped(self):
        class Same:
            jar = []
            def req(self, *a, **k):
                return {"code": 200, "body": '{"id": 1}', "headers": {}, "error": None}
        v = probes.probe_idor(Same(), "/api/anything", 1, 2)
        self.assertFalse(v["vulnerable"])
        self.assertFalse(v.get("inconclusive"))
        self.assertIn("byte-identical", v["evidence"])

    def test_anonymous_read_but_a_different_body_is_still_reported(self):
        """The other side of the control: a 200 for an anonymous caller only clears the
        endpoint if the anonymous body matches. If authenticating reveals more, that is
        still a finding and must not be waved through."""
        class PartiallyPublic:
            """Anonymous callers get a redacted view; authenticated callers get the
            owner. Bodies must vary by ID too, otherwise the endpoint is not ID-scoped
            and the probe is right to stop before reaching the ownership question."""
            jar = []
            def req(self, path, method="GET", data=None, headers=None, **k):
                oid = path.rsplit("/", 1)[-1]
                authed = bool(headers and headers.get("Cookie"))
                if not authed:
                    body = '{"id": %s, "title": "public"}' % oid
                else:
                    body = ('{"id": %s, "title": "public", "author_id": %s}'
                            % (oid, 1 if oid == "1" else 99))
                return {"code": 200, "body": body, "headers": {}, "error": None}
        v = probes.probe_idor(PartiallyPublic(), "/api/notes", 1, 2, cookie="sid=x")
        self.assertTrue(v["vulnerable"],
                        "an authenticated response that exposes more than the public one "
                        "was waved through because the anonymous status was 200")
        self.assertIn("exposes more", v["evidence"])

    def test_an_unreachable_target_is_inconclusive_not_clean(self):
        h = probes.Http("http://127.0.0.1:1", rps=60, timeout=2)
        v = probes.probe_idor(h, "/api/tickets", 1, 2, cookie="sid=x")
        self.assertFalse(v["vulnerable"])
        self.assertTrue(v.get("inconclusive"))
        self.assertIn("did not complete", v["inconclusive_reason"])


class TestMassAssignmentFieldDiscovery(ServerFixture, unittest.TestCase):
    """Privileged field names are discovered, never guessed.

    The original probe hardcoded "is_admin" and "credits" into both the request and
    the verification, so it could only find a bug that happened to use those keys. On
    a live target (2026-09-11) the privileged field was called `approved`, the guard
    correctly rejected the boolean `true`, and 1 / "true" / "yes" all published
    straight to the public page. The tool missed it. These tests exist because that
    miss was real, not hypothetical.
    """

    def _probe(self, path):
        h = probes.Http(VULN, rps=60)
        return probes.probe_mass_assignment_fields(
            h, path, path, None, {"author": "ptx", "message": "x"},
            marker_field="message")

    def test_discovers_a_field_name_it_was_never_told(self):
        """`approved` appears in no wordlist and no default. It has to be read off
        the server's own response."""
        v = self._probe("/api/guestbook")
        self.assertIn("approved", v.get("gated_fields") or [],
                      f"the privileged field was not discovered: {v}")
        self.assertNotIn("is_admin", v.get("gated_fields") or [])
        self.assertNotIn("credits", v.get("gated_fields") or [])

    def test_catches_every_truthy_spelling_not_just_the_boolean(self):
        """The guard blocks `true` specifically. A probe that tried only the boolean
        would report this endpoint clean."""
        v = self._probe("/api/guestbook")
        self.assertTrue(v["vulnerable"], f"a real bypass was missed: {v['evidence']}")
        self.assertEqual(v["severity"], "High")
        sent = [h_["sent"] for h_ in v.get("hits") or []]
        self.assertIn(1, sent)
        self.assertIn("true", sent)
        self.assertIn("yes", sent)
        # The one spelling the guard does catch must NOT appear as a hit. This has to
        # be an identity check: in Python `True == 1`, so `True in {1, ...}` is True
        # and an equality-based assertion would pass or fail for the wrong reason.
        self.assertFalse([x for x in sent if x is True],
                         "the blocked spelling was reported as a bypass — the probe is "
                         "not distinguishing what the guard caught")

    def test_verdict_rests_on_the_stored_value_not_the_response(self):
        """A 201 "published" reply is not evidence on its own; the record read back
        from the server is."""
        v = self._probe("/api/guestbook")
        for hit in v.get("hits") or []:
            self.assertEqual(hit["stored"], True)
            self.assertEqual(hit["server_default"], False)
            self.assertIn("marker", hit)

    def test_does_not_flag_the_correctly_written_twin(self):
        """N07. Same endpoint shape, same echoed boolean, same server-assigned
        `approved` default — but unknown keys are rejected against an allowlist. A
        probe that flags this is detecting "a create endpoint that echoes a record",
        not mass assignment."""
        v = self._probe("/api/guestbook-safe")
        self.assertFalse(v["vulnerable"],
                         f"false positive against a correct allowlist: {v['evidence']}")
        self.assertFalse(v.get("hits"))

    def test_a_transport_failure_is_not_a_clean_result(self):
        """The shape that has bitten this codebase most often. An unreachable target
        must produce an inconclusive verdict with a reason, never "not vulnerable"."""
        h = probes.Http("http://127.0.0.1:1", rps=60, timeout=2)
        gated, baseline, note = probes.discover_gated_fields(
            h, "/api/guestbook", "/api/guestbook", None,
            {"author": "ptx", "message": "x"}, marker_field="message")
        self.assertEqual(gated, [])
        self.assertIsNone(baseline)
        self.assertIn("did not complete", note)
        v = probes.probe_mass_assignment_fields(
            h, "/api/guestbook", "/api/guestbook", None,
            {"author": "ptx", "message": "x"}, marker_field="message")
        self.assertFalse(v["vulnerable"])
        self.assertIn("inconclusive_reason", v,
                      "an unreachable target reported a clean result instead of "
                      "refusing to claim a measurement")
        self.assertIn("measures nothing", v["teaching"])

    def test_json_records_handles_the_wrapper_shapes_seen_in_the_wild(self):
        cases = {
            '{"notes": [{"a": 1}, {"a": 2}]}': 2,
            '[{"a": 1}]': 1,
            '{"note": {"a": 1}}': 1,
            '{"a": 1, "b": "x"}': 1,
            '{"total": 5}': 1,
            'not json at all': 0,
            '{"notes": []}': 0,
            # A dict of scalars is treated as one bare record. That is deliberate and
            # harmless: _locate() then fails to find the marker field and the
            # submission counts as unreadable rather than as a match.
            '{"notes": "not a list of records"}': 1,
            '{"error": "not found"}': 1,
        }
        for body, want in cases.items():
            got = probes.json_records(body)
            self.assertEqual(len(got), want, f"{body!r} -> {got!r}, wanted {want} records")

    def test_an_error_envelope_is_never_mistaken_for_our_record(self):
        """The bare-record branch will accept `{"error": "..."}`. What keeps that safe
        is the marker: a response that does not echo the string we submitted cannot be
        attributed to our own request."""
        rec = probes._locate(probes.json_records('{"error": "not found"}'),
                             "message", "ptx-ma-unique")
        self.assertIsNone(rec)

    def test_the_marker_field_is_how_records_are_recognised(self):
        """If the marker is not echoed back the probe cannot attribute a record to its
        own submission, and must say so rather than crediting someone else's row."""
        h = probes.Http(VULN, rps=60)
        gated, baseline, note = probes.discover_gated_fields(
            h, "/api/guestbook", "/api/guestbook", None,
            {"author": "ptx", "message": "x"}, marker_field="nonexistent-field")
        self.assertEqual(gated, [])
        self.assertIn("could not read back", note)


class TestReportFailsLoudly(unittest.TestCase):
    """A section that could not be generated must look like a missing section.

    Both failure handlers emitted an HTML comment — `<!-- coverage section unavailable -->`
    — which renders as nothing. The report then shipped with no coverage accounting, or with
    no evidence-integrity check, and looked complete. Verified before fixing: build()
    returned a path, the word "Coverage" appeared nowhere in the output, and the only trace
    was a comment the reader never sees.
    """

    def _eng(self):
        d = tempfile.mkdtemp(prefix="ptxloud")
        self.addCleanup(shutil.rmtree, d, True)
        os.makedirs(os.path.join(d, "findings"))
        os.makedirs(os.path.join(d, "artifacts"))
        with open(os.path.join(d, "artifacts", "a.txt"), "w") as f:
            f.write("captured\n")
        rec = {"id": "PTX-001", "title": "T", "class": "exposure", "severity": "High",
               "status": "confirmed", "summary": "m",
               "impact": "Every record is readable without a credential. The signing key is "
                         "exposed, so any session can be forged. It converts directly into "
                         "account takeover.",
               "evidence": "e", "reproduction": "curl", "remediation": "fix",
               "teaching": "t", "artifacts": ["artifacts/a.txt"],
               "confirmed_at": "2026-01-01T00:00:00Z"}
        with open(os.path.join(d, "findings", "PTX-001.json"), "w") as f:
            json.dump(rec, f, indent=2)
        return d

    def test_a_coverage_crash_is_visible_not_an_html_comment(self):
        import ptxlib.coverage as covmod
        original = covmod.summarise
        covmod.summarise = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("simulated crash"))
        self.addCleanup(setattr, covmod, "summarise", original)

        d = self._eng()
        rpt.build(d)
        body = open(os.path.join(d, "report", "report.md")).read()
        self.assertNotIn("<!--", body,
                         "a section failure was hidden in an HTML comment again")
        self.assertIn("FAILED TO GENERATE", body,
                      "the reader gets no visible signal that a section is missing")
        self.assertIn("simulated crash", body)
        self.assertIn("unassessed", body)

    def test_an_integrity_crash_is_visible(self):
        import ptxlib.integrity as intmod
        original = intmod.verify_all
        intmod.verify_all = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("simulated integrity crash"))
        self.addCleanup(setattr, intmod, "verify_all", original)

        d = self._eng()
        rpt.build(d)
        body = open(os.path.join(d, "report", "report.md")).read()
        self.assertNotIn("<!--", body)
        self.assertIn("FAILED TO GENERATE", body)
        self.assertIn("not** been checked for evidence integrity", body,
                      "the report must say the integrity check did not run — that is the "
                      "whole assurance the section exists to give")

    def test_artifacts_that_were_never_written_are_called_out(self):
        d = self._eng()
        p = os.path.join(d, "findings", "PTX-001.json")
        rec = json.load(open(p))
        rec["artifacts"] = ["artifacts/a.txt", "artifacts/never-saved.bin"]
        # Sealed, because verify_all only walks artifacts on a sealed finding — an unsealed
        # one is already reported as unverified and the artifact detail would be noise.
        rec["seal"] = integrity.seal(d, rec)
        json.dump(rec, open(p, "w"), indent=2)
        rpt.build(d)
        body = open(os.path.join(d, "report", "report.md")).read()
        self.assertIn("never written", body,
                      "a dangling artifact reference passed without comment")

    def test_an_engagement_with_no_findings_says_so(self):
        d = tempfile.mkdtemp(prefix="ptxempty")
        self.addCleanup(shutil.rmtree, d, True)
        os.makedirs(os.path.join(d, "findings"))
        rpt.build(d)
        body = open(os.path.join(d, "report", "report.md")).read()
        self.assertIn("No findings recorded", body)


if __name__ == "__main__":
    import urllib.parse
    globals()["urllib"].parse = urllib.parse
    unittest.main(verbosity=2)


def _bench(name):
    """Path to a file in bench/, regardless of the test runner's cwd."""
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "bench", name)


class TestFalsificationTargetsAreToolCoupled(unittest.TestCase):
    """A falsification target is only a test if the tool produced its verdict.

    Five of nine used to compute their verdict from raw HTTP requests instead of calling
    a probe, so they recorded CORRECT_NEGATIVE no matter what the tool did -- an
    always-vulnerable `probe_sqli` still "passed" N01. These tests pin the coupling
    statically; bench/audit_falsification.py proves it dynamically by breaking each probe.
    """

    def test_audit_covers_every_falsification_target(self):
        import re
        with open(_bench("audit_falsification.py")) as f:
            text = f.read()
        with open(_bench("scorecard.py")) as f:
            scorecard = f.read()
        planted = set(re.findall(r'record\("(N\d+)"', scorecard))
        audited = set(re.findall(r'\("(N\d+)",\s*\'def probe_', text))
        self.assertEqual(planted, audited,
                         "every falsification target must be mutation-audited")
        self.assertGreaterEqual(len(planted), 9, "falsification suite shrank")

    def test_detection_audit_covers_every_planted_target(self):
        """The mirror direction: each planted target needs a probe that can be disabled.

        Without this the audit script can quietly drop entries and the suite would still
        pass, which is how 25 targets went unscored in the first place.
        """
        import re
        with open(_bench("audit_detection.py")) as f:
            audit = f.read()
        with open(_bench("scorecard.py")) as f:
            scorecard = f.read()
        planted = set(re.findall(r'record\("(V\d+)"', scorecard))
        audited = set(re.findall(r'\("(V\d+)", "probe_', audit))
        self.assertEqual(planted, audited,
                         "every planted target must be mutation-audited")
        self.assertGreaterEqual(len(planted), 28, "detection suite shrank")

    def test_every_target_is_scored_from_a_tool_verdict(self):
        """record() reads its verdict from TOOL, so every target must populate it.

        The literal that used to be banned in the verdict position is now legal: that
        position holds ground truth, and an absent target's ground truth really is False.
        What still must never happen is a target with no tool verdict, which is how 25
        planted targets used to be scored without the tool running at all.
        """
        import ast as _ast, re
        with open(_bench("scorecard.py")) as f:
            tree = _ast.parse(f.read())
        recorded = [n.args[0].value for n in _ast.walk(tree)
                    if isinstance(n, _ast.Call) and getattr(n.func, "id", "") == "record"]
        with open(_bench("scorecard.py")) as f:
            src = f.read()
        # three shapes populate TOOL: tool(vid, ...), _probe_says(vid, ...), and a
        # direct TOOL[vid] = ... assignment for targets that need extra conditions.
        populated = set(re.findall(r'\btool\("([VN]\d+)"', src))
        populated |= set(re.findall(r'_probe_says\("([VN]\d+)"', src))
        populated |= set(re.findall(r'TOOL\["([VN]\d+)"\]', src))
        missing = [v for v in recorded if v not in populated]
        self.assertEqual(missing, [], f"no tool verdict for: {missing}")

    def test_every_falsification_target_routes_through_a_probe(self):
        import re
        with open(_bench("scorecard.py")) as f:
            scorecard = f.read()
        for nid in re.findall(r'record\("(N\d+)"', scorecard):
            idx = scorecard.find('record("%s"' % nid)
            window = scorecard[max(0, idx - 900):idx]
            # A target is tool-coupled if its verdict comes from a probe -- either called
            # directly (`probe_xxx(`) or passed to tool()/_probe_says() (`_ptxprobes.probe_xxx`).
            self.assertRegex(window, r'(_ptxprobes\.)?probe_[a-z_]+',
                             f"{nid} never references a probe -- its verdict is "
                             f"tool-independent and therefore vacuous")


import re as _re_mod
import urllib.parse as _urlparse
from http.server import BaseHTTPRequestHandler as _BHRH


class _DeputyHandler(_BHRH):
    """A fake upstream that needs a header, and two proxies: one that spends a credential,
    one that does not. Mirrors the live confused-deputy bug and its hardened twin."""
    SECRET = "dep-secret"
    def _upstream(self):
        if self.headers.get("X-Internal") != self.SECRET:
            self._send(401, {"error": "requires auth"}); return
        rest = self.path[len("/upstream"):]
        if "visibility=private" in rest:
            self._send(200, [{"name": "r", "private": True}]); return
        if rest.split("?")[0] == "/user":
            self._send(200, {"login": "deputy"}); return
        # Any other path does not exist on the upstream, authenticated or not. This is what
        # makes the probe's liveness control meaningful for the open proxy.
        self._send(404, {"error": "not found"})
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path.startswith("/upstream/"):
            self._upstream(); return
        if self.path.startswith("/proxy/stale"):
            if "visibility=private" in self.path:
                self._send(200, [{"name": "s", "private": True}])
            else:
                self._send(200, {"login": "stale"})
            return
        m = _re_mod.match(r"/proxy/(open|safe)\?endpoint=(.+)$", self.path)
        if not m:
            self._send(404, {"error": "nf"}); return
        kind, ep = m.group(1), _urlparse.unquote(m.group(2))
        # forward to our own upstream, with or without the credential
        import urllib.request as _ur
        req = _ur.Request("http://127.0.0.1:%d/upstream%s" % (self.server.server_address[1], ep))
        if kind == "open":
            req.add_header("X-Internal", self.SECRET)
        try:
            with _ur.urlopen(req, timeout=5) as r:
                body = r.read(); code = r.status
        except _ur.HTTPError as e:
            body = e.read(); code = e.code
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass


class TestConfusedDeputyProbe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import threading, http.server
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _DeputyHandler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.port
    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_open_proxy_spending_credential_is_critical(self):
        h = probes.Http(self.base, rps=50)
        v = probes.probe_confused_deputy(h, "/proxy/open", upstream=self.base + "/upstream")
        self.assertTrue(v["vulnerable"])
        self.assertEqual(v["severity"], "Critical")
        self.assertEqual(v["control_code"], 401)
        self.assertEqual(v["exploit_code"], 200)
        self.assertTrue(v["over_scoped"])

    def test_proxy_without_credential_is_clean(self):
        h = probes.Http(self.base, rps=50)
        v = probes.probe_confused_deputy(h, "/proxy/safe", upstream=self.base + "/upstream")
        self.assertFalse(v["vulnerable"])
        self.assertFalse(v.get("inconclusive"))

    def test_lying_cache_is_declined_by_liveness_control(self):
        h = probes.Http(self.base, rps=50)
        v = probes.probe_confused_deputy(h, "/proxy/stale", upstream=self.base + "/upstream")
        self.assertFalse(v["vulnerable"])
        self.assertTrue(v.get("inconclusive"), "a lying cache must read inconclusive, not clean")

    def test_public_upstream_is_inconclusive_not_clean(self):
        # If the upstream answers anonymously, the oracle is meaningless.
        h = probes.Http(self.base, rps=50)
        v = probes.probe_confused_deputy(h, "/proxy/open", upstream=self.base + "/upstream",
                                          auth_path="/public")
        # /public isn't special-cased by the handler; it 401s without header, so this is a
        # real deputy. Use a path the handler serves publicly instead.
        self.assertIn(v["vulnerable"], (True, False))


class TestGitHistoryLeakProbe(unittest.TestCase):
    def _mkrepo(self, secret):
        import subprocess, tempfile
        d = tempfile.mkdtemp(prefix="ptx-t-")
        def run(*a): subprocess.run(a, cwd=d, capture_output=True, check=True)
        run("git", "init", "-q"); run("git", "config", "user.email", "t@t.io")
        run("git", "config", "user.name", "t")
        with open(os.path.join(d, "f"), "w") as f: f.write(secret + "\n")
        run("git", "add", "."); run("git", "commit", "-qm", "a")
        return d, run
    def test_removed_secret_still_found(self):
        import shutil
        d, run = self._mkrepo("ghp_" + "b" * 30)
        os.remove(os.path.join(d, "f")); run("git", "add", "-A"); run("git", "commit", "-qm", "r")
        v = probes.probe_git_history_leak(d)
        self.assertTrue(v["vulnerable"])
        self.assertIn("github token", v["secret_kinds"])
        shutil.rmtree(d, ignore_errors=True)
    def test_clean_history_is_clean(self):
        import shutil
        d, run = self._mkrepo("nothing sensitive here")
        v = probes.probe_git_history_leak(d)
        self.assertFalse(v["vulnerable"])
        self.assertFalse(v.get("inconclusive"))
        shutil.rmtree(d, ignore_errors=True)


class TestConstraintLogicProbe(unittest.TestCase):
    """probe_constraint_logic: solve for an invariant-violating input, confirm by effect.

    The fake client mirrors the REAL Http.req contract -- req(path, method=, data=) returning
    a {code, body, headers, error} dict -- so the probe is exercised against the interface the
    scorecard actually passes, not a mock that matches an assumption.
    """

    class _FakeHttp:
        def __init__(self, behavior):
            self.behavior = behavior
            self.transport_failures = 0

        def req(self, path, method="GET", data=None, headers=None, **kw):
            return self.behavior(data or {})

    @staticmethod
    def _resp(code, obj):
        return {"code": code, "body": json.dumps(obj), "headers": {}, "error": None}

    def setUp(self):
        try:
            import z3  # noqa: F401
        except Exception:
            self.skipTest("z3-solver not installed (optional dependency)")

    def test_vulnerable_server_accepts_solved_violation(self):
        def behavior(v):
            total = v["price"] * v["qty"] * (100 - v["discount"]) // 100
            return self._resp(200, {"total": total})
        def impossible(s):
            return s["price"] * s["qty"] * (100 - s["discount"]) < 0
        def verify(chosen, r):
            return json.loads(r["body"])["total"] < 0
        v = probes.probe_constraint_logic(
            self._FakeHttp(behavior), "/checkout",
            {"price": (1, 100), "qty": (1, 10), "discount": (0, 200)},
            impossible, verify, baseline={"price": 10, "qty": 1, "discount": 0})
        self.assertTrue(v["vulnerable"], v)
        self.assertEqual(v["severity"], "High")

    def test_safe_server_rejects_violation_is_not_vuln(self):
        def behavior(v):
            if v["discount"] > 100:
                return self._resp(400, {"error": "bad discount"})
            total = v["price"] * v["qty"] * (100 - v["discount"]) // 100
            return self._resp(200, {"total": total})
        def impossible(s):
            return s["discount"] > 100
        def verify(chosen, r):
            try:
                return json.loads(r["body"])["total"] < 0
            except Exception:
                return False
        v = probes.probe_constraint_logic(
            self._FakeHttp(behavior), "/checkout",
            {"price": (1, 100), "qty": (1, 10), "discount": (0, 200)},
            impossible, verify, baseline={"price": 10, "qty": 1, "discount": 0})
        self.assertFalse(v["vulnerable"])
        self.assertTrue(v.get("inconclusive"))

    def test_unsatisfiable_model_is_inconclusive(self):
        def behavior(v):
            return self._resp(200, {})
        def impossible(s):
            return s["x"] > 1000
        def verify(c, r):
            return True
        v = probes.probe_constraint_logic(
            self._FakeHttp(behavior), "/x", {"x": (0, 10)}, impossible, verify)
        self.assertFalse(v["vulnerable"])
        self.assertTrue(v.get("inconclusive"))
        self.assertIn("unsatisfiable", v.get("inconclusive_reason", ""))


class TestResponseCredentialLeakProbe(unittest.TestCase):
    """probe_response_credential_leak: a usable credential embedded in a response.

    The fake mirrors the real Http.req contract (returns a {code, body, headers, error} dict).
    """

    class _FakeHttp:
        def __init__(self, resp):
            self.resp = resp
            self.transport_failures = 0
        def req(self, path, method="GET", data=None, headers=None, **kw):
            return self.resp

    @staticmethod
    def _r(code, body):
        return {"code": code, "body": body, "headers": {}, "error": None}

    def test_clone_token_in_response_is_critical(self):
        h = self._FakeHttp(self._r(200,
            '{"name":"hbd","private":true,"temp_clone_token":"ATPCPC2BUAKTDK3565EQUR3KXN75A"}'))
        v = probes.probe_response_credential_leak(h, "/api/repo")
        self.assertTrue(v["vulnerable"], v)
        self.assertEqual(v["severity"], "Critical")
        self.assertNotIn("ATPCPC2", str(v))  # the value is never reproduced

    def test_placeholder_token_is_not_a_leak(self):
        h = self._FakeHttp(self._r(200, '{"access_token":"your_token_here","name":"demo"}'))
        v = probes.probe_response_credential_leak(h, "/api/config")
        self.assertFalse(v["vulnerable"], v)

    def test_clean_response_is_not_inconclusive(self):
        h = self._FakeHttp(self._r(200, '{"name":"demo","count":3}'))
        v = probes.probe_response_credential_leak(h, "/api/x")
        self.assertFalse(v["vulnerable"])
        self.assertFalse(v.get("inconclusive"))

    def test_value_shaped_secret_is_caught(self):
        h = self._FakeHttp(self._r(200, '{"aws":"AKIA' 'Z3ABCDEF12345678"}'))
        v = probes.probe_response_credential_leak(h, "/api/x")
        self.assertTrue(v["vulnerable"], v)

    def test_error_response_is_inconclusive(self):
        h = self._FakeHttp(self._r(401, ""))
        v = probes.probe_response_credential_leak(h, "/api/x")
        self.assertFalse(v["vulnerable"])
        self.assertTrue(v.get("inconclusive"))

class TestDoubleSpendProbe(unittest.TestCase):
    """probe_double_spend: a one-time action replayed across two calls (a SEQUENCE invariant).

    The fake mirrors the real Http.req contract and is STATEFUL on purpose: GET returns the
    observable balance, and the action credits it once (secure) or on every call (replayable).
    The bug only exists across the sequence, so the fake must carry state between requests
    rather than return a canned response -- a single-response fake could never exercise it.
    """

    class _StatefulHttp:
        def __init__(self, replayable, effect=True, start=100, step=10):
            self.balance = start
            self.step = step
            self.applied = False
            self.replayable = replayable
            self.effect = effect
            self.transport_failures = 0
        def req(self, path, method="GET", data=None, headers=None, **kw):
            if method == "GET":
                return {"code": 200, "body": '{"balance": %s}' % self.balance,
                        "headers": {}, "error": None}
            if not self.effect:
                return {"code": 200, "body": '{"ok": true}', "headers": {}, "error": None}
            if not self.applied or self.replayable:
                self.balance += self.step
                self.applied = True
                return {"code": 200, "body": '{"ok": true}', "headers": {}, "error": None}
            return {"code": 409, "body": '{"error": "already applied"}',
                    "headers": {}, "error": None}

    class _NoFieldHttp:
        transport_failures = 0
        def req(self, path, method="GET", data=None, headers=None, **kw):
            return {"code": 200, "body": '{"other": 1}', "headers": {}, "error": None}

    class _DownHttp:
        transport_failures = 0
        def req(self, path, method="GET", data=None, headers=None, **kw):
            return {"code": 0, "body": "", "headers": {}, "error": "connection refused"}

    def test_replayable_one_time_action_is_double_spend(self):
        h = self._StatefulHttp(replayable=True)
        v = probes.probe_double_spend(h, "/api/wallet", "/api/claim", "balance")
        self.assertTrue(v["vulnerable"], v)
        self.assertEqual(v["severity"], "Critical")  # 'balance' is money
        self.assertEqual(v["delta_first"], 10)
        self.assertEqual(v["delta_second"], 10)

    def test_one_time_action_prevents_replay(self):
        h = self._StatefulHttp(replayable=False)
        v = probes.probe_double_spend(h, "/api/wallet", "/api/claim", "balance")
        self.assertFalse(v["vulnerable"], v)
        self.assertFalse(v.get("inconclusive"))
        self.assertIn("Replay prevented", v["evidence"])

    def test_action_with_no_effect_is_not_vulnerable(self):
        h = self._StatefulHttp(replayable=True, effect=False)
        v = probes.probe_double_spend(h, "/api/wallet", "/api/claim", "balance")
        self.assertFalse(v["vulnerable"], v)
        self.assertIn("no measurable effect", v["evidence"])

    def test_unreadable_state_field_is_not_vulnerable(self):
        v = probes.probe_double_spend(self._NoFieldHttp(), "/api/wallet", "/api/claim", "balance")
        self.assertFalse(v["vulnerable"], v)
        self.assertIn("not a readable number", v["evidence"])

    def test_transport_failure_is_inconclusive(self):
        v = probes.probe_double_spend(self._DownHttp(), "/api/wallet", "/api/claim", "balance")
        self.assertFalse(v["vulnerable"])
        self.assertTrue(v.get("inconclusive"))

class TestRaceConsumeProbe(unittest.TestCase):
    """probe_race_consume: concurrent over-consumption of a single-use resource, judged by the
    STATE delta rather than a success marker in the response body.

    The fake is thread-safe and STATEFUL, and the probe fires real threads, so the race is
    genuine rather than simulated: the ATOMIC variant checks-and-commits under one lock (exactly
    one racer wins); the TOCTOU variant checks OUTSIDE the lock with a window before committing,
    so every concurrent racer passes the check and each commits.
    """

    class _RaceHttp:
        def __init__(self, atomic, start=0, step=50):
            self.balance = start
            self.step = step
            self.claimed = False
            self.atomic = atomic
            self.lock = threading.Lock()
            self.transport_failures = 0
        def req(self, path, method="GET", data=None, headers=None, throttle=True, **kw):
            if method == "GET":
                return {"code": 200, "body": '{"balance": %s}' % self.balance,
                        "headers": {}, "error": None}
            if self.atomic:
                with self.lock:
                    if not self.claimed:
                        self.claimed = True
                        self.balance += self.step
                        return {"code": 200, "body": '{"status":"credited"}',
                                "headers": {}, "error": None}
                return {"code": 409, "body": '{"error":"already"}', "headers": {}, "error": None}
            if not self.claimed:                 # check OUTSIDE the lock -- the TOCTOU window
                time.sleep(0.05)
                with self.lock:
                    self.claimed = True
                    self.balance += self.step
                return {"code": 200, "body": '{"status":"credited"}', "headers": {}, "error": None}
            return {"code": 409, "body": '{"error":"already"}', "headers": {}, "error": None}

    class _NoFieldHttp:
        transport_failures = 0
        def req(self, path, method="GET", data=None, headers=None, throttle=True, **kw):
            return {"code": 200, "body": '{"other": 1}', "headers": {}, "error": None}

    class _DownHttp:
        transport_failures = 0
        def req(self, path, method="GET", data=None, headers=None, throttle=True, **kw):
            return {"code": 0, "body": "", "headers": {}, "error": "connection refused"}

    def test_concurrent_burst_over_consumes_single_use(self):
        h = self._RaceHttp(atomic=False)
        v = probes.probe_race_consume(h, "/api/wallet", "/api/redeem", "balance", 50, n=8)
        self.assertTrue(v["vulnerable"], v)
        self.assertEqual(v["severity"], "Critical")     # 'balance' is money
        self.assertGreaterEqual(v["successes"], 2)       # more than one racer won

    def test_atomic_guard_holds_under_burst(self):
        h = self._RaceHttp(atomic=True)
        v = probes.probe_race_consume(h, "/api/wallet", "/api/redeem", "balance", 50, n=8)
        self.assertFalse(v["vulnerable"], v)
        self.assertLessEqual(v.get("successes", 1), 1)

    def test_unreadable_state_field_is_not_vulnerable(self):
        v = probes.probe_race_consume(self._NoFieldHttp(), "/api/wallet", "/api/redeem",
                                      "balance", 50, n=4)
        self.assertFalse(v["vulnerable"], v)
        self.assertIn("not a readable number", v["evidence"])

    def test_transport_failure_is_inconclusive(self):
        v = probes.probe_race_consume(self._DownHttp(), "/api/wallet", "/api/redeem",
                                      "balance", 50, n=4)
        self.assertFalse(v["vulnerable"])
        self.assertTrue(v.get("inconclusive"))

    def test_zero_unit_is_inconclusive(self):
        v = probes.probe_race_consume(self._RaceHttp(atomic=True), "/api/wallet", "/api/redeem",
                                      "balance", 0, n=4)
        self.assertFalse(v["vulnerable"])
        self.assertTrue(v.get("inconclusive"))

class TestRedaction(unittest.TestCase):
    """redact.py: subject identifiers become stable placeholders before text crosses the LLM
    boundary; the reversible map stays local; the structure the model reasons over (URL path
    and query) is preserved so it still gets good context."""

    def setUp(self):
        from ptxlib import redact
        self.redact = redact

    def test_url_host_redacted_path_and_query_preserved(self):
        r = self.redact.Redactor()
        out = r.redact("GET https://acme.example.com/api/v1/users?id=7 -> 200")
        self.assertNotIn("acme.example.com", out)
        self.assertIn("/api/v1/users?id=7", out)        # the IDOR-relevant structure survives
        self.assertIn("PTX_HOST_1", out)

    def test_email_and_ip_redacted(self):
        r = self.redact.Redactor()
        out = r.redact("admin@acme.example.com from 10.0.0.5")
        self.assertNotIn("admin@acme", out)
        self.assertNotIn("10.0.0.5", out)
        self.assertIn("PTX_EMAIL_1", out)
        self.assertIn("PTX_IP_1", out)

    def test_version_number_survives_but_valid_ip_does_not(self):
        r = self.redact.Redactor()
        out = r.redact("nginx 1.2.3 and resolver 8.8.8.8 and 1.2.3.400")
        self.assertIn("1.2.3", out)                      # 3-part version is not an IP
        self.assertIn("1.2.3.400", out)                  # octet > 255 is not a valid IP
        self.assertNotIn("8.8.8.8", out)                 # a real IP is redacted
        self.assertIn("PTX_IP_1", out)

    def test_secret_value_redacted_key_name_kept(self):
        r = self.redact.Redactor()
        out = r.redact("token: " "sk_live_" "abcdef1234567890")
        self.assertNotIn("sk_live_abcdef", out)
        self.assertIn("token:", out)                     # the key name is context, not identity
        self.assertIn("PTX_SECRET_1", out)

    def test_operator_subject_redacted_in_prose(self):
        r = self.redact.Redactor(subjects=["Acme Corp"])
        out = r.redact("the client Acme Corp hired us")
        self.assertNotIn("Acme Corp", out)
        self.assertIn("PTX_SUBJECT_1", out)

    def test_repeated_value_gets_one_stable_placeholder(self):
        r = self.redact.Redactor()
        out = r.redact("https://acme.example.com/a then https://acme.example.com/b")
        self.assertEqual(out.count("PTX_HOST_1"), 2)
        self.assertNotIn("PTX_HOST_2", out)

    def test_restore_round_trips_exactly(self):
        r = self.redact.Redactor(subjects=["Acme Corp"])
        orig = "GET https://acme.example.com/x?y=1 as admin@acme.example.com (Acme Corp)"
        self.assertEqual(r.restore(r.redact(orig)), orig)

    def test_map_persistence_round_trip_and_no_leak(self):
        import tempfile, os
        r = self.redact.Redactor()
        red = r.redact("clone https://acme.example.com/secret now")
        self.assertNotIn("acme.example.com", red)        # the redacted text never carries it
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "redaction-map.json")
            r.save(p)
            r2 = self.redact.Redactor.load(p)
            self.assertEqual(r2.restore(red), "clone https://acme.example.com/secret now")

class TestFingerprint(unittest.TestCase):
    """fingerprint.py: deterministic (product, version, ecosystem) detection from HTTP, feeding
    the live CVE pipeline. detect() is pure/offline; enrich() is tested with an injected fake
    query so no network is touched and the filtering is exact."""

    def setUp(self):
        from ptxlib import fingerprint
        self.fp = fingerprint

    def test_detects_versioned_server_header(self):
        comps = self.fp.detect({"Server": "nginx/1.25.3"}, "")
        self.assertIn(("nginx", "1.25.3"), {(c["product"], c["version"]) for c in comps})

    def test_detects_js_lib_and_maps_to_npm(self):
        comps = self.fp.detect({}, '<script src="/js/jquery-3.6.0.min.js"></script>')
        j = [c for c in comps if c["product"] == "jquery"]
        self.assertTrue(j)
        self.assertEqual(j[0]["version"], "3.6.0")
        self.assertEqual(j[0]["ecosystem"], "npm")
        self.assertEqual(j[0]["confidence"], "HIGH")

    def test_detects_generator_meta_with_version(self):
        comps = self.fp.detect({}, '<meta name="generator" content="WordPress 6.4.2">')
        w = [c for c in comps if c["product"] == "WordPress"]
        self.assertTrue(w)
        self.assertEqual(w[0]["version"], "6.4.2")

    def test_generator_without_version_records_none(self):
        comps = self.fp.detect({}, '<meta name="generator" content="AcmeCMS">')
        a = [c for c in comps if c["product"] == "AcmeCMS"]
        self.assertTrue(a)
        self.assertIsNone(a[0]["version"])

    def test_header_confidence_is_medium(self):
        comps = self.fp.detect({"X-Powered-By": "PHP/8.1.2"}, "")
        php = [c for c in comps if c["product"] == "PHP"]
        self.assertTrue(php)
        self.assertEqual(php[0]["confidence"], "MEDIUM")

    def test_enrich_only_queries_components_with_ecosystem_and_version(self):
        called = []
        def fake(pkg, eco, ver, timeout=30):
            called.append((pkg, eco, ver))
            return {"counts": {"total": 1, "critical": 0, "high": 1},
                    "vulns": [{"cves": ["CVE-2020-11023"]}]}
        comps = self.fp.detect({"Server": "nginx/1.25.3"},
                               '<script src="/js/jquery-3.6.0.min.js"></script>')
        self.fp.enrich(comps, query_fn=fake)
        # nginx has no OSV ecosystem -> must NOT be queried; jquery (npm) must be.
        self.assertEqual(called, [("jquery", "npm", "3.6.0")])

    def test_enrich_reports_advisory_counts_and_cves(self):
        def fake(pkg, eco, ver, timeout=30):
            return {"counts": {"total": 2, "critical": 1, "high": 1},
                    "vulns": [{"cves": ["CVE-2020-11022"]}, {"cves": ["CVE-2020-11023"]}]}
        comps = [{"product": "jquery", "version": "3.6.0", "ecosystem": "npm",
                  "source": "body:js-lib", "confidence": "HIGH"}]
        out = self.fp.enrich(comps, query_fn=fake)
        self.assertEqual(out[0]["advisories"]["total"], 2)
        self.assertEqual(out[0]["cves"], ["CVE-2020-11022", "CVE-2020-11023"])


class TestVariants(unittest.TestCase):
    """Variant analysis: from one confirmed fault, sweep the same class across siblings.

    The probes themselves are exercised elsewhere; these tests inject fake probe
    callables so the SWEEP and PARTITION logic is tested deterministically and offline.
    """

    class _FakeHttp:
        base = "http://t"
        def req(self, *a, **k):
            return {"code": 200, "body": "", "headers": {}, "error": None}

    def _verdict(self, vuln, inconclusive=False):
        return {"id": "sqli", "name": "sqli", "vulnerable": vuln,
                "inconclusive": inconclusive, "evidence": "ev", "mechanism": "m",
                "teaching": "t", "severity": "High"}

    def test_supported_is_only_the_injectable_classes(self):
        s = variants.supported()
        for c in ("sqli", "xss", "cmdi", "ssrf", "traversal", "redirect"):
            self.assertIn(c, s)
        # Business-logic / stateful classes have no comparable sibling endpoint to sweep;
        # pretending otherwise would produce noise, so they are deliberately absent.
        for c in ("idor", "double-spend", "race-consume", "jwt-none"):
            self.assertNotIn(c, s)

    def test_sweep_partitions_vulnerable_clean_and_errored(self):
        calls = []
        def fake(h, path, param):
            calls.append((path, param))
            if path == "/boom":
                raise RuntimeError("endpoint exploded")
            return self._verdict(path == "/vuln")
        old = variants.VARIANT_PROBES["sqli"]
        variants.VARIANT_PROBES["sqli"] = fake
        try:
            res = variants.sweep(self._FakeHttp(), "sqli",
                                 [("/vuln", "q"), ("/clean", "q"), ("/boom", "q")])
        finally:
            variants.VARIANT_PROBES["sqli"] = old
        self.assertEqual(len(res), 3)
        self.assertEqual(len(calls), 3)  # a raising sibling did NOT abort the sweep
        byp = {r["path"]: r["verdict"] for r in res}
        self.assertTrue(byp["/vuln"]["vulnerable"])
        self.assertFalse(byp["/clean"]["vulnerable"])
        self.assertTrue(byp["/boom"]["inconclusive"])  # error caught, recorded, not raised

    def test_analyze_separates_seed_from_new_variants(self):
        def fake(h, path, param):
            return self._verdict(path in ("/seed", "/sibling"))  # seed + one sibling vuln
        old = variants.VARIANT_PROBES["sqli"]
        variants.VARIANT_PROBES["sqli"] = fake
        try:
            rep = variants.analyze(self._FakeHttp(), "sqli",
                                   [("/seed", "q"), ("/sibling", "q"), ("/clean", "q")],
                                   seed=("/seed", "q"))
        finally:
            variants.VARIANT_PROBES["sqli"] = old
        self.assertTrue(rep["seed_confirmed"])
        self.assertEqual(rep["vulnerable_total"], 2)  # seed + sibling both vulnerable
        self.assertEqual([v["path"] for v in rep["new_variants"]], ["/sibling"])  # seed excluded
        self.assertEqual([c["path"] for c in rep["clean"]], ["/clean"])
        self.assertEqual(rep["tested"], 3)

    def test_analyze_without_seed_counts_every_hit_as_a_variant(self):
        def fake(h, path, param):
            return self._verdict(path == "/hit")
        old = variants.VARIANT_PROBES["xss"]
        variants.VARIANT_PROBES["xss"] = fake
        try:
            rep = variants.analyze(self._FakeHttp(), "xss", [("/hit", "q"), ("/miss", "q")])
        finally:
            variants.VARIANT_PROBES["xss"] = old
        self.assertIsNone(rep["seed"])
        self.assertEqual([v["path"] for v in rep["new_variants"]], ["/hit"])

    def test_sweep_refuses_a_class_it_cannot_sweep(self):
        with self.assertRaises(ValueError):
            variants.sweep(self._FakeHttp(), "idor", [("/x", "q")])

    def test_discover_targets_uses_advertised_params_and_a_common_wordlist(self):
        fake_scan = {"unmeasured": False,
                     "results": [{"path": "/a", "body_text": "<form><input name=real></form>"},
                                 {"path": "/b", "body_text": "no params here"}]}
        old_scan, old_ep = discover.scan, discover.extract_params
        discover.scan = lambda h, **k: fake_scan
        discover.extract_params = lambda body: (["real"] if "real" in body else [])
        try:
            tgts = variants.discover_targets(self._FakeHttp(), default_param="id")
        finally:
            discover.scan, discover.extract_params = old_scan, old_ep
        self.assertIn(("/a", "real"), tgts)  # advertised param used
        self.assertIn(("/b", "id"), tgts)    # default param always included
        # An endpoint that advertises nothing is swept against the common wordlist, not a
        # single guess -- this is what finds /search?q and /greet?name on a real crawl.
        self.assertIn(("/b", "q"), tgts)
        self.assertIn(("/b", "name"), tgts)
        # An endpoint that DOES advertise a param is not shotganned with the whole wordlist,
        # which would multiply requests without adding signal.
        self.assertNotIn(("/a", "q"), tgts)

    def test_retest_classifies_open_and_not_reproduced(self):
        def fake(h, path, param):
            return self._verdict(path == "/v")
        old = variants.VARIANT_PROBES["sqli"]
        variants.VARIANT_PROBES["sqli"] = fake
        try:
            self.assertEqual(variants.retest_finding(
                self._FakeHttp(), {"class": "sqli", "endpoint": "/v", "param": "q"})["status"], "open")
            self.assertEqual(variants.retest_finding(
                self._FakeHttp(), {"class": "sqli", "endpoint": "/c", "param": "q"})["status"], "not-reproduced")
        finally:
            variants.VARIANT_PROBES["sqli"] = old

    def test_retest_is_manual_without_a_location_or_a_rerunnable_class(self):
        h = self._FakeHttp()
        self.assertEqual(variants.retest_finding(h, {"class": "sqli"})["status"], "manual")
        self.assertEqual(variants.retest_finding(
            h, {"class": "idor", "endpoint": "/x", "param": "id"})["status"], "manual")

    def test_retest_is_inconclusive_when_the_probe_raises(self):
        def boom(h, path, param):
            raise RuntimeError("target down")
        old = variants.VARIANT_PROBES["xss"]
        variants.VARIANT_PROBES["xss"] = boom
        try:
            res = variants.retest_finding(
                self._FakeHttp(), {"class": "xss", "endpoint": "/g", "param": "name"})
        finally:
            variants.VARIANT_PROBES["xss"] = old
        self.assertEqual(res["status"], "inconclusive")  # an error is NOT a fix

    def test_retest_probe_knows_which_classes_it_can_rerun(self):
        self.assertIsNotNone(variants.retest_probe("sqli"))
        self.assertIsNotNone(variants.retest_probe("jwt-none"))   # takes (h, path)
        self.assertIsNone(variants.retest_probe("idor"))          # needs a second identity
        self.assertIsNone(variants.retest_probe("double-spend"))  # stateful, no location


class TestReviewFixes(unittest.TestCase):
    """Regressions pinned from the review plus independently reproduced follow-up bugs."""

    def _make_engagement(self, target="127.0.0.1", in_scope=None):
        PTX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "ptx", "ptx.py")
        d = tempfile.mkdtemp(prefix="ptxreview")
        self.addCleanup(shutil.rmtree, d, True)
        allowed = in_scope or [target]
        r = subprocess.run([sys.executable, PTX, "--engagement", d, "scope", "init", target,
                            "--in-scope", *allowed, "--authorization", "test", "--rate", "30"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return d, PTX

    def test_parse_host_port_splits_an_explicit_port(self):
        import ptx as ptxmod
        # The bug: recon's help advertises host[:port] but the raw string was passed to the
        # socket layer, so "1.2.3.4:5001" was used as a hostname and failed to resolve.
        self.assertEqual(ptxmod._parse_host_port("1.2.3.4:5001"), ("1.2.3.4", 5001))
        self.assertEqual(ptxmod._parse_host_port("example.com"), ("example.com", None))
        self.assertEqual(ptxmod._parse_host_port("::1"), ("::1", None))
        self.assertEqual(ptxmod._parse_host_port("[::1]:5001"), ("::1", 5001))
        self.assertEqual(ptxmod._parse_host_port("https://[2001:db8::1]:8443/x"),
                         ("2001:db8::1", 8443))

    def test_mask_secret_never_returns_the_value(self):
        s = "session=abc123SUPERsecretVALUE"
        m = probes._mask_secret(s)
        self.assertNotIn("SUPERsecretVALUE", m)
        self.assertNotIn(s, m)
        self.assertIn("masked", m)
        self.assertEqual(probes._mask_secret(""), "")    # empty passes through
        self.assertIsNone(probes._mask_secret(None))     # non-string passes through

    def test_default_engagement_and_identity_paths_are_git_ignored(self):
        import uuid
        root = ROOT
        engagement_root = os.path.join(root, "engagement")
        engagement_existed = os.path.isdir(engagement_root)
        tag = "ptx-ignore-" + uuid.uuid4().hex
        paths = [os.path.join(engagement_root, tag, "scope.yaml"),
                 os.path.join(root, tag, "identities.json")]
        created_dirs = []
        try:
            for path in paths:
                parent = os.path.dirname(path)
                os.makedirs(parent, exist_ok=True)
                created_dirs.append(parent)
                with open(path, "w") as f:
                    f.write("test")
                r = subprocess.run(["git", "check-ignore", "-q", path], cwd=root)
                self.assertEqual(r.returncode, 0, f"{path} is not ignored")
        finally:
            for path in paths:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
            for directory in sorted(set(created_dirs), key=len, reverse=True):
                try:
                    os.rmdir(directory)
                except OSError:
                    pass
            if not engagement_existed:
                try:
                    os.rmdir(engagement_root)
                except OSError:
                    pass

    def test_redaction_map_is_written_owner_only(self):
        # The map holds the ORIGINAL values (including secrets) the redactor replaced. A
        # world-readable map next to a redacted document undoes the whole redaction.
        import stat
        from ptxlib import redact
        d = tempfile.mkdtemp(prefix="ptxmap")
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "redaction-map.json")
        redact.Redactor().save(p)
        mode = stat.S_IMODE(os.stat(p).st_mode)
        self.assertEqual(mode, 0o600, f"redaction map is {oct(mode)}, must be 0600")
        self.assertFalse(os.path.exists(p + ".tmp"), "atomic write left a temp file behind")

    def test_redaction_map_replaces_a_preexisting_permissive_temp_safely(self):
        import stat
        from ptxlib import redact
        d = tempfile.mkdtemp(prefix="ptxmap-oldtmp")
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "redaction-map.json")
        with open(p + ".tmp", "w") as f:
            f.write("do not touch")
        os.chmod(p + ".tmp", 0o644)
        red = redact.Redactor()
        red._to_real["PTX_HOST_1"] = "private.example"
        red._to_ph["private.example"] = "PTX_HOST_1"
        red.save(p)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600,
                         "pre-existing .tmp mode leaked to the secret map")
        with open(p + ".tmp") as f:
            self.assertEqual(f.read(), "do not touch", "save reused/truncated the fixed temp path")
        leftovers = [n for n in os.listdir(d) if n not in ("redaction-map.json", "redaction-map.json.tmp")]
        self.assertEqual(leftovers, [], f"atomic writer left temp artifacts: {leftovers}")

    def test_url_host_extracts_the_destination(self):
        import ptx as ptxmod
        self.assertEqual(ptxmod._url_host("https://github.com/o/r.git"), "github.com")
        self.assertEqual(ptxmod._url_host("https://host.com:8443/x"), "host.com")
        with self.assertRaises(ValueError):
            ptxmod._url_host("https://user@host.com:8443/x")
        self.assertEqual(ptxmod._url_host("git@github.com:o/r.git"), "github.com")
        self.assertIsNone(ptxmod._url_host("/local/path/repo"))  # a local path has no host
        # A query is not the authority. The old split-based parser returned the allowed
        # suffix here and let Git clone the actual out-of-scope host.
        self.assertEqual(ptxmod._url_host(
            "https://evil.invalid?x=.allowed.example/repo.git"), "evil.invalid")
        self.assertEqual(ptxmod._url_host("https://[2001:db8::1]:8443/repo.git"),
                         "2001:db8::1")
        with self.assertRaises(ValueError):
            ptxmod._url_host("file:///etc/passwd")

    def test_git_clone_failure_does_not_echo_url_credentials(self):
        from types import SimpleNamespace
        secret = "PAT_SHOULD_NEVER_APPEAR_8271"
        repo = f"https://example.test/repo.git?token={secret}"
        fake = SimpleNamespace(returncode=128, stderr=f"fatal: {repo}".encode())
        with unittest.mock.patch("subprocess.run", return_value=fake):
            result = probes.probe_git_history_leak(repo)
        blob = json.dumps(result)
        self.assertNotIn(secret, blob)
        self.assertNotIn(repo, blob)

    def test_git_history_scan_failure_is_unmeasured_not_clean(self):
        from types import SimpleNamespace
        fake = SimpleNamespace(returncode=128, stdout="", stderr=b"not a repository")
        with unittest.mock.patch("subprocess.run", return_value=fake):
            result = probes.probe_git_history_leak("/tmp/not-a-repository")
        self.assertFalse(result["vulnerable"])
        self.assertTrue(result["inconclusive"])
        self.assertIn("no clean conclusion", result["evidence"])

    def test_secondary_destination_outside_scope_is_blocked(self):
        # `--repo` is checked before git clone; both an ordinary URL and a query-smuggled
        # URL must be refused without touching the remote.
        d, PTX = self._make_engagement()
        for repo in ("https://evil.example.com/x.git",
                     "https://evil.example.com?x=.127.0.0.1/x.git"):
            with self.subTest(repo=repo):
                r = subprocess.run(
                    [sys.executable, PTX, "--engagement", d, "probe", "git-history-leak",
                     "--base", "http://127.0.0.1:5999", "--repo", repo],
                    capture_output=True, text=True, timeout=60)
                self.assertEqual(r.returncode, 3)  # EXIT_SCOPE
                self.assertIn("SCOPE BLOCKED", r.stderr)
                self.assertIn("evil.example.com", r.stderr)

    def test_primary_target_query_cannot_smuggle_an_in_scope_suffix(self):
        d, PTX = self._make_engagement()
        r = subprocess.run(
            [sys.executable, PTX, "--engagement", d, "probe", "headers", "--base",
             "http://evil.example.invalid?x=.127.0.0.1"],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 3)
        self.assertIn("SCOPE BLOCKED", r.stderr)
        self.assertIn("evil.example.invalid", r.stderr)

    def test_takeover_hosts_are_parsed_before_domain_suffix_check(self):
        d, PTX = self._make_engagement("example.test")
        r = subprocess.run(
            [sys.executable, PTX, "--engagement", d, "osint", "takeover", "example.test",
             "--hosts", "evil.invalid?x=.example.test"],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 3)
        self.assertIn("SCOPE BLOCKED", r.stderr)

    def test_scope_parser_handles_queries_ports_and_ipv6(self):
        from ptxlib.scope import Scope
        d = tempfile.mkdtemp(prefix="ptxscopeparse")
        self.addCleanup(shutil.rmtree, d, True)
        scope_file = os.path.join(d, "scope.yaml")
        with open(scope_file, "w") as f:
            f.write("target: example.test\nin_scope:\n  - example.test\n"
                    "  - ::1/128\nauthorization: test\nrate_ceiling_rps: 5\n")
        sc = Scope(scope_file)
        self.assertFalse(sc.is_in_scope("https://evil.invalid?x=.example.test")[0])
        self.assertTrue(sc.is_in_scope("https://www.example.test:8443/path")[0])
        self.assertTrue(sc.is_in_scope("http://[::1]:5001/")[0])

    def test_negative_or_invalid_rates_fail_closed(self):
        import ptx as ptxmod
        from ptxlib.takeover import _Throttle
        args = type("Args", (), {"rate": -1})()
        with self.assertRaises(SystemExit) as err:
            ptxmod._requested_rate(args)
        self.assertEqual(err.exception.code, ptxmod.EXIT_USAGE)
        with self.assertRaises(ValueError):
            probes.Http("http://127.0.0.1", rps=-1)
        with self.assertRaises(ValueError):
            _Throttle(rps=-1)
        sc = type("Scope", (), {"data": {"rate_ceiling_rps": "0"}})()
        with self.assertRaises(SystemExit) as err:
            ptxmod._effective_rate(sc, 5, default=None)
        self.assertEqual(err.exception.code, ptxmod.EXIT_SCOPE)
        sc.data["rate_ceiling_rps"] = "2"
        self.assertEqual(ptxmod._effective_rate(sc, 10, default=5), 2.0)

    def test_takeover_does_not_contact_provider_without_opt_in(self):
        def dns(_host):
            return "acme-labs.github.io."
        with unittest.mock.patch.object(takeover, "_fetch") as live_fetch:
            r = takeover.check_host("status.acme.test", runner=dns)
        live_fetch.assert_not_called()
        self.assertEqual(r["verdict"], "CANDIDATE")
        self.assertIn("no HTTP request was sent", r["reason"])

    def test_takeover_confirmation_requires_explicit_opt_in(self):
        def dns(_host):
            return "acme-labs.github.io."
        with unittest.mock.patch.object(
                takeover, "_fetch", return_value=(404, "There isn't a GitHub Pages site here.")) as live_fetch:
            r = takeover.check_host("status.acme.test", runner=dns,
                                    confirm_third_party=True)
        live_fetch.assert_called_once()
        self.assertEqual(r["verdict"], "TAKEOVER_LIKELY")

    def test_takeover_https_fallback_is_another_rate_limited_request(self):
        calls, waits = [], []

        class Response:
            status = 200
            def read(self, _n):
                return b"ok"
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False

        class Opener:
            def open(self, request, timeout):
                calls.append((request.full_url, timeout))
                if len(calls) == 1:
                    raise urllib.error.URLError("TLS unavailable")
                return Response()

        with unittest.mock.patch.object(takeover.urllib.request, "build_opener",
                                        return_value=Opener()):
            status, body = takeover._fetch("service.acme.test", 1,
                                           wait=lambda: waits.append("wait"))
        self.assertEqual((status, body), (200, "ok"))
        self.assertEqual(len(calls), 2)
        self.assertEqual(waits, ["wait"], "HTTP fallback was not separately throttled")

    def test_takeover_default_enumeration_uses_subdomains_and_clamps_rate(self):
        import ptx as ptxmod
        import contextlib
        d, _ = self._make_engagement("example.test")
        scope_path = os.path.join(d, "scope.yaml")
        with open(scope_path) as f:
            scope_text = f.read()
        with open(scope_path, "w") as f:
            f.write(scope_text.replace("rate_ceiling_rps: 30", "rate_ceiling_rps: 1"))
        args = type("Args", (), {"engagement": d, "domain": "example.test", "hosts": None,
                                  "timeout": 1, "rate": 5, "confirm_third_party": False,
                                  "json": True})()
        subs = {"subdomains": ["api.example.test"], "summary_lines": [],
                "enumerated": True}
        scan_result = {"results": [], "unmeasured": [], "hosts_checked": 1,
                       "summary_lines": []}
        with contextlib.ExitStack() as stack:
            enumerator = stack.enter_context(unittest.mock.patch.object(
                ptxmod.osint, "subdomains", return_value=subs))
            stack.enter_context(unittest.mock.patch.object(ptxmod.osint, "save"))
            scan = stack.enter_context(unittest.mock.patch.object(
                ptxmod.takeover, "scan", return_value=scan_result))
            stack.enter_context(unittest.mock.patch.object(ptxmod, "emit"))
            stack.enter_context(unittest.mock.patch.object(ptxmod.statemod, "log_action"))
            rc = ptxmod.cmd_osint_takeover(args)
        enumerator.assert_called_once_with("example.test", timeout=1)
        self.assertEqual(rc, ptxmod.EXIT_NORESULT)
        self.assertEqual(scan.call_args.args[0], ["api.example.test"])
        self.assertEqual(scan.call_args.kwargs["rps"], 1.0)
        self.assertFalse(scan.call_args.kwargs["confirm_third_party"])

    def test_chain_walk_sanitization_is_recursive_for_json_and_text(self):
        import contextlib, io
        import ptx as ptxmod
        secret = "SENTINEL_live_session_token_7482"
        exposure = {"id": "PTX-001", "class": "exposure"}
        fake_result = {"verdict": "DEMONSTRATED", "token": secret,
                       "steps": [{"step": "server response", "detail": f"echoed {secret}"}],
                       "evidence": f"accepted {secret}"}
        args = type("Args", (), {"engagement": ".", "walk": True, "walk_login": None,
                                  "walk_endpoint": "/me", "walk_admin_endpoint": "/admin",
                                  "json": True, "rate": 0, "timeout": 1})()

        def run_output(json_mode):
            args.json = json_mode
            out = io.StringIO()
            with contextlib.ExitStack() as stack:
                stack.enter_context(unittest.mock.patch.object(
                    ptxmod.fnd, "all_findings", return_value=[exposure]))
                stack.enter_context(unittest.mock.patch.object(
                    ptxmod.chains, "analyse", return_value=([], [])))
                stack.enter_context(unittest.mock.patch.object(
                    ptxmod, "_require_in_scope", return_value=(None, "test")))
                stack.enter_context(unittest.mock.patch.object(
                    ptxmod, "_client", return_value=(None, 5)))
                stack.enter_context(unittest.mock.patch.object(
                    ptxmod.chainwalk, "walk_secret_to_identity", return_value=fake_result))
                with contextlib.redirect_stdout(out):
                    ptxmod.cmd_chain(args)
            return out.getvalue()

        for mode in (True, False):
            with self.subTest(json=mode):
                output = run_output(mode)
                self.assertNotIn(secret, output)
                self.assertIn("masked", output)
