"""Subdomain takeover detection.

A dangling CNAME is one of the highest-yield findings in a web engagement: the target's
domain still points at a third-party service where the resource has been deprovisioned, so
an attacker claims it there and immediately serves content — including cookies scoped to a
parent domain — from inside the target's own namespace.

It is also entirely passive until the last step, which is why it belongs in OSINT rather
than in the probe suite: the CNAME chain is read from public DNS, and only the confirmation
request touches the third-party service.

Three states, deliberately:

  TAKEOVER_LIKELY   the CNAME points at a service that can be claimed AND that service
                    answered with its "this resource does not exist" marker. Claimable.
  CANDIDATE         the CNAME points at a takeable service but the confirmation could not
                    be read. A lead, not a finding — the operator must check it.
  (nothing)         the CNAME is not a known-takeable target.

The distinction between the first two is the same one that cost this codebase a bug before:
"could not confirm" is not "not vulnerable", and reporting it as clean is how a real
takeover disappears from a report.
"""
import math
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request

UA = "ptx-takeover/1.0 (authorized assessment)"

# service -> how to recognise a dangling delegation to it.
#
#   cname       CNAME suffixes that mean "delegated to this service"
#   markers     response text proving the resource on that service is unclaimed.
#               A dangling CNAME alone is NOT proof: the record may point at a live
#               resource the operator simply forgot to document.
#   claim       what claiming it looks like, so the finding is actionable.
TAKEABLE = [
    {"service": "GitHub Pages", "cname": ("github.io", "github.map.fastly.net"),
     "markers": ("There isn't a GitHub Pages site here",
                 "For root URLs (like http://example.com/) you must provide an index.html"),
     "claim": "create a repository or org with the same name"},
    {"service": "Heroku", "cname": ("herokuapp.com", "herokudns.com", "herokussl.com"),
     "markers": ("No such app", "no-such-app", "There is no app configured at this hostname"),
     "claim": "create a Heroku app with the subdomain's first label"},
    {"service": "Amazon S3", "cname": ("s3.amazonaws.com", "s3-website.amazonaws.com",
                                       "s3-website-us-east-1.amazonaws.com",
                                       "s3-website.eu-west-1.amazonaws.com",
                                       "s3-website-us-west-2.amazonaws.com",
                                       "s3-website-ap-southeast-1.amazonaws.com",
                                       "s3-website-ap-northeast-1.amazonaws.com",
                                       "s3-website-sa-east-1.amazonaws.com"),
     "markers": ("NoSuchBucket", "The specified bucket does not exist"),
     "claim": "create the S3 bucket with that exact name"},
    {"service": "Azure App Service", "cname": ("azurewebsites.net", "cloudapp.net",
                                               "azurehdinsight.net", "scm.azurewebsites.net"),
     "markers": ("404 Web Site not found", "Error 404 - Web app not found"),
     "claim": "create an Azure App Service with that name"},
    {"service": "Fastly", "cname": ("fastly.net", "fastlylb.net"),
     "markers": ("Fastly error: unknown domain", "Fastly - Unknown Domain"),
     "claim": "add the domain to a Fastly service you control"},
    {"service": "Netlify", "cname": ("netlify.app", "netlify.com", "s3.amazonaws.com"),
     "markers": ("Not Found - Request ID", "Site not found", "Looks like you're lost"),
     "claim": "create a Netlify site with that subdomain"},
    # `myshopify.com`, not `shops.myshopify.com`: a dangling Shopify delegation is
    # `<name>.myshopify.com`, so the narrower suffix could never match anything. This is
    # the fifth time in this codebase that a pattern was narrower than the thing it was
    # meant to recognise, and the third time the failure was silence rather than an error.
    {"service": "Shopify", "cname": ("myshopify.com",),
     "markers": ("Sorry, this shop is currently unavailable",
                 "To finish setting up your new web address"),
     "claim": "create a Shopify store with that name"},
    {"service": "Pantheon", "cname": ("pantheonsite.io",),
     "markers": ("The gods are wise", "404 error unknown site"),
     "claim": "create a Pantheon site with that name"},
    {"service": "Ghost", "cname": ("ghost.io",),
     "markers": ("The thing you were looking for is just not there",
                 "Site unavailable", "offline.ghost.org"),
     "claim": "create a Ghost publication with that subdomain"},
    {"service": "Webflow", "cname": ("proxy-ssl.webflow.com", "proxy.webflow.com"),
     "markers": ("The requested URL was not found on this server",
                 "Hmm, we couldn't find that page"),
     "claim": "create a Webflow site bound to that domain"},
    {"service": "Zendesk", "cname": ("zendesk.com",),
     "markers": ("Help Center Closed", "Oops, this help center no longer exists"),
     "claim": "register a Zendesk account with that subdomain"},
    {"service": "Freshdesk", "cname": ("freshdesk.com",),
     "markers": ("May be this is still unclaimed", "Sorry, this helpdesk is no longer"),
     "claim": "sign up for Freshdesk with that subdomain"},
    {"service": "Help Scout", "cname": ("helpscoutdocs.com",),
     "markers": ("No settings were found for this company",),
     "claim": "create a Help Scout docs site with that name"},
    {"service": "Intercom", "cname": ("custom.intercom.help",),
     "markers": ("Uh oh. That page doesn't exist",),
     "claim": "register an Intercom account with that subdomain"},
    {"service": "Statuspage", "cname": ("statuspage.io",),
     "markers": ("You are being", "Missing page", "statuspage.io/404"),
     "claim": "create a Statuspage with that subdomain"},
    {"service": "Vercel", "cname": ("cname.vercel-dns.com", "cname.vercel.com"),
     "markers": ("DEPLOYMENT_NOT_FOUND", "The deployment could not be found on Vercel"),
     "claim": "claim the domain in a Vercel project you control"},
    {"service": "Unbounce", "cname": ("unbouncepages.com",),
     "markers": ("The requested URL was not found on this server",),
     "claim": "create an Unbounce page with that URL"},
    {"service": "Instapage", "cname": ("pageserve.co", "secure.pageserve.co"),
     "markers": ("Looks Like You're Lost", "The page you've requested can not be displayed"),
     "claim": "create an Instapage landing page on that domain"},
    {"service": "Surveymonkey", "cname": ("surveymonkey.com",),
     "markers": ("Sorry, the page you were looking for does not exist",),
     "claim": "claim the survey subdomain"},
    {"service": "Wufoo", "cname": ("wufoo.com",),
     "markers": ("Profile not found", "Hmmm....something's not right"),
     "claim": "create a Wufoo account with that name"},
    {"service": "GitBook", "cname": ("gitbook.io",),
     "markers": ("If you need specifics, here's the error",),
     "claim": "create a GitBook space with that subdomain"},
    {"service": "Uptimerobot", "cname": ("stats.uptimerobot.com",),
     "markers": ("page not found",),
     "claim": "create an Uptime Robot status page with that subdomain"},
    {"service": "Feedpress", "cname": ("redirect.feedpress.me",),
     "markers": ("The feed has not been found",),
     "claim": "create a FeedPress feed with that alias"},
]

_CNAME_SUFFIX = re.compile(r"[a-z0-9.-]+\.[a-z]{2,}\.?$", re.I)


def cname_chain(host, timeout=8, runner=None):
    """Return the CNAME chain for `host`, or None if DNS could not be queried.

    None means "unmeasured", not "no CNAME". The caller must treat the two differently —
    reporting "no takeover" because `dig` was missing is exactly the fabricated-DMARC bug
    this codebase already paid for.

    `runner` exists so tests can feed recorded DNS output instead of depending on a
    resolver being installed, which this sandbox does not have.
    """
    run = runner
    if run is None:
        def run(host):
            try:
                p = subprocess.run(["dig", "+short", "CNAME", host],
                                   capture_output=True, text=True, timeout=timeout)
            except FileNotFoundError:
                return None                      # dig not installed
            except subprocess.TimeoutExpired:
                return None
            if p.returncode != 0:
                return None
            return p.stdout

    seen, out, current = set(), [], host
    for _ in range(8):                             # bound the chain; CNAME loops exist
        raw = run(current)
        if raw is None:
            return None if not out else out        # unmeasured, or partial chain
        names = [l.strip().strip(".").lower() for l in raw.splitlines() if l.strip()]
        names = [n for n in names if _CNAME_SUFFIX.match(n)]
        if not names:
            break
        nxt = names[0]
        if nxt in seen:
            break
        seen.add(nxt)
        out.append(nxt)
        current = nxt
    return out


def _service_for(chain):
    """Which takeable service does this CNAME chain delegate to, if any."""
    if not chain:
        return None
    tip = chain[-1].lower().rstrip(".")
    for svc in TAKEABLE:
        for suffix in svc["cname"]:
            if tip == suffix or tip.endswith("." + suffix):
                return svc
    return None


class _Throttle:
    """Space confirmation requests. Thread-safe, and deliberately so.

    This codebase already found the unlocked version of this bug: ten threads all read the
    same `_last`, computed the same wait, slept the same interval, and fired together —
    48 req/s against a 5 req/s ceiling the operator had set. The lock is what makes a
    ceiling a ceiling.

    It matters more here than for the probes, because these requests go to *third parties*
    — GitHub, Heroku, Amazon — not to the target. An unthrottled fan-out across a domain
    with a few thousand subdomains is a volume attack on someone else's infrastructure and
    a fast way to get the operator's egress IP blocked.
    """

    def __init__(self, rps=None):
        if rps is not None:
            try:
                rps = float(rps)
            except (TypeError, ValueError) as e:
                raise ValueError("rps must be a non-negative finite number") from e
            if not math.isfinite(rps) or rps < 0:
                raise ValueError("rps must be a non-negative finite number")
        self.min_interval = (1.0 / rps) if rps else 0
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self):
        if not self.min_interval:
            return
        with self._lock:
            pause = self.min_interval - (time.time() - self._last)
            if pause > 0:
                time.sleep(pause)
            self._last = time.time()


def _fetch(host, timeout, wait=None):
    """GET the scoped host over HTTPS then HTTP, returning (status, body). Never raises.

    Do not follow redirects: an in-scope hostname must not redirect this confirmation probe
    to a different, unchecked host. If HTTPS cannot connect, space the HTTP fallback as a
    second request too; the engagement limit is per request, not per hostname.
    """
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    for attempt, scheme in enumerate(("https", "http")):
        if attempt and wait is not None:
            wait()
        url = f"{scheme}://{host}/"
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with opener.open(req, timeout=timeout) as r:
                return r.status, r.read(20000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read(20000).decode("utf-8", "replace")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            continue
    return None, None


def check_host(host, timeout=8, runner=None, fetch=None, confirm_third_party=False,
               rate_wait=None):
    """Assess one host. Returns a dict, or None when it is not a takeover candidate.

    The real HTTP confirmation contacts the hosting service behind the target's CNAME. It is
    opt-in for live use; injecting `fetch` is an explicit test/offline harness override.
    """
    chain = cname_chain(host, timeout=timeout, runner=runner)
    if chain is None:
        return {"host": host, "verdict": "UNMEASURED",
                "reason": "DNS could not be queried (dig unavailable or timed out), so "
                          "the CNAME chain was never read. This is a coverage gap, not a "
                          "clean result."}
    svc = _service_for(chain)
    if not svc:
        return None                                # not delegated anywhere interesting

    base = {"host": host, "service": svc["service"], "cname": chain,
            "claim_hint": svc["claim"]}
    if fetch is None and not confirm_third_party:
        base.update(
            verdict="CANDIDATE",
            reason="DNS points at a claimable service, but no HTTP request was sent to the "
                   "third-party host. Re-run with --confirm-third-party only if the rules "
                   "of engagement explicitly permit that confirmation.")
        return base
    if fetch is not None:
        status, body = fetch(host, timeout)
    else:
        status, body = _fetch(host, timeout, wait=rate_wait)

    if status is None:
        base.update(verdict="CANDIDATE",
                    reason="the CNAME points at a claimable service but the host did not "
                           "answer, so the dangling state could not be confirmed")
        return base
    text = body or ""
    hit = next((m for m in svc["markers"] if m.lower() in text.lower()), None)
    if hit:
        base.update(verdict="TAKEOVER_LIKELY", marker=hit, status=status,
                    reason=f"{svc['service']} answered with its unclaimed-resource marker "
                           f"({hit!r}) — the resource this CNAME points at does not exist "
                           f"and can be registered by anyone")
    else:
        base.update(verdict="CANDIDATE", status=status,
                    reason="the CNAME points at a claimable service, but the response did "
                           "not contain that service's unclaimed-resource marker — the "
                           "resource may be live, or may use a custom error page. Verify "
                           "by hand before reporting")
    return base


def scan(hosts, timeout=8, runner=None, fetch=None, rps=5,
         confirm_third_party=False):
    """Assess a list of hosts; per-host assessment failures become UNMEASURED results.

    Live HTTP confirmation is disabled unless explicitly opted into. `fetch` remains
    injectable for local tests and controlled harnesses. The default live rate is 5
    requests/second; invalid negative or non-finite rates raise ValueError.
    """
    throttle = _Throttle(rps)
    results, unmeasured = [], []
    for h in hosts:
        throttle.wait()
        try:
            r = check_host(h, timeout=timeout, runner=runner, fetch=fetch,
                           confirm_third_party=confirm_third_party,
                           rate_wait=throttle.wait)
        except Exception as e:                     # one bad host must not end the scan
            unmeasured.append({"host": h, "verdict": "UNMEASURED",
                               "reason": f"assessment failed: {e}"})
            continue
        if r is None:
            continue
        if r["verdict"] == "UNMEASURED":
            unmeasured.append(r)
        else:
            results.append(r)
    order = {"TAKEOVER_LIKELY": 0, "CANDIDATE": 1}
    results.sort(key=lambda r: order.get(r["verdict"], 9))
    return {"results": results, "unmeasured": unmeasured, "hosts_checked": len(hosts),
            "summary_lines": render_lines(results, unmeasured, len(hosts))}


def render_lines(results, unmeasured, checked):
    likely = [r for r in results if r["verdict"] == "TAKEOVER_LIKELY"]
    cand = [r for r in results if r["verdict"] == "CANDIDATE"]
    if unmeasured and not results:
        lines = [f"subdomain takeover — SOURCE UNAVAILABLE, NOT ENUMERATED "
                 f"({len(unmeasured)}/{checked} hosts)"]
        lines.append(f"  {unmeasured[0].get('reason', 'DNS unavailable')}")
        lines.append("  This is a COVERAGE GAP. Do not read 'no takeover' as a result.")
        return lines
    lines = [f"subdomain takeover — {len(likely)} claimable, {len(cand)} candidate(s), "
             f"{len(unmeasured)} unmeasured, of {checked} host(s)"]
    for r in likely:
        lines.append(f"  [TAKEOVER LIKELY] {r['host']} -> {r['cname'][-1]} "
                     f"({r['service']})")
        lines.append(f"      {r['reason']}")
        lines.append(f"      TO CLAIM: {r['claim_hint']}")
        lines.append("      IMPACT: attacker serves content from inside the target's own "
                     "namespace — cookie theft where the scope is a parent domain, "
                     "credential phishing under a trusted name, and CSP/SRI bypass for "
                     "any page that references it.")
    for r in cand:
        lines.append(f"  [CANDIDATE] {r['host']} -> {r['cname'][-1]} ({r['service']})")
        lines.append(f"      {r['reason']}")
    for r in unmeasured:
        lines.append(f"  [UNMEASURED] {r['host']} — {r['reason']}")
    return lines
