"""
Scope enforcement. The hard safety boundary.

Every network-bound ptx command resolves its target against this before sending anything.
On violation: raise ScopeViolation, log the attempt, exit 3.

This is code, not a prompt instruction. A prompt can be talked out of a rule; this cannot.
"""
import ipaddress, json, os, re, time


class ScopeViolation(Exception):
    pass


# A scope pattern is a host, a wildcard host, a CIDR, or a bare IP. Anything else —
# a stray comment, a bracket, a path — cannot match any host, and a pattern that cannot
# match is an exclusion that does not exclude.
_PATTERN_OK = re.compile(
    r"^(?:\*\.|\*{1,2}\.)?"                       # optional leading wildcard
    r"[A-Za-z0-9_.*\-]+"                            # host labels / wildcard / digits
    r"(?:/[0-9]{1,2})?"                              # optional CIDR prefix
    r"(?::[0-9]{1,5})?$"                             # optional port
)


def strip_comment(value):
    """Remove a trailing `# comment` from a scalar, respecting quotes.

    This is a safety-boundary parser, so an unhandled syntax is not a cosmetic issue.
    `exclusions:\n  - 10.9.0.0/16  # production DB` used to parse as the literal string
    "10.9.0.0/16  # production DB", which matches no host — so the tool went ahead and
    attacked the production range the operator had just excluded, and printed a confident
    "in scope" reason while doing it. Writing a comment on the line where you exclude
    something is the most natural thing in the world to do.
    """
    out, quote = [], None
    for i, ch in enumerate(value):
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            continue
        if ch == "#" and (i == 0 or value[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).strip()


def _split_flow_list(val):
    """`[a, b, c]` -> ["a", "b", "c"]. An unparsed flow list was stored verbatim, so
    `exclusions: [10.9.0.0/16]` excluded nothing."""
    inner = val.strip()[1:-1]
    if not inner.strip():
        return []
    return [part.strip().strip("'\"") for part in inner.split(",") if part.strip()]


def _parse_simple_yaml(text):
    """Minimal YAML subset parser — avoids a hard dependency on PyYAML.
    Handles: key: value, key: [a, b], and "- item" lists under a key, with inline
    comments stripped and single/double quotes removed."""
    data, cur_list = {}, None
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        if re.match(r"^\s*-\s+", raw):
            if cur_list is not None:
                item = strip_comment(raw.split("-", 1)[1]).strip("'\"").strip()
                if item:
                    data[cur_list].append(item)
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$", raw)
        if not m:
            continue
        key, val = m.group(1), strip_comment(m.group(2).strip())
        if val == "":
            data[key] = []
            cur_list = key
        elif val.startswith("[") and val.endswith("]"):
            data[key] = _split_flow_list(val)
            cur_list = None
        else:
            data[key] = val.strip("'\"")
            cur_list = None
    return data


def _matches(pattern, h):
    """Does one scope pattern match one host?

    Shared by the inclusion list and the exclusion list. It used to be inlined twice with
    different capabilities: inclusions understood wildcards, subdomains, CIDRs and bare
    IPs, while exclusions understood only exact hosts and subdomains. So `exclusions:
    10.0.0.0/8` matched nothing and `exclusions: *.prod.acme.com` matched nothing, and both
    hosts were ALLOWED because an in-scope CIDR or wildcard covered them.

    That is the guard failing open — the user excludes their production range and the tool
    attacks it. One function used by both sides makes the two lists incapable of drifting
    again, which is the only real fix; a second implementation will diverge.
    """
    pattern = pattern.lower().strip().strip(".")
    if not pattern:
        return False
    if pattern.startswith("*."):                       # wildcard suffix
        return h.endswith(pattern[1:]) or h == pattern[2:]
    if h == pattern:
        return True
    if h.endswith("." + pattern):                      # subdomain
        return True
    # CIDR or bare IP. Only attempted when the pattern looks like a network, so a domain
    # never reaches ipaddress and raises.
    if "/" in pattern or re.match(r"^[0-9a-f:.]+$", pattern):
        try:
            if "/" in pattern:
                return ipaddress.ip_address(h) in ipaddress.ip_network(pattern, strict=False)
            return ipaddress.ip_address(h) == ipaddress.ip_address(pattern)
        except ValueError:
            return False
    return False


class Scope:
    def __init__(self, path):
        self.path = path
        with open(path) as f:
            self.data = _parse_simple_yaml(f.read())
        self.engagement = os.path.dirname(os.path.abspath(path))
        self.in_scope = [h.lower().strip() for h in (self.data.get("in_scope") or [])
                         if h and h.strip()]
        self.exclusions = [h.lower().strip() for h in (self.data.get("exclusions") or [])
                           if h and h.strip()]
        self._reject_unmatchable_patterns()

    def _reject_unmatchable_patterns(self):
        """Refuse to load a scope whose patterns cannot match any host.

        A pattern that can never match is not a harmless typo. In `in_scope` it silently
        narrows the engagement; in `exclusions` it silently *removes a protection*, and
        the tool then attacks the range the operator excluded while printing a confident
        "in scope" reason. Both earlier failures of this guard — CIDRs and wildcards not
        understood, then an inline comment swallowed into the pattern — were exactly this:
        a pattern present in the file, absent from the matcher.

        Failing at load is the only safe direction. An engagement that will not start is
        noticed; an exclusion that quietly does nothing is not.
        """
        bad = [(n, p) for n, plist in (("in_scope", self.in_scope),
                                       ("exclusions", self.exclusions))
               for p in plist if not _PATTERN_OK.match(p)]
        if bad:
            listed = "\n".join(f"    {n}: {p!r}" for n, p in bad)
            raise ScopeViolation(
                "scope.yaml contains patterns that cannot match any host:\n" + listed +
                "\n  A pattern that matches nothing is an exclusion that does not exclude. "
                "Fix the file — common causes are a stray comment, a bracket, a path, or "
                "an unsupported syntax. Nothing was tested.")

    # --- the guard -----------------------------------------------------------
    def is_in_scope(self, host):
        """Returns (allowed: bool, reason: str)."""
        h = host.lower().strip().strip(".")
        h = re.sub(r"^https?://", "", h).split("/")[0].split(":")[0]
        if not h:
            return False, "empty host"

        # Exclusions win over inclusions, always — and now they understand the same
        # pattern language inclusions do (wildcard, subdomain, CIDR, bare IP).
        for ex in self.exclusions:
            if _matches(ex, h):
                return False, f"explicitly excluded: matches {ex}"

        for inc in self.in_scope:
            if _matches(inc, h):
                if "/" in inc:
                    return True, f"inside CIDR {inc}"
                if inc.startswith("*."):
                    return True, f"matches wildcard {inc}"
                if h == inc:
                    return True, f"matches {inc}"
                return True, f"subdomain of {inc}"

        return False, f"{h} matches no in-scope entry"

    def assert_in_scope(self, host):
        ok, reason = self.is_in_scope(host)
        if not ok:
            raise ScopeViolation(reason)
        return reason

    # --- logging -------------------------------------------------------------
    def log_scope_checks(self, allowed, blocked):
        if not blocked:
            return
        p = os.path.join(self.engagement, "log.md")
        with open(p, "a") as f:
            for b in blocked:
                f.write(f"\n## [{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] "
                        f"SCOPE BLOCK tier:sentinel\n"
                        f"REQUESTED: {b['host']}\nREASON: {b['reason']}\n"
                        f"ACTION: blocked, nothing sent\n")
        sp = os.path.join(self.engagement, "state.json")
        if os.path.exists(sp):
            with open(sp) as f:
                st = json.load(f)
            st["scope_blocks"] = st.get("scope_blocks", 0) + len(blocked)
            with open(sp, "w") as f:
                json.dump(st, f, indent=2)

    def summary_lines(self):
        d = self.data
        return [
            f"target          : {d.get('target')}",
            f"in scope        : {', '.join(self.in_scope) or 'NONE — nothing is testable'}",
            f"exclusions      : {', '.join(self.exclusions) or 'none listed'}",
            f"authorization   : {d.get('authorization')}",
            f"assessment type : {d.get('assessment_type')}",
            f"destructive     : {d.get('destructive_permitted')}",
            f"rate ceiling    : {d.get('rate_ceiling_rps')} req/s",
        ]

    def as_dict(self):
        return {"path": self.path, "in_scope": self.in_scope,
                "exclusions": self.exclusions, **self.data}


def load_scope(engagement="engagement"):
    p = os.path.join(engagement, "scope.yaml")
    if not os.path.exists(p):
        raise FileNotFoundError(p)
    return Scope(p)
