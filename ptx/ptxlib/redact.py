"""LLM-boundary redaction — keep the subject's identity away from a third-party provider.

The pentest agent reasons through a third-party LLM. Everything that crosses that boundary —
the operator's prompts, tool output pasted back into the conversation, the running findings —
can reveal WHO is being tested: the target host inside a URL, an internal IP, a registrant
email, a bearer token, the client's organisation or product name. The provider needs none of
that to help find the bug, and once it has seen it, it cannot un-see it.

This module replaces subject-identifying values with STABLE placeholders — the same value
always maps to the same token, so the model's context stays coherent across a whole
engagement — and keeps the reversible map on the operator's machine. The structure the model
actually reasons over is preserved: a URL keeps its scheme, path and query, so
``https://acme.example/api/v1/users?id=7`` becomes ``https://PTX_HOST_1/api/v1/users?id=7``
and the IDOR is still perfectly legible while the subject is not. ``restore()`` reverses it
locally, so the operator reads a real report and the provider only ever saw PTX_HOST_1.

Redaction here is a BOUNDARY, not a scanner, so it is deliberately greedy: when a string
might be an identifier it is replaced, because a missed identifier is a leak and an
over-eager placeholder costs nothing but a little readability. The operator-supplied
``subjects`` list (org, product, repo, person names) is the reliable core — pattern matching
is best-effort on top of it, and no automatic redactor is a substitute for a human review
before something leaves the machine.
"""

import collections
import json
import os
import re
import urllib.parse

# Placeholder shape: a distinctive prefix that will not occur in ordinary text, a KIND so the
# model still knows what sort of thing it is looking at, and a stable index.
_PREFIX = "PTX"
_KINDS = ("HOST", "IP", "EMAIL", "SECRET", "SUBJECT")
_PLACEHOLDER_RE = re.compile(r"\bPTX_(?:%s)_\d+\b" % "|".join(_KINDS))

# A curated TLD set. Matching "a domain with a known TLD" rather than "anything with a dot"
# keeps filenames (app.py, package.json, README.md) and version strings out of the net while
# still catching real hostnames in prose. Over-redaction is safe; this list errs toward it.
_TLDS = frozenset("""
com net org io co dev app gov edu mil int info biz me ai xyz online site tech cloud sh ly to
in uk de fr jp cn ru br au ca es it nl se no fi dk pl cz at ch be pt ie nz za mx ar cl sg hk
kr tw id th vn my ph pk bd lk np ae sa tr il gr hu ro bg rs hr si sk lt lv ee is lu mt cy local
internal example test corp lan home office
""".split())

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_URL_RE = re.compile(r"https?://[^\s<>\"'`\)\]}]+", re.I)
# A secret is redacted by CONTEXT: a key-ish name followed by a value. This avoids mangling
# ordinary long words while still catching "token: abc...", "password=...", "Authorization: Bearer ...".
_SECRET_CTX_RE = re.compile(
    r"(?i)\b(bearer|authorization|token|api[_\-]?key|apikey|access[_\-]?key|secret[_\-]?key|"
    r"secret|client[_\-]?secret|password|passwd|pwd|session|cookie|private[_\-]?key)\b"
    r"([\s]*[:=][\s]*|[\s]+)"
    r"(['\"]?)([A-Za-z0-9._\-/+=]{8,})\3")
_AWS_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b")
_GH_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")          # GitHub tokens
_IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def _is_ipv4(m):
    return all(0 <= int(g) <= 255 for g in m.groups())


class Redactor:
    """A reversible, stable subject-redactor.

    The map (real value <-> placeholder) lives only in this object and, on disk, only where the
    operator saves it (the local engagement directory). It is never part of the redacted text,
    so it never crosses the LLM boundary.
    """

    def __init__(self, subjects=()):
        self._to_ph = {}                       # real value -> placeholder
        self._to_real = {}                     # placeholder -> real value
        self._counters = collections.Counter()
        for s in subjects:
            s = (s or "").strip()
            if s:
                self._intern(s, "SUBJECT")

    # -- mapping -------------------------------------------------------------
    def _intern(self, value, kind):
        """Return the stable placeholder for `value`, creating one on first sight."""
        if value in self._to_ph:
            return self._to_ph[value]
        self._counters[kind] += 1
        ph = "%s_%s_%d" % (_PREFIX, kind, self._counters[kind])
        self._to_ph[value] = ph
        self._to_real[ph] = value
        return ph

    # -- redaction -----------------------------------------------------------
    def redact(self, text):
        """Return `text` with every subject identifier replaced by a stable placeholder."""
        if not text:
            return text
        # Emails first: the domain inside an email must become part of the email placeholder,
        # not be separately rewritten as a host afterwards.
        text = _EMAIL_RE.sub(lambda m: self._intern(m.group(0), "EMAIL"), text)
        # URLs: replace only the authority, keep scheme/path/query so the structure survives.
        text = _URL_RE.sub(self._redact_url, text)
        # Secrets by context, then the provider-specific shapes.
        text = _SECRET_CTX_RE.sub(self._redact_secret_ctx, text)
        text = _AWS_RE.sub(lambda m: self._intern(m.group(0), "SECRET"), text)
        text = _JWT_RE.sub(lambda m: self._intern(m.group(0), "SECRET"), text)
        text = _GH_RE.sub(lambda m: self._intern(m.group(0), "SECRET"), text)
        # IPs (validated, so a version like 1.2.300 is left alone).
        text = _IPV4_RE.sub(lambda m: self._intern(m.group(0), "IP") if _is_ipv4(m) else m.group(0),
                            text)
        # Standalone hostnames in prose.
        text = self._redact_domains(text)
        # Operator-named subjects, longest first so "Acme Corp" wins over "Acme".
        text = self._redact_subjects(text)
        return text

    def _redact_url(self, m):
        url = m.group(0)
        parts = urllib.parse.urlsplit(url)
        if not parts.netloc:
            return url
        host_ph = self._intern(parts.netloc, "HOST")
        return urllib.parse.urlunsplit(
            (parts.scheme, host_ph, parts.path, parts.query, parts.fragment))

    def _redact_secret_ctx(self, m):
        # Keep the key name and the separator; replace only the value (group 4).
        return m.group(1) + m.group(2) + m.group(3) + self._intern(m.group(4), "SECRET") + m.group(3)

    def _redact_domains(self, text):
        def repl(m):
            tld = m.group(0).rsplit(".", 1)[-1].lower()
            if tld not in _TLDS:
                return m.group(0)
            return self._intern(m.group(0), "HOST")
        # A label sequence ending in an alpha TLD candidate.
        return re.sub(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b",
                      repl, text)

    def _redact_subjects(self, text):
        for value in sorted((v for v in self._to_real.values()
                             if self._to_ph[v].startswith(_PREFIX + "_SUBJECT_")),
                            key=len, reverse=True):
            ph = self._to_ph[value]
            text = re.sub(r"(?i)\b%s\b" % re.escape(value), ph, text)
        return text

    # -- restoration ---------------------------------------------------------
    def restore(self, text):
        """Reverse redact() using the local map. Placeholders with no entry are left as-is."""
        if not text:
            return text
        return _PLACEHOLDER_RE.sub(lambda m: self._to_real.get(m.group(0), m.group(0)), text)

    # -- introspection / persistence ----------------------------------------
    def summary(self):
        """Counts of what was redacted, by kind — never the values themselves."""
        out = collections.Counter()
        for ph in self._to_real:
            out[ph.split("_")[1]] += 1
        return dict(out)

    def to_dict(self):
        return {"map": self._to_real, "counters": dict(self._counters)}

    @classmethod
    def from_dict(cls, d):
        r = cls()
        for ph, value in (d or {}).get("map", {}).items():
            r._to_real[ph] = value
            r._to_ph[value] = ph
        r._counters = collections.Counter((d or {}).get("counters", {}))
        return r

    def save(self, path):
        # The map holds the ORIGINAL values the redactor replaced — including any secrets.
        # Write it owner-only (0600) and atomically, matching identities.py: a world-readable
        # reversal map sitting next to a redacted document undoes the entire redaction.
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.to_dict(), f, indent=2, sort_keys=True)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path, subjects=()):
        try:
            with open(path) as f:
                r = cls.from_dict(json.load(f))
        except (OSError, ValueError):
            r = cls()
        for s in subjects:
            s = (s or "").strip()
            if s:
                r._intern(s, "SUBJECT")
        return r
