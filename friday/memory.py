"""Local memory: indexed results, freshness, and fragment classification.

Three rules:

1. Reuse only verified, fresh results. Every stored value carries the
   skill and version that produced it and a time-to-live. Expired or
   unverified entries are invisible to lookup, never silently reused.
2. Lookup is token overlap (a stub for embedding retrieval). The
   interface is deliberately narrow — put/find — so a real retriever
   can replace the stub without touching callers.
3. Classification before anything leaves the device. A fragment is
   "shareable" or "sensitive". The built-in classifier is rule-based
   (emails, secrets, key-like tokens, passwords) and is a STUB: it
   under-detects by design, so the router redacts "sensitive" fragments
   and treats unclassified input conservatively. A production deployment
   replaces classify_fragment() with a local classifier model and
   re-measures it on a labelled set — relevance filtering alone is
   NOT data protection.
"""

import re
import time

__all__ = ["Memory", "SHAREABLE", "SENSITIVE", "redact_text"]

SHAREABLE = "shareable"
SENSITIVE = "sensitive"

_SECRET_PATTERNS = [
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"(?i)\b(password|passwd|api[_-]?key|secret|token|bearer)\b\s*[:=]\s*\S+"),
    re.compile(r"\b[A-Za-z0-9_-]{32,}\b"),  # key-like token
    re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b"),  # card-like
    # Free-form password leaks ("password is hunter2", "password
    # hunter2"): the key=value pattern above misses them. Over-flagging
    # of "password policy" is accepted at an escalation boundary.
    re.compile(r"(?i)\b(password|passwd)\s+(?:is\s+)?\S+"),
]


def classify_fragment(text):
    """Rule-based stub: 'sensitive' if any secret pattern matches."""
    for pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            return SENSITIVE
    return SHAREABLE


def redact_text(text):
    """Replace sensitive-pattern matches with [redacted].

    Uses the engine's own definition of sensitive (the same patterns
    as classify_fragment), so the two can never disagree about a text.
    Used on text that leaves the device (e.g. the task inside an
    Escalation). Free-form secrets matching no pattern remain a
    documented stub limitation, exactly as with classify_fragment().
    """
    out = text
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub("[redacted]", out)
    return out


def _tokens(text):
    return set(re.findall(r"[a-z0-9]+", text.lower()))


class Memory:
    """Key -> (value, skill, version, expiry, sensitivity)."""

    def __init__(self, clock=None):
        self._store = {}
        self._clock = clock or time.time

    def put(self, key, value, skill, version, ttl_s, sensitivity=SHAREABLE):
        self._store[key] = {
            "value": value,
            "skill": skill,
            "version": version,
            "expiry": self._clock() + ttl_s,
            "sensitivity": sensitivity,
        }

    def get(self, key):
        entry = self._store.get(key)
        if entry is None or self._clock() > entry["expiry"]:
            return None
        return entry["value"]

    def find(self, query, limit=5):
        """Token-overlap retrieval over fresh, shareable entries.

        Best first. An explicit SENSITIVE label always wins over the
        text classifier (F-06): sensitive-labelled entries are never
        returned here, so escalation context built from find() cannot
        include them. Direct key access via get() is unaffected.
        """
        query_tokens = _tokens(query)
        if not query_tokens:
            return []
        now = self._clock()
        scored = []
        for key, entry in self._store.items():
            if now > entry["expiry"]:
                continue
            if entry["sensitivity"] != SHAREABLE:
                continue
            hay = _tokens(key + " " + str(entry["value"]))
            overlap = len(query_tokens & hay)
            if overlap:
                scored.append((overlap, key, entry["value"]))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [(key, value) for _, key, value in scored[:limit]]

    def export_shareable(self, items):
        """Drop sensitive fragments from a list of pairs or triples.

        Pairs (key, value) are filtered by the text classifier only.
        Triples (key, value, sensitivity) additionally drop any entry
        whose explicit label is not SHAREABLE.
        """
        out = []
        for item in items:
            if len(item) == 3:
                key, value, sensitivity = item
                if sensitivity != SHAREABLE:
                    continue
            else:
                key, value = item
            if classify_fragment(str(value)) == SHAREABLE:
                out.append((key, value))
        return out
