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

__all__ = ["Memory", "SHAREABLE", "SENSITIVE"]

SHAREABLE = "shareable"
SENSITIVE = "sensitive"

_SECRET_PATTERNS = [
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"(?i)\b(password|passwd|api[_-]?key|secret|token|bearer)\b\s*[:=]\s*\S+"),
    re.compile(r"\b[A-Za-z0-9_-]{32,}\b"),  # key-like token
    re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b"),  # card-like
]


def classify_fragment(text):
    """Rule-based stub: 'sensitive' if any secret pattern matches."""
    for pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            return SENSITIVE
    return SHAREABLE


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
        """Token-overlap retrieval over fresh entries, best first."""
        query_tokens = _tokens(query)
        if not query_tokens:
            return []
        now = self._clock()
        scored = []
        for key, entry in self._store.items():
            if now > entry["expiry"]:
                continue
            hay = _tokens(key + " " + str(entry["value"]))
            overlap = len(query_tokens & hay)
            if overlap:
                scored.append((overlap, key, entry["value"]))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [(key, value) for _, key, value in scored[:limit]]

    def export_shareable(self, items):
        """Drop sensitive fragments from a list of (key, value) pairs."""
        return [(k, v) for k, v in items
                if classify_fragment(str(v)) == SHAREABLE]
