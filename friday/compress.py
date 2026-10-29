"""Loss-aware context compression.

Compression here is extractive and conservative: it keeps, verbatim,
the lines that carry hard content — numbers, constraints, names,
quoted text — and drops the rest. It never paraphrases, because
paraphrase is where critical details silently change.

Two things compression must never do, and this module does not do:
- drop a number, a limit, a deadline or a name (they are kept by rule);
- present the summary as a substitute for the source: every summary
  carries its source links, and the router keeps the full text local
  so escalation can still send the relevant original fragments.

A kept line must also not be sensitive (Grok audit): the old keep
rules dropped "submitter: Georgii Makarov" (no digit, no keyword)
while keeping any digit-bearing line, including a secret-bearing one.
Sensitive lines are dropped even when they match a keep rule — the
router and the agent filter before compressing, and compress itself
is the second lock, not the first.

fidelity_check() is the acceptance battery for a compression scheme:
run a decision function on the full context and on the compressed
context over the same cases, and report the agreement rate. A scheme
ships only with a measured agreement rate, not with a promise.
"""

import re

from friday.memory import SHAREABLE, classify_fragment

__all__ = ["compress", "fidelity_check"]

_KEEP_PATTERNS = [
    re.compile(r"\d"),  # any number: amounts, limits, dates, versions
    re.compile(r"(?i)\b(must|never|only|limit|budget|deadline|required|forbidden)\b"),
    re.compile(r'"[^"]+"'),  # quoted text is kept verbatim
    re.compile(r"https?://\S+"),  # links are kept verbatim
    re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_ ]{0,40}:\s*\S"),  # labeled field
    re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b"),  # a person's name
]


def _keep(line):
    if classify_fragment(line) != SHAREABLE:
        return False
    return any(pattern.search(line) for pattern in _KEEP_PATTERNS)


def compress(text, sources=()):
    """Extractive summary: kept lines verbatim + source links.

    Returns a string. Empty input returns an empty string.
    """
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    kept = [ln for ln in lines if _keep(ln)]
    out = list(kept)
    for src in sources:
        out.append("source: " + src)
    return "\n".join(out)


def fidelity_check(decide, cases, compress_fn=compress):
    """Agreement rate between decisions on full vs compressed context.

    decide(context, case) -> hashable decision. cases is an iterable of
    (context, case) pairs. Returns (agreement_rate, disagreements), where
    disagreements is a list of case indices that decided differently.
    """
    cases = list(cases)
    if not cases:
        return 1.0, []
    disagreements = []
    for idx, (context, case) in enumerate(cases):
        full = decide(context, case)
        short = decide(compress_fn(context), case)
        if full != short:
            disagreements.append(idx)
    rate = 1.0 - len(disagreements) / len(cases)
    return rate, disagreements
