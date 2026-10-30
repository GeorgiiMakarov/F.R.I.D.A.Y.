"""Local-first router: reuse, answer locally, or escalate.

Request path, in order:

1. Gate, then reuse: the skill's battery runs first. A failed gate
   blocks reuse and forces escalation — a stale answer from a skill
   that no longer passes must never be served. A fresh entry from
   the SAME skill and version answers the task without any reasoning.
   Journal event: "reuse", naming the true producer.
2. Local skill: the skill runs. If its confidence meets the escalation
   threshold, the answer is local. Journal event: "local_answer".
3. Escalate: anything else — gate failure, low confidence, or no
   skill — returns an Escalation carrying a compressed context of
   SHAREABLE fragments only. Sensitive fragments are redacted, never
   sent up. The task inside the Escalation carries sensitive patterns
   redacted (F-05); the journal keeps the raw task for local audit.
   Journal event: "escalate".

The router never invents a confidence: the skill returns one. A skill
that cannot estimate its confidence must return 0.0, which escalates.

Merge (Step 4): the router owns the plumbing — registry, memory,
journal, gate, escalation-context building, redaction, and the anchor
service. The compliance agent shares that plumbing (registry, memory,
journal, gate object, cache key, context builder, anchor service) but
still drives its own rules and gate decisions: it calls fn(doc) and
gate.decide itself and writes its own journal events. Routing remains
in two places, not one; the agent is not a thin layer over the router.
The cache key is skill + version + content hash (the agent's scheme,
generalized); the old raw-text key is never looked up again, so old
entries orphan and expire by TTL.
"""

import hashlib
import json

from friday.compress import compress
from friday.memory import SHAREABLE, classify_fragment, redact_text

__all__ = ["Escalation", "Router", "cache_key"]


def cache_key(skill, version, content):
    """Single cache-key scheme (merge decision).

    skill + version + SHA-256 of the content: a changed document or a
    changed skill version must not hit an old answer. Content is a
    task string or a JSON-serializable document (canonical encoding).
    The old raw-text key is retired: nothing looks it up anymore.
    """
    if isinstance(content, str):
        blob = content.encode("utf-8")
    else:
        blob = json.dumps(content, sort_keys=True, ensure_ascii=False,
                          default=str).encode("utf-8")
    return "%s:%s:%s" % (skill, version, hashlib.sha256(blob).hexdigest())


class Escalation:
    """What goes up to the large model: compressed, shareable only."""

    def __init__(self, task, compressed_context, reasons, redacted_count):
        self.task = task
        self.compressed_context = compressed_context
        self.reasons = reasons
        self.redacted_count = redacted_count

    def __repr__(self):
        return ("Escalation(task=%r, reasons=%r, redacted=%d)"
                % (self.task, self.reasons, self.redacted_count))


class Router:
    """Routes one task through reuse -> local skill -> escalation."""

    def __init__(self, registry, memory, journal, gate, model=None,
                 anchor_service=None):
        self.registry = registry
        self.memory = memory
        self.journal = journal
        self.gate = gate
        self.model = model  # optional LocalModel, used by model-backed skills
        # Shared with the agent layer (merge): the pair's one anchor
        # service. Router.handle never touches it; finalize paths do.
        self.anchor_service = anchor_service

    @staticmethod
    def build_escalation_context(lines):
        """Single escalation-context builder (merge decision).

        Takes pre-built lines — Router passes fragment values, the
        agent passes document-field lines WITHOUT submitter/notes
        (excluded until Step 3: the rules going up do not need them,
        and the denylist does not catch names) — and returns
        (compressed_shareable, redacted_count). The denylist
        classifier is the single redaction decision point; Step 3
        replaces it with schema redaction in this one place.
        """
        shareable = []
        redacted = 0
        for line in lines:
            if classify_fragment(line) == SHAREABLE:
                shareable.append(line)
            else:
                redacted += 1
        return compress("\n".join(shareable)), redacted

    def handle(self, task, skill_name):
        """Returns (kind, payload): kind in reuse/local/escalate."""
        skill, gate_report = self.registry.get_gated(skill_name)
        if skill is None:
            return self._escalate(task, ["gate_failed"], gate_report)

        # Reuse only for the same skill and version (Grok audit): the
        # old key was the task text alone, so another skill's answer
        # was served as this skill's — and journaled as its own.
        # The key is hashed content now; the skill/version check stays
        # as defense in depth against directly seeded entries.
        key = cache_key(skill.name, skill.version, task)
        cached = self.memory.lookup(key)
        if (cached is not None and cached["skill"] == skill.name
                and cached["version"] == skill.version):
            self.journal.append("reuse", {"task": task, "skill": skill.name})
            return "reuse", cached["value"]

        answer, confidence = skill.run(task)
        route = self.gate.decide(confidence)
        if route == "local":
            self.memory.put(key, answer, skill.name, skill.version,
                            ttl_s=3600)
            self.journal.append("local_answer", {
                "task": task, "skill": skill.name,
                "confidence": confidence, "answer": answer,
            })
            return "local", answer
        return self._escalate(task, ["low_confidence"],
                              {"confidence": confidence,
                               "threshold": self.gate.threshold})

    def _escalate(self, task, reasons, detail):
        fragments = self.memory.find(task)
        # Value-only lines (merge fix): cache keys now contain a
        # 64-char SHA-256, and the classifier reads such a token as a
        # key-like secret — gluing "key: value" redacted every cached
        # fragment and left Router escalation context empty.
        lines = [str(value) for _, value in fragments]
        compressed, redacted = self.build_escalation_context(lines)
        self.journal.append("escalate", {
            "task": task, "reasons": reasons, "detail": detail,
            "redacted": redacted,
        })
        # The Escalation is the upward boundary: its task is redacted.
        # The journal entry above keeps the raw task for local audit.
        return "escalate", Escalation(redact_text(task), compressed,
                                      reasons, redacted)
