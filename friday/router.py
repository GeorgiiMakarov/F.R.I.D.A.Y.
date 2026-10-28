"""Local-first router: reuse, answer locally, or escalate.

Request path, in order:

1. Reuse: a fresh, verified memory entry for the task answers it
   without any reasoning. Journal event: "reuse".
2. Local skill: the skill's acceptance gate must pass, then the
   skill runs. If its confidence meets the escalation threshold,
   the answer is local. Journal event: "local_answer".
3. Escalate: anything else — gate failure, low confidence, or no
   skill — returns an Escalation carrying a compressed context of
   SHAREABLE fragments only. Sensitive fragments are redacted, never
   sent up. Journal event: "escalate".

The router never invents a confidence: the skill returns one. A skill
that cannot estimate its confidence must return 0.0, which escalates.
"""

from friday.compress import compress
from friday.memory import SHAREABLE, classify_fragment

__all__ = ["Escalation", "Router"]


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

    def __init__(self, registry, memory, journal, gate, model=None):
        self.registry = registry
        self.memory = memory
        self.journal = journal
        self.gate = gate
        self.model = model  # optional LocalModel, used by model-backed skills

    def handle(self, task, skill_name):
        """Returns (kind, payload): kind in reuse/local/escalate."""
        cached = self.memory.get(task)
        if cached is not None:
            self.journal.append("reuse", {"task": task, "skill": skill_name})
            return "reuse", cached

        skill, gate_report = self.registry.get_gated(skill_name)
        if skill is None:
            return self._escalate(task, ["gate_failed"], gate_report)

        answer, confidence = skill.run(task)
        route = self.gate.decide(confidence)
        if route == "local":
            self.memory.put(task, answer, skill.name, skill.version,
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
        shareable = []
        redacted = 0
        for key, value in fragments:
            text = str(value)
            if classify_fragment(text) == SHAREABLE:
                shareable.append(key + ": " + text)
            else:
                redacted += 1
        compressed = compress("\n".join(shareable))
        self.journal.append("escalate", {
            "task": task, "reasons": reasons, "detail": detail,
            "redacted": redacted,
        })
        return "escalate", Escalation(task, compressed, reasons, redacted)
