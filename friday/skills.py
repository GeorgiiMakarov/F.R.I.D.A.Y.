"""Built-in skills: retrieve, summarise, verify.

Each skill is a manifest: a run function plus its own acceptance
battery. The batteries here are small by design — they pin the exact
behaviour the router depends on. A skill that grows gets a bigger
battery before it ships, not after. Batteries are self-contained:
they never depend on caller state.

Skill back-transfer (reviewed traces -> adapters) is deliberately a
separate, offline step, not a runtime feature: collect journaled
(local_answer) traces, review them, export training pairs, train an
adapter, then ship the adapter as a new skill version behind the same
gate. The runtime never trains itself on live traffic.
"""

from friday.compress import compress
from friday.gates import Skill
from friday.memory import Memory

__all__ = ["builtin_skills"]


def _retrieve_run(memory):
    def run(task):
        hits = memory.find(task)
        if not hits:
            return "no memory hit", 0.0
        text = "; ".join("%s: %s" % (k, v) for k, v in hits[:3])
        return text, 0.9 if len(hits) >= 2 else 0.6
    return run


def _summarise_run():
    def run(task):
        # The task carries the text to compress after a "::" mark.
        text = task.split("::", 1)[1] if "::" in task else task
        return compress(text), 0.85
    return run


def _verify_run(registry):
    def run(task):
        skill, report = registry.get_gated(task)
        if skill is None:
            return "gate failed: %r" % (report["failures"],), 0.0
        return "gate passed: %s v%s" % (skill.name, skill.version), 0.95
    return run


def _scratch_memory():
    mem = Memory()
    mem.put("capital of France", "Paris", "retrieve", "0.1.0", 3600)
    mem.put("capital of Japan", "Tokyo", "retrieve", "0.1.0", 3600)
    return mem


def builtin_skills(memory, registry):
    """Return the three built-in skills bound to this memory/registry."""
    retrieve = Skill(
        "retrieve", "0.1.0", _retrieve_run(memory),
        tests=[
            ("finds a stored fact",
             lambda: bool(_scratch_memory().find("capital of France"))),
            ("empty query finds nothing",
             lambda: _scratch_memory().find("") == []),
        ],
        description="Find fresh gate-passed fragments in local memory.",
    )
    summarise = Skill(
        "summarise", "0.1.0", _summarise_run(),
        tests=[
            ("keeps numbers verbatim",
             lambda: "42" in compress("budget is 42 coins, see notes")),
            ("drops filler",
             lambda: compress("just some chat") == ""),
        ],
        description="Loss-aware extractive compression (see compress).",
    )
    verify = Skill(
        "verify", "0.1.0", _verify_run(registry),
        tests=[
            ("registry answers for a known skill",
             lambda: registry.get_gated("retrieve")[0] is not None),
        ],
        description="Run another skill's acceptance gate and report.",
    )
    return [retrieve, summarise, verify]
