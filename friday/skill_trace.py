"""Skill back-transfer export (offline step, not a runtime feature).

Verified journal traces become training pairs for adapters:

1. Collect: take journal entries with event "local_answer" — each
   carries task, skill and confidence, all of which passed the gate.
2. Review: a human (or a review gate) approves the exported pairs.
   This module does NOT approve anything by itself.
3. Export: JSONL, one pair per line: {prompt, answer, skill,
   confidence, source_entry}. Train an adapter on the file, then ship
   the adapter as a new skill version behind the same gate.

The runtime never trains on live traffic. If a trace was escalated or
its gate failed, it is not a verified trace and is never exported.
"""

import json

__all__ = ["collect_traces", "export_jsonl"]


def collect_traces(entries):
    """Verified local-answer traces from journal entries."""
    traces = []
    for entry in entries:
        if entry.get("event") != "local_answer":
            continue
        payload = entry.get("payload") or {}
        traces.append({
            "prompt": payload.get("task"),
            "answer": payload.get("answer"),
            "skill": payload.get("skill"),
            "confidence": payload.get("confidence"),
            "source_entry": entry.get("event_id"),
        })
    return traces


def export_jsonl(traces, path):
    """Write traces as JSONL. Returns the number of lines written."""
    with open(path, "w", encoding="utf-8") as handle:
        for trace in traces:
            handle.write(json.dumps(trace, ensure_ascii=False) + "\n")
    return len(traces)
