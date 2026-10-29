"""Skill back-transfer export (offline step, not a runtime feature).

Candidate journal traces for training pairs (approval pending):

1. Collect: take journal entries with event "local_answer" — each
   carries task, skill and confidence, all of which passed the gate.
   Passing the gate is NOT correctness: a trace is a candidate, not
   an approved pair (F-08).
2. Review: a human (or a review gate) approves the exported pairs.
   This module does NOT approve anything by itself: every exported
   trace carries approval="pending" until that step happens.
3. Export: JSONL, one pair per line: {prompt, answer, skill,
   confidence, source_entry, approval}. Train an adapter on the file
   only after approval, then ship the adapter as a new skill version
   behind the same gate.

The runtime never trains on live traffic. If a trace was escalated or
its gate failed, it is not a candidate trace and is never exported.
"""

import json

__all__ = ["collect_traces", "export_jsonl"]


def collect_traces(entries):
    """Local-answer traces pending review (F-08).

    "Pending" is the point: gate passage is not correctness, so no
    trace leaves here approved. Training on this output without the
    review step would train on unverified answers.
    """
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
            "approval": "pending",
        })
    return traces


def export_jsonl(traces, path):
    """Write traces as JSONL. Returns the number of lines written."""
    with open(path, "w", encoding="utf-8") as handle:
        for trace in traces:
            handle.write(json.dumps(trace, ensure_ascii=False) + "\n")
    return len(traces)
