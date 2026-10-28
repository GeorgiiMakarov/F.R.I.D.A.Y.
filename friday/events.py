"""Event envelope, adapted from decision-intelligence-core.

DIC's domain/events.py models every event with an event_type literal and
an opaque runtime_context that Core stores but MUST NOT parse or branch
on — that is what keeps Core decoupled from whatever runtime produced
the event. FRIDAY keeps exactly that rule: the router and the journal
never inspect runtime_context. They route on event_type and payload
shape only.

Adaptation: DIC uses pydantic models. FRIDAY uses standard-library
dataclasses instead, because a phone/laptop engine cannot assume a
pydantic install — and the envelope does not need validation machinery,
it needs a stable shape and a canonical encoding for hashing.
"""

import json
import uuid

__all__ = ["FrEvent", "new_event"]


class FrEvent:
    """One journaled fact. occurred_at is asserted wall-clock time: it
    is stored on the entry but NOT covered by the chain hash (wall
    clocks lie and break deterministic replay). Trusted time comes
    from the anchor's TSA stamp, not from the entry. See journal.py."""

    __slots__ = ("event_id", "event_type", "payload", "idempotency_key",
                 "occurred_at", "runtime_context")

    def __init__(self, event_type, payload, idempotency_key=None,
                 occurred_at=None, runtime_context=None, event_id=None):
        self.event_id = event_id or uuid.uuid4().hex
        self.event_type = event_type
        self.payload = payload
        self.idempotency_key = idempotency_key
        self.occurred_at = occurred_at
        # Opaque by contract: never inspected by router or journal.
        self.runtime_context = runtime_context or {}

    def canonical(self):
        """Canonical dict for hashing and export (no wall-clock)."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "payload": self.payload,
            "idempotency_key": self.idempotency_key,
        }

    def to_dict(self):
        data = self.canonical()
        data["occurred_at"] = self.occurred_at
        data["runtime_context"] = self.runtime_context
        return data

    @classmethod
    def from_dict(cls, data):
        return cls(
            event_type=data["event_type"],
            payload=data["payload"],
            idempotency_key=data.get("idempotency_key"),
            occurred_at=data.get("occurred_at"),
            runtime_context=data.get("runtime_context") or {},
            event_id=data["event_id"],
        )

    def to_json(self):
        return json.dumps(self.to_dict(), sort_keys=True,
                          ensure_ascii=False)


def new_event(event_type, payload, **kwargs):
    return FrEvent(event_type, payload, **kwargs)
