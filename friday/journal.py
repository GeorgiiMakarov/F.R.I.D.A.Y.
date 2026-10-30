"""Hash-chained, append-only journal for agent actions (v2, DIC-based).

Entries are FrEvent records (see events.py). Each entry carries its own
SHA-256 over a canonical encoding of (index, previous hash, event type,
payload, idempotency key, event id, runtime_context). Verification
replays the chain: any edited, removed or reordered entry breaks its
own hash and every hash after it.

Two DIC invariants are built into the shape of this class:

- I7, append-only by interface: there is no update() and no delete().
  The only mutation allowed after append is mark_batched(), which
  stamps a batch id — and batch_id is deliberately NOT covered by the
  chain hash, so batching never breaks verification.
- I6, idempotency inside append(): a repeated idempotency_key is a
  no-op returning the existing entry. Check-then-append as two calls
  would be a race; folding the check into append() removes it.

Time: occurred_at is stored but NOT hashed (wall clocks lie and break
deterministic replay). Trusted time comes from a real RFC 3161 TSA
stamp (see anchor.py), not from the entry; the local NullTsa stamp
proves nothing (trust local_untrusted). runtime_context IS hashed, even
though the router never inspects it (Grok audit): the old code left it
out while the docstring named only occurred_at as excluded, so
swapping alice for mallory verified clean.

The journal proves tampering *inside* the log. It does NOT protect
against a full rebuild of the log from scratch: for that, anchor the
head hash or batch roots externally and compare them later.
"""

import copy
import hashlib
import json

from friday.events import FrEvent

__all__ = ["Journal"]

GENESIS_PREV = "0" * 64


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def _entry_hash(index, prev_hash, event):
    return hashlib.sha256(_canonical({
        "index": index,
        "prev_hash": prev_hash,
        "event_type": event.event_type,
        "payload": event.payload,
        "idempotency_key": event.idempotency_key,
        "event_id": event.event_id,
        "runtime_context": event.runtime_context,
    })).hexdigest()


class Journal:
    """Append-only chain of FrEvent records."""

    def __init__(self):
        self._entries = []
        self._by_key = {}

    def __len__(self):
        return len(self._entries)

    def append(self, event_type, payload, idempotency_key=None,
               runtime_context=None, occurred_at=None):
        """Append one record; returns the stored entry dict.

        A repeated idempotency_key returns the existing entry without
        appending (I6). Entries without a key are always appended.
        """
        if idempotency_key is not None and idempotency_key in self._by_key:
            return copy.deepcopy(self._by_key[idempotency_key])
        # Deep-copy: the journal must own its snapshot. A shallow copy
        # would let the caller mutate a stored entry through the
        # original payload, the returned dict, or entries() (F-04).
        payload = copy.deepcopy(payload)
        runtime_context = copy.deepcopy(runtime_context)
        event = FrEvent(event_type, payload,
                        idempotency_key=idempotency_key,
                        occurred_at=occurred_at,
                        runtime_context=runtime_context)
        index = len(self._entries)
        prev = self._entries[-1]["hash"] if self._entries else GENESIS_PREV
        entry = {
            "index": index,
            "prev_hash": prev,
            "event": event.event_type,
            "payload": event.payload,
            "hash": _entry_hash(index, prev, event),
            "event_id": event.event_id,
            "idempotency_key": event.idempotency_key,
            "occurred_at": event.occurred_at,
            "runtime_context": event.runtime_context,
            "batch_id": None,
        }
        self._entries.append(entry)
        if idempotency_key is not None:
            self._by_key[idempotency_key] = entry
        return copy.deepcopy(entry)

    def entries(self):
        """Deep copies of the entries (callers must not mutate the chain)."""
        return [copy.deepcopy(e) for e in self._entries]

    def head(self):
        """Head hash, or None for an empty journal. Anchor this value."""
        if not self._entries:
            return None
        return self._entries[-1]["hash"]

    def unbatched(self):
        """Deep copies of entries not yet folded into a Merkle batch."""
        return [copy.deepcopy(e) for e in self._entries
                if e["batch_id"] is None]

    def mark_batched(self, event_ids, batch_id):
        """Stamp a batch id on entries. Never breaks verification:
        batch_id is not covered by the chain hash."""
        wanted = set(event_ids)
        for entry in self._entries:
            if entry["event_id"] in wanted:
                entry["batch_id"] = batch_id

    def verify(self):
        """Replay the chain. Returns (ok, first_bad_index or None)."""
        return self._verify_list(self._entries)

    def verify_external(self, entries):
        """Verify an exported entry list (same rules as verify())."""
        return self._verify_list(entries)

    @classmethod
    def from_entries(cls, entries, batch_marks=None):
        """Rebuild a journal from stored entries (persistence load path).

        Verifies the chain before installing anything: a broken chain
        raises ValueError instead of silently starting a new one.
        batch_marks is a list of (event_id, batch_id) pairs applied
        after verification (batch_id is not hashed, so marks never
        break it). A mark for an unknown event_id, or a duplicate
        idempotency key, is corruption, not a no-op.
        """
        try:
            ok, bad = cls._verify_list(entries)
        except (KeyError, TypeError, AttributeError) as exc:
            raise ValueError(f"malformed stored entry: {exc}") from exc
        if not ok:
            raise ValueError(f"journal chain broken at index {bad}")
        journal = cls()
        journal._entries = copy.deepcopy(entries)
        for entry in journal._entries:
            key = entry.get("idempotency_key")
            if key is not None:
                if key in journal._by_key:
                    raise ValueError(
                        f"duplicate idempotency key in stored journal: {key!r}")
                journal._by_key[key] = entry
        for event_id, batch_id in (batch_marks or []):
            for entry in journal._entries:
                if entry["event_id"] == event_id:
                    entry["batch_id"] = batch_id
                    break
            else:
                raise ValueError(
                    f"batch mark for unknown event_id {event_id!r}")
        return journal

    @staticmethod
    def _verify_list(entries):
        prev = GENESIS_PREV
        for pos, entry in enumerate(entries):
            if entry["index"] != pos:
                return False, pos
            if entry["prev_hash"] != prev:
                return False, entry["index"]
            event = FrEvent(
                entry["event"], entry["payload"],
                idempotency_key=entry.get("idempotency_key"),
                event_id=entry["event_id"],
                runtime_context=entry.get("runtime_context") or {})
            expect = _entry_hash(entry["index"], prev, event)
            if entry["hash"] != expect:
                return False, entry["index"]
            prev = entry["hash"]
        return True, None
