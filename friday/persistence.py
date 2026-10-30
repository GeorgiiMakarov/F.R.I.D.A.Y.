"""Durable journal file (format v1, JSON Lines) + pilot-mode wiring.

Step 2 of the post-review plan (Claude's order: text, then journal +
Ed25519): the RAM journal becomes a file a pilot can show after the
process dies. The demo keeps its RAM journal and demo HMAC keys; this
module is opt-in and changes no existing behaviour.

File format (one JSON object per line, UTF-8, "\\n" separated):

    {"format": "friday-journal", "version": 1}          header, line 1
    {"type": "entry", "entry": {...}}                 one journal entry
    {"type": "batch_mark", "event_id": ..., "batch_id": ...}
    {"type": "anchor", "anchor": {...}}                root, signature, key_id

Versioned from day one: a file whose header version is not 1 is
refused, not guessed at. batch_id is deliberately NOT in the chain
hash, and it is NOT rewritten into the entry line either: batching is
appended as separate batch_mark lines, so the file itself stays
append-only (rewriting an entry line would break exactly the property
the journal exists to prove). Anchor lines carry root, signature,
key_id, leaf count and the TSA token; proof rows are NOT persisted —
they are recomputed from the batch's entries (leaf order = entry
order within the batch).

Load is strict: a corrupt line, an unknown record type, a bad header,
or a broken chain raises CorruptJournalError. A broken chain NEVER
degrades to a fresh journal — a silent new chain would let a
tampered log pass as an empty one, so the caller must resolve it out
of band. A failed disk write raises out of append() and leaves RAM
ahead of disk; the file is the durable truth, so the run must be
treated as interrupted, not continued as if the write had landed.

Honest limits, unchanged from the RAM journal: the root's DATE is not
proven. NullTsa tokens carry trust="local_untrusted" — a local stamp
is not an RFC 3161 token. A real TSA client (for a KZ pilot, the
state tsp.pki.gov.kz is the candidate — live-checked 2026-10-30: it
granted an RFC 3161 stamp for a test query) is future work, not
in this module. Likewise, Ed25519 key custody here is pilot-grade
(a PEM file, mode 0600); production needs a key manager or HSM.
"""

import json
import os

from friday.anchor import AnchorRecord
from friday.journal import Journal

__all__ = ["CorruptJournalError", "JournalStore", "PersistentJournal",
           "FORMAT", "FORMAT_VERSION"]

FORMAT = "friday-journal"
FORMAT_VERSION = 1


class CorruptJournalError(ValueError):
    """Stored journal fails header, shape, or chain checks."""


def _dumps(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"))


class JournalStore:
    """Append-only JSONL file for one journal."""

    def __init__(self, path):
        self.path = os.fspath(path)
        if not os.path.exists(self.path) or os.path.getsize(self.path) == 0:
            if not os.path.exists(self.path):
                # Owner-only from birth: the file holds raw tasks and
                # answers (see the Router payloads), so the default
                # umask mode (0644/0660) is not acceptable here.
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT
                             | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(_dumps({"format": FORMAT,
                                     "version": FORMAT_VERSION}) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            else:
                with open(self.path, "w", encoding="utf-8") as fh:
                    fh.write(_dumps({"format": FORMAT,
                                     "version": FORMAT_VERSION}) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
        else:
            with open(self.path, "r", encoding="utf-8") as fh:
                first = fh.readline()
            try:
                header = json.loads(first)
            except json.JSONDecodeError as exc:
                raise CorruptJournalError("journal header is not JSON") from exc
            if header.get("format") != FORMAT:
                raise CorruptJournalError(f"not a {FORMAT} file")
            if header.get("version") != FORMAT_VERSION:
                raise CorruptJournalError(
                    f"unsupported journal format version "
                    f"{header.get('version')!r} (this code reads "
                    f"{FORMAT_VERSION})")
        # The store owns this file and its contents may include raw
        # personal data, so it enforces owner-only mode on every open
        # (new files are created 0600; an existing file is tightened).
        try:
            os.chmod(self.path, 0o600)
        except (OSError, NotImplementedError):
            pass

    def _append_line(self, obj):
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(_dumps(obj) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def append_entry(self, entry):
        self._append_line({"type": "entry", "entry": entry})

    def append_batch_mark(self, event_id, batch_id):
        self._append_line({"type": "batch_mark", "event_id": event_id,
                           "batch_id": batch_id})

    def append_anchor(self, record):
        self._append_line({"type": "anchor", "anchor": record.to_dict()})

    def load(self):
        """Strict load: (Journal, {batch_id: AnchorRecord}).

        See the module docstring: anything corrupt raises, and a
        broken chain never becomes a fresh journal.
        """
        entries, marks, anchors = [], [], {}
        with open(self.path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        if not lines:
            raise CorruptJournalError("journal file is empty (no header)")
        try:
            header = json.loads(lines[0])
        except json.JSONDecodeError as exc:
            raise CorruptJournalError("journal header is not JSON") from exc
        if (header.get("format") != FORMAT
                or header.get("version") != FORMAT_VERSION):
            raise CorruptJournalError("unsupported journal header")
        for lineno, line in enumerate(lines[1:], start=2):
            if not line.strip():
                raise CorruptJournalError(f"blank line {lineno}")
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CorruptJournalError(
                    f"line {lineno} is not JSON") from exc
            kind = obj.get("type") if isinstance(obj, dict) else None
            if kind == "entry":
                entries.append(obj.get("entry"))
            elif kind == "batch_mark":
                marks.append((obj.get("event_id"), obj.get("batch_id")))
            elif kind == "anchor":
                try:
                    record = AnchorRecord.from_dict(obj.get("anchor"))
                except (KeyError, TypeError, ValueError) as exc:
                    raise CorruptJournalError(
                        f"line {lineno}: bad anchor record") from exc
                anchors[record.batch_id] = record
            else:
                raise CorruptJournalError(
                    f"line {lineno}: unknown record type {kind!r}")
        try:
            journal = Journal.from_entries(entries, marks)
        except ValueError as exc:
            raise CorruptJournalError(
                f"stored chain failed verification: {exc}") from exc
        return journal, anchors


class PersistentJournal(Journal):
    """Journal that writes every append and batch mark to a store.

    Append semantics are exactly Journal's: an idempotent replay
    (repeated idempotency_key) returns the existing entry and writes
    no duplicate line. Anchor lines are written by passing
    store.append_anchor as AnchorService's on_anchor callback.
    """

    def __init__(self, store):
        super().__init__()
        self.store = store

    def append(self, *args, **kwargs):
        before = len(self._entries)
        entry = super().append(*args, **kwargs)
        if len(self._entries) > before:
            self.store.append_entry(entry)
        return entry

    def mark_batched(self, event_ids, batch_id):
        super().mark_batched(event_ids, batch_id)
        for event_id in event_ids:
            self.store.append_batch_mark(event_id, batch_id)

    @classmethod
    def open(cls, store):
        """Load an existing store (or start empty) and keep appending
        to it. Returns (journal, anchors); anchors carry root,
        signature and key_id, with proof rows recomputed, not restored.
        """
        journal, anchors = store.load()
        pj = cls(store)
        pj._entries = journal._entries
        pj._by_key = journal._by_key
        return pj, anchors
