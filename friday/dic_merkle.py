"""Merkle tree machinery, adapted from decision-intelligence-core.

Provenance: decision-intelligence-core, application/merkle.py (Apache-2.0,
same author). The tree, proof and verification logic below follow DIC
exactly, including its padding convention: an odd level duplicates its
last node (Bitcoin-style). That convention is NOT the same as the
RFC 6962 convention (promote the odd node unchanged) used by the live
Defense-Dossier demo — proofs from the two systems are not
interchangeable, and this module must never verify the other system's
proofs.

What is reused here: canonical_json, the MerkleBatch tree, inclusion
proofs, offline verification, and the batch builder with two close
triggers (N leaves OR T seconds). What is NOT reused: DIC's
decision-leaf formula is kept verbatim as compute_leaf_hash for
compatibility (it hashes decision_id + metric_name + value +
timestamp + evidence refs + idempotency key), but FRIDAY's journal
batches use journal entry hashes as leaves instead — a journal entry
is not a decision metric, and forcing it into that formula would be a
category error.

Standard library only, pure functions where possible — the same reason
DIC keeps this module dependency-free: a bug here silently breaks every
inclusion proof built on it.
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "canonical_json",
    "compute_leaf_hash",
    "ProofStep",
    "MerkleBatch",
    "verify_inclusion_proof",
    "PendingLeaf",
    "MerkleBatchBuilder",
]


def canonical_json(value):
    """Deterministic serialisation: same logical value, same bytes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def compute_leaf_hash(*, decision_id, metric_name, value, timestamp_iso,
                      evidence_refs, idempotency_key):
    """DIC's decision-leaf formula, verbatim. evidence_refs is sorted AND
    deduplicated here, so citing the same evidence twice hashes exactly
    like citing it once."""
    sorted_refs = sorted(set(evidence_refs))
    payload = "|".join([
        decision_id,
        metric_name,
        canonical_json(value),
        timestamp_iso,
        ",".join(sorted_refs),
        idempotency_key,
    ])
    return hashlib.sha256(payload.encode("utf-8")).digest()


def _hash_pair(left, right):
    return hashlib.sha256(left + right).digest()


@dataclass
class ProofStep:
    sibling_hash: bytes
    position: str  # "LEFT" | "RIGHT" — position of the SIBLING


@dataclass
class MerkleBatch:
    """A closed batch. Root is computed once, at close time."""

    leaves: list = field(default_factory=list)
    _levels: list = field(default_factory=list, repr=False)

    def close(self):
        """Build bottom-up. Odd level: duplicate the last node, so every
        level is even until the root. The PADDED levels are stored, so
        proof_for() indexes them directly with no drift risk."""
        if not self.leaves:
            raise ValueError("cannot close an empty batch")
        level = list(self.leaves)
        levels = []
        while len(level) > 1:
            if len(level) % 2 == 1:
                level = level + [level[-1]]
            levels.append(level)
            level = [_hash_pair(level[i], level[i + 1])
                     for i in range(0, len(level), 2)]
        levels.append(level)
        self._levels = levels
        return level[0]

    def proof_for(self, leaf_index):
        """Inclusion proof for leaf_index into the ORIGINAL leaves."""
        if not self._levels:
            raise ValueError("call close() before requesting a proof")
        if not (0 <= leaf_index < len(self.leaves)):
            raise IndexError(leaf_index)
        steps = []
        idx = leaf_index
        for level in self._levels[:-1]:
            is_right = idx % 2 == 1
            sibling_idx = idx - 1 if is_right else idx + 1
            sibling = level[sibling_idx]
            steps.append(ProofStep(
                sibling_hash=sibling,
                position="LEFT" if is_right else "RIGHT"))
            idx //= 2
        return steps


def verify_inclusion_proof(leaf_hash, proof, expected_root):
    """Pure, offline verification: no service access needed, only the
    leaf hash, the proof path and the published root."""
    current = leaf_hash
    for step in proof:
        if step.position == "RIGHT":
            current = _hash_pair(current, step.sibling_hash)
        else:
            current = _hash_pair(step.sibling_hash, current)
    return current == expected_root


@dataclass(frozen=True)
class PendingLeaf:
    leaf_hash: bytes
    event_id: str
    decision_id: str


class MerkleBatchBuilder:
    """Stateful accumulator. Two independent close triggers:
    leaf_count >= max_leaves, or elapsed_seconds >= max_seconds since
    the first leaf. The caller checks should_close(); this class only
    tracks whether a trigger is currently satisfied."""

    def __init__(self, max_leaves, max_seconds):
        self.max_leaves = max_leaves
        self.max_seconds = max_seconds
        self._pending = []
        self._first_leaf_ts = None

    def add_leaf(self, leaf_hash, event_id, decision_id, now_ts):
        if self._first_leaf_ts is None:
            self._first_leaf_ts = now_ts
        self._pending.append(PendingLeaf(
            leaf_hash=leaf_hash, event_id=event_id,
            decision_id=decision_id))

    def should_close(self, now_ts):
        if not self._pending:
            return False
        if len(self._pending) >= self.max_leaves:
            return True
        if (self._first_leaf_ts is not None
                and (now_ts - self._first_leaf_ts) >= self.max_seconds):
            return True
        return False

    def has_pending(self):
        return bool(self._pending)

    def close_and_reset(self):
        pending = self._pending
        batch = MerkleBatch(leaves=[p.leaf_hash for p in pending])
        root = batch.close()
        self._pending = []
        self._first_leaf_ts = None
        return batch, root, pending
