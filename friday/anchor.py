"""Batch anchoring: close journal batches, sign roots, stamp time.

Synchronous mirror of decision-intelligence-core's MerkleAnchorService
(application/merkle_anchor_service.py), minus the server parts:

- close trigger: N leaves OR T seconds (MerkleBatchBuilder, DIC);
- sign root AND leaf count (Signer protocol, DIC interfaces/signer.py):
  the signed payload binds both, so a batch presented with a forged
  leaf count fails verification even when the root collides under the
  DIC duplication convention ([A,B,C] vs [A,B,C,C] share a root);
  signing the root alone would leave that hole open;
- timestamp the root (TimestampAuthority protocol, DIC interfaces/tsa.py);
- project one proof row per leaf into an in-memory proof store
  (DIC projects into ProjectionStore; on-device, a dict is enough);
- mark journal entries batched (DIC appends one MerkleRootPublished
  per decision_id; FRIDAY stamps batch ids on the journal entries
  themselves, because a phone has no separate audit backend).

Signers (two honesty levels, never conflated):

- HmacSigner (stdlib): proves integrity under a shared secret. It is
  NOT non-repudiation: anyone with the secret can forge. Use it for
  local tamper-evidence only.
- Ed25519Signer (needs the `cryptography` package, lazy import):
  real public-key signatures, same API as DIC's Ed25519Signer,
  including key_id rotation generations.

Timestamp authorities:

- NullTsa: a local stamp (sha256 of root + time), authority_id
  "local". It is explicitly NOT an RFC 3161 token and proves nothing
  to a third party. It exists so the pipeline runs offline.
- A real RFC 3161 TSA plugs in where DIC's rfc3161_client lives:
  implement timestamp(digest) -> token and verify(digest, token).
"""

import hashlib
import hmac as hmac_lib
import time
import uuid

from friday.dic_merkle import (MerkleBatchBuilder, verify_inclusion_proof)

__all__ = [
    "HmacSigner",
    "Ed25519Signer",
    "NullTsa",
    "AnchorService",
    "AnchorRecord",
]


def _signed_payload(root, leaf_count):
    """Canonical bytes covered by the anchor signature.

    Binding the leaf count to the root closes the DIC duplication
    collision: a 3-leaf batch [A,B,C] and a forged 4-leaf batch
    [A,B,C,C] share a root, but their signed payloads differ, so the
    forged batch fails signature verification.
    """
    return (b"friday-anchor-v1\x00" + bytes(root) + b"\x00"
            + int(leaf_count).to_bytes(8, "big"))


class HmacSigner:
    """Integrity-only signer (stdlib). NOT non-repudiation."""

    def __init__(self, secret, key_id="local-hmac-v1"):
        self._secret = secret if isinstance(secret, bytes) else secret.encode()
        self._key_id = key_id

    def sign(self, payload):
        return hmac_lib.new(self._secret, payload, hashlib.sha256).digest()

    def verify(self, payload, signature, public_key=None):
        expect = hmac_lib.new(self._secret, payload, hashlib.sha256).digest()
        return hmac_lib.compare_digest(expect, signature)

    def public_key_bytes(self):
        return b""  # no public key exists for a shared secret

    def key_id(self):
        return self._key_id


class Ed25519Signer:
    """Public-key signer, same API as DIC's. Requires `cryptography`."""

    def __init__(self, private_key=None, key_id="friday-ed25519-v1"):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey)
        except ImportError as exc:
            raise RuntimeError(
                "Ed25519Signer needs the 'cryptography' package; "
                "use HmacSigner for stdlib-only deployments") from exc
        self._private_key = private_key or Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self._key_id = key_id

    def sign(self, payload):
        return self._private_key.sign(payload)

    def verify(self, payload, signature, public_key):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey)
            from cryptography.exceptions import InvalidSignature
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature, payload)
            return True
        except InvalidSignature:
            return False

    def public_key_bytes(self):
        from cryptography.hazmat.primitives import serialization
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)

    def key_id(self):
        return self._key_id


class NullTsa:
    """Local-only stamp. NOT an RFC 3161 token. Offline use only.

    Tokens carry trust="local_untrusted" (F-10): no consumer may present
    a local stamp as external proof of time for a third party.
    """

    def __init__(self, authority_id="local"):
        self.authority_id = authority_id

    def timestamp(self, digest):
        import datetime as dt
        stamp = dt.datetime.now(dt.timezone.utc).isoformat()
        token = hashlib.sha256(digest + stamp.encode()).hexdigest()
        return {"token": token, "timestamp_iso": stamp,
                "authority_id": self.authority_id,
                "trust": "local_untrusted"}

    def verify(self, digest, token):
        if token.get("authority_id") != self.authority_id:
            return False
        expect = hashlib.sha256(
            digest + token["timestamp_iso"].encode()).hexdigest()
        return hmac_lib.compare_digest(expect, token["token"])


class AnchorRecord:
    """One closed batch: root, signature, stamp, and proof rows."""

    def __init__(self, batch_id, root, signature, key_id, tsa_token,
                 leaf_count, proofs):
        self.batch_id = batch_id
        self.root = root
        self.signature = signature
        self.key_id = key_id
        self.tsa_token = tsa_token
        self.leaf_count = leaf_count
        self.proofs = proofs  # leaf_hex -> list of ProofStep

    @property
    def root_hex(self):
        return self.root.hex()


class AnchorService:
    """Close journal batches and anchor them (DIC flow, sync, local)."""

    def __init__(self, signer, tsa, max_leaves=100, max_seconds=300.0,
                 clock=None):
        self._builder = MerkleBatchBuilder(max_leaves, max_seconds)
        self._signer = signer
        self._tsa = tsa
        self._clock = clock or time.time
        self.proof_store = {}  # leaf_hex -> proof row dict
        self.anchors = {}  # batch_id -> AnchorRecord
        # Event ids already folded into the builder. anchor_pending()
        # runs on every call, but an unbatched entry must be added
        # exactly once: without this set, repeated non-closing calls
        # duplicate leaves (F-01). Cleared on close (all pending close
        # at once).
        self._added = set()

    def anchor_pending(self, journal, force=False):
        """Fold unbatched journal entries into the builder and close
        when a trigger fires (or when forced). Returns an AnchorRecord
        or None when nothing closed."""
        now = self._clock()
        for entry in journal.unbatched():
            if entry["event_id"] in self._added:
                continue
            self._added.add(entry["event_id"])
            self._builder.add_leaf(
                bytes.fromhex(entry["hash"]), entry["event_id"],
                decision_id=entry["event"], now_ts=now)
        if not self._builder.has_pending():
            return None
        if not force and not self._builder.should_close(now):
            return None
        batch, root, pending = self._builder.close_and_reset()
        self._added.clear()
        batch_id = uuid.uuid4().hex
        signature = self._signer.sign(
            _signed_payload(root, len(pending)))
        tsa_token = self._tsa.timestamp(root)
        proofs = {}
        for idx, leaf in enumerate(pending):
            steps = batch.proof_for(idx)
            proofs[leaf.leaf_hash.hex()] = steps
            self.proof_store[leaf.leaf_hash.hex()] = {
                "leaf_hash": leaf.leaf_hash.hex(),
                "proof_path": [(s.sibling_hash.hex(), s.position)
                               for s in steps],
                "root": root.hex(),
                "anchor_signature": signature.hex(),
                "anchor_timestamp": tsa_token["timestamp_iso"],
                "batch_id": batch_id,
            }
        journal.mark_batched([p.event_id for p in pending], batch_id)
        record = AnchorRecord(batch_id, root, signature,
                              self._signer.key_id(), tsa_token,
                              len(pending), proofs)
        self.anchors[batch_id] = record
        return record

    def verify_anchor_signature(self, record):
        """Check a record's signature over (root, leaf_count).

        Returns False for a record whose leaf count was altered after
        signing, even if the root still matches (the DIC duplication
        collision). For Ed25519 the signer's public key is used; for
        HMAC the shared secret (integrity only, not authorship).
        """
        payload = _signed_payload(record.root, record.leaf_count)
        public_key = self._signer.public_key_bytes() or None
        try:
            return bool(self._signer.verify(
                payload, record.signature, public_key))
        except Exception:
            return False

    def verify_proof(self, leaf_hex, proof, root_hex):
        """Offline inclusion check, no service needed."""
        return verify_inclusion_proof(bytes.fromhex(leaf_hex), proof,
                                      bytes.fromhex(root_hex))
