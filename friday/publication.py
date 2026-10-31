"""Epoch publication: one signed, public record per journal per day.

Part 1: record format, canonical serialisation, domain-separated
signature, epoch root, and verification. No TSA client here (that
is a later step, after the NUCA root fingerprint check and the legal
question) and no anchors-repository writes (the repository is
created and protected by the operator; until then nothing is
pushed there).

Record shape (see the root-publication note):

- Public record — the only thing published: journal_id (random UUID,
  never a client name), epoch (UTC day, "YYYY-MM-DD"), root (epoch
  Merkle root, DIC duplication convention, over the epoch's batch
  roots), prev_epoch_root (previous epoch's root for the same
  journal, None for genesis), key_id, public_key (Ed25519 hex),
  format_version, epoch_stamp_digest (SHA-256 of the epoch stamp's
  DER bytes, None when no stamp yet), signature, epoch_stamp
  (base64 DER, None when no stamp yet).
- Client signed copy — the public record's fields PLUS leaf_count
  (sum of batch leaf counts), batch_count, the batches list
  (batch_id, root, leaf_count, stamp, status), and client_signature.
  leaf_count and batch_count are NEVER published, and — this is the
  correction to the note's earlier wording — they are NOT confirmed
  by the public signature either: the epoch root does not bind the
  counts, and under the DIC duplication convention [a,b,c] and
  [a,b,c,c] share a root. Volume is confirmed only by the copy's
  OWN signature (domain friday-epoch-client-v1, over the public
  signature + leaf_count + batch_count + the batch list) together
  with recomputation (sum, count, root). A copy whose counts were
  edited and whose sum was recomputed still fails the copy
  signature.
- Batch roots inside one epoch must be unique: build and verifier
  both reject a repeated root, or the [a,b,c,c] forgery would pass
  with batch_count=4 under the same root.
- Key history is fail-closed: a compromised entry without a
  compromise_epoch, or a retired entry without a last_epoch, is
  refused at add time and rejects every epoch at check time.
- Epochs in a chain must strictly increase: two records for one day
  or epochs out of order are rejected, even when linkage is intact.
- Verification never returns a bare True. It returns a structure:
  signature_ok, and a stamp status of "absent" or
  "present_unverified". A present stamp is NOT proven by
  verification in part 1: its bytes are opaque until the TSA client
  checks the token up the chain to the NUCA CA (a later step). A
  date is proven only then.

Signature domain: signed bytes are EPOCH_DOMAIN + canonical JSON of
exactly the signed fields (journal_id, epoch, root,
prev_epoch_root, key_id, public_key, format_version,
epoch_stamp_digest). The domain prefix is what stops a signature
from being replayed across message types: the same key also signs
batch anchors under "friday-anchor-v1", with a different payload
shape, so an epoch signature never verifies as a batch anchor and
vice versa. format_version inside the signed fields stops
downgrade: stripping or lowering it breaks the signature.

Keys: publication records are Ed25519 only. An HMAC signer is
refused at build time — HMAC proves integrity under a shared
secret, not authorship, and a shared secret cannot be verified by
third parties. The pilot private key is never generated or seen
here: the signer is passed in by the caller (the operator creates
the key on their own machine); tests generate ephemeral keys.
"""

import base64
import binascii
import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from friday.dic_merkle import MerkleBatch, canonical_json

__all__ = [
    "PublicationError",
    "KeyHistory",
    "RecordVerification",
    "ChainVerification",
    "EPOCH_DOMAIN",
    "CLIENT_DOMAIN",
    "FORMAT_VERSION",
    "PUBLIC_SIGNED_FIELDS",
    "canonical_record_bytes",
    "canonical_client_bytes",
    "utc_today_epoch",
    "epoch_root",
    "build_epoch_publication",
    "verify_public_record",
    "verify_client_copy",
    "verify_epoch_chain",
]

EPOCH_DOMAIN = b"friday-epoch-v1\x00"
CLIENT_DOMAIN = b"friday-epoch-client-v1\x00"
FORMAT_VERSION = 1

# Exactly the fields the signature covers. Nothing else is signed.
PUBLIC_SIGNED_FIELDS = (
    "journal_id",
    "epoch",
    "root",
    "prev_epoch_root",
    "key_id",
    "public_key",
    "format_version",
    "epoch_stamp_digest",
)

# Full public record: signed fields + signature + stamp (not signed
# themselves — the signature covers the stamp's DIGEST, and it
# cannot cover itself).
PUBLIC_RECORD_FIELDS = PUBLIC_SIGNED_FIELDS + ("signature", "epoch_stamp")

# Full client copy: public record + volume data + the copy's own
# signature (verified by recomputation AND signature, never by
# trusting the counts).
CLIENT_COPY_FIELDS = PUBLIC_RECORD_FIELDS + (
    "leaf_count", "batch_count", "batches", "client_signature")

BATCH_ENTRY_FIELDS = ("batch_id", "root", "leaf_count", "stamp", "status")


@dataclass(frozen=True)
class RecordVerification:
    """Outcome for one record. Never a bare True.

    signature_ok: the Ed25519 signature over the canonical signed
    fields matches (for a client copy, BOTH the public signature
    and the copy signature matched).
    stamp: "absent" when the record carries no epoch stamp,
    "present_unverified" when stamp bytes are present and their
    digest matches — explicitly NOT "verified": no TSA client exists
    yet, so nothing about the stamp's cryptographic validity has
    been checked. A date is proven only when the stamp verifies up
    the chain to the NUCA CA (a later step).
    """

    signature_ok: bool
    stamp: str


@dataclass(frozen=True)
class ChainVerification:
    """Outcome for a chain: linkage + strict epoch order hold, plus
    one RecordVerification per record, in chain order."""

    chain_ok: bool
    records: tuple


class PublicationError(ValueError):
    """A publication record or chain failed verification."""


def canonical_record_bytes(fields):
    """Signed bytes: domain prefix + canonical JSON of the fields.

    canonical_json sorts keys and uses tight separators, so the same
    logical fields always produce the same bytes regardless of dict
    insertion order.
    """
    return EPOCH_DOMAIN + canonical_json(fields).encode("utf-8")


def canonical_client_bytes(fields):
    """Signed bytes for a client copy: its own domain prefix +
    canonical JSON of {public_signature, leaf_count, batch_count,
    batches}. The public signature inside binds the copy to exactly
    one public record; the counts and batch list bind the volume."""
    return CLIENT_DOMAIN + canonical_json(fields).encode("utf-8")


def utc_today_epoch():
    """Today's epoch: the UTC calendar day, "YYYY-MM-DD"."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _validate_epoch(epoch):
    if not isinstance(epoch, str):
        raise ValueError("epoch must be a 'YYYY-MM-DD' string")
    try:
        parsed = datetime.strptime(epoch, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError("epoch must be a valid 'YYYY-MM-DD' date") from exc
    if parsed.strftime("%Y-%m-%d") != epoch:
        raise ValueError("epoch must be zero-padded 'YYYY-MM-DD'")
    return epoch


def _validate_journal_id(journal_id):
    if not isinstance(journal_id, str):
        raise ValueError("journal_id must be a UUID string")
    try:
        parsed = uuid.UUID(journal_id)
    except ValueError as exc:
        raise ValueError("journal_id must be a UUID string") from exc
    if str(parsed) != journal_id:
        raise ValueError("journal_id must be a canonical UUID string")
    return journal_id


def _validate_hex64(value, name):
    if not isinstance(value, str):
        raise PublicationError("%s must be hex" % name)
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise PublicationError("%s must be hex" % name) from exc
    if len(raw) != 32:
        raise PublicationError("%s must be 32 bytes" % name)
    return value


def _validate_root_or_none(value, name):
    if value is None:
        return None
    return _validate_hex64(value, name)


def _signer_key_id(signer):
    kid = getattr(signer, "key_id", None)
    if kid is None:
        raise ValueError("signer has no key_id")
    return kid() if callable(kid) else kid


def _signer_public_key_hex(signer):
    fn = getattr(signer, "public_key_bytes", None)
    if fn is None:
        raise ValueError("signer has no public_key_bytes")
    raw = fn()
    if not raw:
        # HMAC and other secret-based signers have no public key:
        # they prove integrity under a shared secret, not authorship,
        # so they must never sign a publication record.
        raise ValueError(
            "publication records require an Ed25519 signer: HMAC "
            "proves integrity only, not authorship")
    return raw.hex()


def _ed25519_verify(public_key_hex, payload, signature_hex):
    """True when the Ed25519 signature matches, False otherwise."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey)
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        raise RuntimeError(
            "publication verification needs the 'cryptography' "
            "package (pip install -e .[ed25519])") from exc
    try:
        public = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(public_key_hex))
        public.verify(bytes.fromhex(signature_hex), payload)
        return True
    except (ValueError, TypeError, InvalidSignature, binascii.Error):
        return False


def _decode_stamp(stamp, name):
    if stamp is None:
        return None
    if not isinstance(stamp, str) or not stamp:
        raise PublicationError("%s must be non-empty base64 or None"
                               % name)
    try:
        return base64.b64decode(stamp, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PublicationError("%s must be base64" % name) from exc


def epoch_root(batches):
    """Epoch Merkle root over batch roots (DIC duplication convention).

    Single batch: the root IS the batch root. Empty batch list: no
    record — a day without batches publishes nothing. A repeated
    batch root is refused: under duplication [a,b,c] and [a,b,c,c]
    share a root, so a repeated root would let a forged extra batch
    ride under the same root with an inflated batch_count.
    """
    if not batches:
        raise ValueError("no batches: a day without batches publishes "
                         "no epoch record")
    leaves = []
    seen = set()
    for batch in batches:
        root = batch.get("root") if isinstance(batch, dict) else None
        if not isinstance(root, str):
            raise ValueError("each batch needs a hex root")
        try:
            leaf = bytes.fromhex(root)
        except ValueError as exc:
            raise ValueError("each batch root must be hex") from exc
        if len(leaf) != 32:
            raise ValueError("each batch root must be 32 bytes")
        if leaf in seen:
            raise ValueError(
                "duplicate batch root in one epoch: repeated roots "
                "are ambiguous under the DIC duplication convention")
        seen.add(leaf)
        leaves.append(leaf)
    return MerkleBatch(leaves=leaves).close().hex()


def _validate_batch(batch):
    if not isinstance(batch, dict):
        raise ValueError("each batch must be a dict")
    batch_id = batch.get("batch_id")
    if not isinstance(batch_id, str) or not batch_id:
        raise ValueError("each batch needs a non-empty batch_id")
    root = batch.get("root")
    if not isinstance(root, str):
        raise ValueError("each batch needs a hex root")
    try:
        raw = bytes.fromhex(root)
    except ValueError as exc:
        raise ValueError("each batch root must be hex") from exc
    if len(raw) != 32:
        raise ValueError("each batch root must be 32 bytes")
    leaf_count = batch.get("leaf_count")
    if (not isinstance(leaf_count, int) or isinstance(leaf_count, bool)
            or leaf_count < 0):
        raise ValueError("each batch leaf_count must be an int >= 0")
    stamp = batch.get("stamp")
    if stamp is not None and (not isinstance(stamp, str) or not stamp):
        raise ValueError("each batch stamp must be base64 or None")
    return batch_id, root, leaf_count, stamp


def build_epoch_publication(journal_id, epoch, batches, prev_epoch_root,
                            signer, epoch_stamp=None):
    """Build (public_record, client_copy) for one journal epoch.

    batches: [{batch_id, root (hex), leaf_count, stamp (base64 or
    None)}]. A batch without a stamp is marked "stamp_pending" in
    the client copy — never silently omitted, and the copy never
    claims a stamp that does not exist. epoch_stamp is the epoch's
    RFC 3161 token (base64 DER) or None while the TSA client does
    not exist yet; the signature covers its digest, so adding a
    stamp later means re-signing, not editing.
    """
    _validate_journal_id(journal_id)
    _validate_epoch(epoch)
    if prev_epoch_root is not None:
        try:
            _validate_hex64(prev_epoch_root, "prev_epoch_root")
        except PublicationError as exc:
            raise ValueError(str(exc)) from exc
    if not batches:
        raise ValueError("no batches: a day without batches publishes "
                         "no epoch record")
    validated = [_validate_batch(batch) for batch in batches]
    root = epoch_root(batches)
    stamp_bytes = (_decode_stamp(epoch_stamp, "epoch_stamp")
                   if epoch_stamp is not None else None)
    digest = (hashlib.sha256(stamp_bytes).hexdigest()
              if stamp_bytes is not None else None)
    signed_fields = {
        "journal_id": journal_id,
        "epoch": epoch,
        "root": root,
        "prev_epoch_root": prev_epoch_root,
        "key_id": _signer_key_id(signer),
        "public_key": _signer_public_key_hex(signer),
        "format_version": FORMAT_VERSION,
        "epoch_stamp_digest": digest,
    }
    signature = signer.sign(canonical_record_bytes(signed_fields)).hex()
    public_record = dict(signed_fields)
    public_record["signature"] = signature
    public_record["epoch_stamp"] = epoch_stamp
    client_batches = []
    for batch_id, batch_root, leaf_count, stamp in validated:
        client_batches.append({
            "batch_id": batch_id,
            "root": batch_root,
            "leaf_count": leaf_count,
            "stamp": stamp,
            "status": "stamped" if stamp is not None else "stamp_pending",
        })
    client_copy = dict(public_record)
    client_copy["leaf_count"] = sum(
        entry["leaf_count"] for entry in client_batches)
    client_copy["batch_count"] = len(client_batches)
    client_copy["batches"] = client_batches
    # The copy's own signature: without it, the counts are just
    # numbers anyone can rewrite (recomputing the sum is not proof).
    # It covers the public signature (binding the copy to one public
    # record) plus the full volume data, under its own domain.
    client_copy["client_signature"] = signer.sign(
        canonical_client_bytes({
            "public_signature": signature,
            "leaf_count": client_copy["leaf_count"],
            "batch_count": client_copy["batch_count"],
            "batches": client_batches,
        })).hex()
    return public_record, client_copy


class KeyHistory:
    """The independent public-key channel (anchors repo README).

    A record's public_key field alone proves nothing: an attacker
    can generate their own keypair and sign a forged record that
    verifies against their own key. What stops that is this history:
    key_id -> the public key that key_id is supposed to have, with
    status and validity window. The history lives outside any single
    record (in the anchors repo README); the verifier builds it
    from that channel, never from the record being checked.
    """

    STATUSES = ("active", "retired", "compromised")

    def __init__(self):
        self._entries = {}

    def add(self, key_id, public_key, status="active", first_epoch=None,
            last_epoch=None, compromise_epoch=None, successor=None):
        if status not in self.STATUSES:
            raise ValueError("unknown key status %r" % (status,))
        # Fail-closed at construction: a window without its bound is
        # not a window at all — it would accept every epoch.
        if status == "compromised" and compromise_epoch is None:
            raise ValueError(
                "compromised requires compromise_epoch: without it "
                "the key would accept every epoch")
        if status == "retired" and last_epoch is None:
            raise ValueError(
                "retired requires last_epoch: without it the key "
                "would accept every epoch")
        if first_epoch is not None:
            _validate_epoch(first_epoch)
        if last_epoch is not None:
            _validate_epoch(last_epoch)
        if compromise_epoch is not None:
            _validate_epoch(compromise_epoch)
        self._entries[key_id] = {
            "public_key": public_key,
            "status": status,
            "first_epoch": first_epoch,
            "last_epoch": last_epoch,
            "compromise_epoch": compromise_epoch,
            "successor": successor,
        }

    def check(self, record):
        """Raise PublicationError unless the record's key matches."""
        entry = self._entries.get(record.get("key_id"))
        if entry is None:
            raise PublicationError(
                "unknown key_id %r" % (record.get("key_id"),))
        if entry["public_key"] != record.get("public_key"):
            raise PublicationError(
                "public_key mismatch for key_id %r: the key history "
                "says otherwise" % (record.get("key_id"),))
        epoch = record.get("epoch")
        if (entry["first_epoch"] is not None
                and epoch < entry["first_epoch"]):
            raise PublicationError(
                "key_id %r did not exist yet at epoch %s"
                % (record.get("key_id"), epoch))
        if entry["status"] == "compromised":
            # Fail-closed even if an entry somehow lacks its bound
            # (for example, loaded from an incomplete history): a
            # compromised key without a compromise epoch accepts
            # nothing, not everything.
            if entry["compromise_epoch"] is None:
                raise PublicationError(
                    "key_id %r compromised without compromise_epoch: "
                    "all epochs rejected" % (record.get("key_id"),))
            if epoch >= entry["compromise_epoch"]:
                raise PublicationError(
                    "key_id %r compromised at epoch %s; records at "
                    "or after it are rejected"
                    % (record.get("key_id"), entry["compromise_epoch"]))
        if entry["status"] == "retired":
            if entry["last_epoch"] is None:
                raise PublicationError(
                    "key_id %r retired without last_epoch: all epochs "
                    "rejected" % (record.get("key_id"),))
            if epoch > entry["last_epoch"]:
                raise PublicationError(
                    "key_id %r retired after epoch %s"
                    % (record.get("key_id"), entry["last_epoch"]))
        return True


def _signed_fields_of(record):
    if not isinstance(record, dict):
        raise PublicationError("record must be a dict")
    return {name: record[name] for name in PUBLIC_SIGNED_FIELDS
            if name in record}


def verify_public_record(record, key_history):
    """Verify a public record. Returns a RecordVerification, or
    raises PublicationError.

    Checks, in order: exact field set (volume fields smuggled into
    a public record are rejected, not ignored), format version,
    journal/epoch/root shapes, stamp/digest invariant, signature
    over the canonical signed fields, and the key history. The
    returned stamp status is honest, not a proof: "present_unverified"
    means stamp bytes are present and their digest matches, but no
    TSA token has been cryptographically checked — there is no TSA
    client yet. A date is proven only when the stamp verifies up
    the chain to the NUCA CA (a later step).
    """
    if not isinstance(record, dict):
        raise PublicationError("record must be a dict")
    if set(record) != set(PUBLIC_RECORD_FIELDS):
        raise PublicationError(
            "public record fields must be exactly %s, got %s"
            % (sorted(PUBLIC_RECORD_FIELDS), sorted(record)))
    if record["format_version"] != FORMAT_VERSION:
        raise PublicationError(
            "unknown format_version %r" % (record["format_version"],))
    try:
        _validate_journal_id(record["journal_id"])
        _validate_epoch(record["epoch"])
    except ValueError as exc:
        raise PublicationError(str(exc)) from exc
    _validate_hex64(record["root"], "root")
    _validate_root_or_none(record["prev_epoch_root"], "prev_epoch_root")
    stamp = record["epoch_stamp"]
    digest = record["epoch_stamp_digest"]
    if (stamp is None) != (digest is None):
        raise PublicationError(
            "epoch_stamp and epoch_stamp_digest must both be present "
            "or both absent")
    if stamp is not None:
        stamp_bytes = _decode_stamp(stamp, "epoch_stamp")
        if hashlib.sha256(stamp_bytes).hexdigest() != digest:
            raise PublicationError(
                "epoch_stamp_digest does not match epoch_stamp")
    signature = record["signature"]
    if not isinstance(signature, str):
        raise PublicationError("signature must be hex")
    try:
        raw_sig = bytes.fromhex(signature)
    except ValueError as exc:
        raise PublicationError("signature must be hex") from exc
    if len(raw_sig) != 64:
        raise PublicationError("signature must be 64 bytes")
    payload = canonical_record_bytes(_signed_fields_of(record))
    if not _ed25519_verify(record["public_key"], payload, signature):
        raise PublicationError("signature mismatch")
    key_history.check(record)
    return RecordVerification(
        signature_ok=True,
        stamp="absent" if stamp is None else "present_unverified")


def verify_client_copy(copy, key_history):
    """Verify a client signed copy. Returns a RecordVerification, or
    raises PublicationError.

    The embedded public record must verify, batch roots inside one
    epoch must be unique, and the volume data must recompute:
    leaf_count is the sum of batch leaf counts, batch_count is the
    number of batches, and the epoch root is the Merkle root over
    the batch roots. Every batch entry must state its stamp status
    honestly: "stamped" if and only if stamp bytes are present,
    "stamp_pending" otherwise — a stamped claim without bytes is a
    false claim and is rejected. Finally the copy's own signature
    (domain friday-epoch-client-v1, over the public signature +
    counts + batch list, verified with the public record's key)
    must match: recomputation alone is not proof, because anyone
    can rewrite counts and recompute the sum.
    """
    if not isinstance(copy, dict):
        raise PublicationError("client copy must be a dict")
    if set(copy) != set(CLIENT_COPY_FIELDS):
        raise PublicationError(
            "client copy fields must be exactly %s, got %s"
            % (sorted(CLIENT_COPY_FIELDS), sorted(copy)))
    public_part = {name: copy[name] for name in PUBLIC_RECORD_FIELDS}
    public_result = verify_public_record(public_part, key_history)
    batches = copy["batches"]
    if not isinstance(batches, list) or not batches:
        raise PublicationError("client copy batches must be non-empty")
    total = 0
    roots = []
    seen_roots = set()
    for entry in batches:
        if not isinstance(entry, dict) or set(entry) != set(
                BATCH_ENTRY_FIELDS):
            raise PublicationError(
                "batch entries must have exactly %s"
                % (sorted(BATCH_ENTRY_FIELDS),))
        _validate_hex64(entry["root"], "batch root")
        if entry["root"] in seen_roots:
            raise PublicationError(
                "duplicate batch root in one epoch: repeated roots "
                "are ambiguous under the DIC duplication convention")
        seen_roots.add(entry["root"])
        leaf_count = entry["leaf_count"]
        if (not isinstance(leaf_count, int)
                or isinstance(leaf_count, bool) or leaf_count < 0):
            raise PublicationError("batch leaf_count must be an int >= 0")
        if not isinstance(entry["batch_id"], str) or not entry["batch_id"]:
            raise PublicationError("batch_id must be a non-empty string")
        stamp = entry["stamp"]
        status = entry["status"]
        if status == "stamped":
            if stamp is None:
                raise PublicationError(
                    "batch %r claims stamped but carries no stamp "
                    "bytes" % (entry["batch_id"],))
            _decode_stamp(stamp, "batch stamp")
        elif status == "stamp_pending":
            if stamp is not None:
                raise PublicationError(
                    "batch %r claims stamp_pending but carries stamp "
                    "bytes" % (entry["batch_id"],))
        else:
            raise PublicationError(
                "batch %r has unknown status %r"
                % (entry["batch_id"], status))
        total += leaf_count
        roots.append(bytes.fromhex(entry["root"]))
    if copy["leaf_count"] != total:
        raise PublicationError(
            "leaf_count %r != sum of batch leaf counts %r"
            % (copy["leaf_count"], total))
    if copy["batch_count"] != len(batches):
        raise PublicationError(
            "batch_count %r != number of batches %r"
            % (copy["batch_count"], len(batches)))
    recomputed = MerkleBatch(leaves=roots).close().hex()
    if recomputed != copy["root"]:
        raise PublicationError(
            "epoch root mismatch: recomputed %s != published %s"
            % (recomputed, copy["root"]))
    client_payload = canonical_client_bytes({
        "public_signature": copy["signature"],
        "leaf_count": copy["leaf_count"],
        "batch_count": copy["batch_count"],
        "batches": copy["batches"],
    })
    if not _ed25519_verify(copy["public_key"], client_payload,
                            copy["client_signature"]):
        raise PublicationError("client copy signature mismatch")
    return RecordVerification(signature_ok=True,
                              stamp=public_result.stamp)


def verify_epoch_chain(records, key_history, expect_genesis=True):
    """Verify an ordered chain of public records for one journal.
    Returns a ChainVerification, or raises PublicationError.

    Each record must verify, all must share one journal_id, epochs
    must strictly increase (two records for one day or epochs out
    of order are rejected even when linkage is intact), each
    record's prev_epoch_root must equal the previous record's root,
    and (when expect_genesis) the first record must be genesis
    (prev_epoch_root None). A rewritten old epoch breaks the chain:
    its root no longer matches the next record's prev_epoch_root.
    """
    if not isinstance(records, list) or not records:
        raise PublicationError("epoch chain must be a non-empty list")
    journal_id = None
    prev_root = None
    prev_epoch = None
    results = []
    for index, record in enumerate(records):
        results.append(verify_public_record(record, key_history))
        if journal_id is None:
            journal_id = record["journal_id"]
        elif record["journal_id"] != journal_id:
            raise PublicationError(
                "chain mixes journal_ids %r and %r"
                % (journal_id, record["journal_id"]))
        if index == 0:
            if expect_genesis and record["prev_epoch_root"] is not None:
                raise PublicationError(
                    "first record is not genesis: prev_epoch_root "
                    "must be None")
        else:
            if record["prev_epoch_root"] != prev_root:
                raise PublicationError(
                    "chain broken at index %d: prev_epoch_root %r != "
                    "previous root %r"
                    % (index, record["prev_epoch_root"], prev_root))
            if record["epoch"] <= prev_epoch:
                raise PublicationError(
                    "chain broken at index %d: epochs must strictly "
                    "increase, got %s after %s"
                    % (index, record["epoch"], prev_epoch))
        prev_root = record["root"]
        prev_epoch = record["epoch"]
    return ChainVerification(chain_ok=True, records=tuple(results))
