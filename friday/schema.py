"""Schema redaction (Step 3): an allowlist for what goes up.

Replaces the denylist as the redaction decision point for the
compliance agent path (Router.build_escalation_context already named
this step). Rules:

- Only fields listed in the pack schema reach an escalation context.
  Anything else present in the document is withheld and counted.
- submitter, notes, approver are never sent, and no pack config can
  open them (the never-list vetoes config).
- evidence_ref is allowed by FORMAT, not by sensitivity regex: a UUID
  or a letter-first identifier up to the cap (default 40). A bare
  digit string is indistinguishable from a phone/IIN/INN, so it is
  dropped and counted; packs prefix numeric refs. The cap applies to
  the identifier rule; UUIDs pass by format whatever the cap is. A
  pack may raise the cap only through its config, which is journaled.
  The identifier path has a subtractive second line: a 9+ digit run
  (a phone/IIN/INN shape) or an IBAN-shaped string (two letters, two
  digits, 11-30 alphanumerics) is rejected even when it matches the
  identifier pattern. UUIDs bypass that line too (checked first).
- The old denylist survives as a second line for allowed STRING
  fields only (doc_id, period, config-allowed strings): it can only
  remove, never add. It does not run on evidence_ref (format rules)
  or on int fields (type rules).
- Absence is not redaction: a field that is None (or an evidence_ref
  that is empty) renders as `missing` and is not counted. A present
  value of the wrong type, or a string failing its rule, is omitted
  and counted.
- The composed lines contain only validated values plus fixed
  labels, so they are joined directly: they do NOT pass through
  compress(), whose classifier would drop a UUID evidence_ref line
  (the 32+ key-like token pattern) after the schema just allowed it.
  compress() stays for the Router fragment path only.
"""

import re

from friday.memory import SHAREABLE, classify_fragment

__all__ = ["DEFAULT_SCHEMA", "MISSING", "NEVER_FIELDS", "PackSchema",
           "apply_schema", "evidence_ref_ok"]

MISSING = "missing"
DEFAULT_EVIDENCE_REF_MAX_LEN = 40
NEVER_FIELDS = ("submitter", "notes", "approver")
DEFAULT_VERSION = "default"

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_DIGIT_RUN_RE = re.compile(r"\d{9,}")
_IBAN_LIKE_RE = re.compile(r"[A-Za-z]{2}[0-9]{2}[A-Za-z0-9]{11,30}")


def _id_pattern(max_len):
    return re.compile(r"^[A-Za-z][A-Za-z0-9._/-]{0,%d}$" % (max_len - 1))


def evidence_ref_ok(value, max_len=DEFAULT_EVIDENCE_REF_MAX_LEN):
    """True when value is a UUID or a letter-first id within the cap.

    fullmatch throughout: the old ^...$ match accepted a trailing
    newline ($ matches before it); fullmatch does not. The id path
    then subtracts 9+ digit runs and IBAN-shaped strings; UUIDs bypass
    both (a UUID's last group alone is 12 digits).
    """
    if not isinstance(value, str):
        return False
    if _UUID_RE.fullmatch(value):
        return True
    if not _id_pattern(max_len).fullmatch(value):
        return False
    if _DIGIT_RUN_RE.search(value):
        return False
    if _IBAN_LIKE_RE.fullmatch(value):
        return False
    return True


class PackSchema:
    """A pack's upward allowlist: default fields + config additions."""

    def __init__(self, version=DEFAULT_VERSION, allow=(),
                 evidence_ref_max_len=DEFAULT_EVIDENCE_REF_MAX_LEN):
        self.version = version
        self.allow = tuple(allow)  # list of (field, kind); kind str|int
        self.evidence_ref_max_len = evidence_ref_max_len

    @classmethod
    def from_config(cls, config):
        """Build a schema from a pack config dict; never-fields vetoed."""
        if not isinstance(config, dict):
            raise ValueError("schema config must be a dict")
        allow_in = config.get("allow", [])
        version = config.get("version")
        if allow_in or "evidence_ref_max_len" in config:
            if not version or not isinstance(version, str):
                raise ValueError(
                    "a non-default schema config needs a version string")
        else:
            version = version or DEFAULT_VERSION
        allow = []
        for entry in allow_in:
            if isinstance(entry, str):
                field, kind = entry, "str"
            elif isinstance(entry, dict):
                field, kind = entry.get("field"), entry.get("kind", "str")
            else:
                raise ValueError(
                    "allow entries must be field names or {field, kind} dicts")
            if field in NEVER_FIELDS:
                raise ValueError(
                    "never-field %r cannot be allowed" % (field,))
            if kind not in ("str", "int"):
                raise ValueError(
                    "unknown kind %r for field %r" % (kind, field))
            allow.append((field, kind))
        max_len = config.get("evidence_ref_max_len",
                             DEFAULT_EVIDENCE_REF_MAX_LEN)
        if (not isinstance(max_len, int) or isinstance(max_len, bool)
                or max_len < 1):
            raise ValueError("evidence_ref_max_len must be a positive int")
        schema = cls(version=version, allow=allow,
                     evidence_ref_max_len=max_len)
        schema.pack = config.get("pack")
        return schema

    def journal_record(self):
        """What the schema event records: the widening, not user data."""
        record = {"version": self.version,
                  "allow": [{"field": f, "kind": k} for f, k in self.allow],
                  "evidence_ref_max_len": self.evidence_ref_max_len}
        if getattr(self, "pack", None):
            record["pack"] = self.pack
        return record


DEFAULT_SCHEMA = PackSchema()


def apply_schema(doc, schema):
    """Filter one document through the schema.

    Returns (context, redacted, excluded): context is the joined lines
    for the upward payload, redacted the count of withheld fields,
    excluded the labels of withheld fields. Labels are known schema
    labels (submitter, notes, approver, field paths) plus the fixed
    "unknown_field" label: unknown document keys are NEVER named,
    because the key text itself comes from the document and may be
    user data (a name, a phone number) — naming it would leak it
    into the item and the journal.
    """
    lines, excluded = [], []
    redacted = 0

    def withhold(name):
        nonlocal redacted
        redacted += 1
        excluded.append(name)

    def str_field(name, value):
        if value is None:
            return MISSING
        if not isinstance(value, str):
            withhold(name)
            return None
        if classify_fragment(value) != SHAREABLE:
            withhold(name)
            return None
        return value

    def int_field(name, value):
        if value is None:
            return MISSING
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            withhold(name)
            return None
        return value

    for name in ("doc_id", "period"):
        rendered = str_field(name, doc.get(name))
        if rendered is not None:
            lines.append("%s: %s" % (name, rendered))
    rendered = int_field("total_minor", doc.get("total_minor"))
    if rendered is not None:
        lines.append("total_minor: %s" % (rendered,))

    raw_lines = doc.get("lines")
    if raw_lines is None:
        pass
    elif not isinstance(raw_lines, list):
        withhold("lines")
    else:
        for idx, line in enumerate(raw_lines):
            if not isinstance(line, dict):
                withhold("lines[%d]" % idx)
                continue
            # Unknown line keys are withheld under the fixed label,
            # never named (same leak as unknown top-level keys).
            for sub in line:
                if sub not in ("amount_minor", "evidence_ref") \
                        and line.get(sub) is not None:
                    withhold("unknown_field")
            parts = []
            amount = int_field("lines[%d].amount_minor" % idx,
                               line.get("amount_minor"))
            if amount is not None:
                parts.append("amount_minor=%s" % (amount,))
            ref = line.get("evidence_ref")
            if ref is None or ref == "":
                parts.append("evidence_ref=%s" % (MISSING,))
            elif evidence_ref_ok(ref, schema.evidence_ref_max_len):
                parts.append("evidence_ref=%s" % (ref,))
            else:
                withhold("lines[%d].evidence_ref" % idx)
            if parts:
                lines.append("line %d: %s" % (idx, " ".join(parts)))

    for field, kind in schema.allow:
        if kind == "str":
            rendered = str_field(field, doc.get(field))
        else:
            rendered = int_field(field, doc.get(field))
        if rendered is not None:
            lines.append("%s: %s" % (field, rendered))

    known = {"doc_id", "period", "total_minor", "lines"}
    known |= {field for field, _ in schema.allow}
    for key in doc:
        if key in known or doc.get(key) is None:
            continue
        # Never-fields are known schema labels, safe to name. Unknown
        # keys come from the document itself, so they are never named:
        # a fixed label, not the key text.
        withhold(key if key in NEVER_FIELDS else "unknown_field")
    return "\n".join(lines), redacted, excluded
