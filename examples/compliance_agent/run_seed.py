"""Run the regression seed against a real local model server.

Unlike run_with_model.py (the three demo documents), this script
runs a whole seed split (dev or test) and writes a run record:
model, quantization, prompt, temperature, seed version,
per-document outcomes, per model judgment (rule_id, confidence,
source, gate decision, answer length) and the number of discarded
generations.

The run starts with a preflight on the configured server: a fixed
canonical prompt is sent twice — once with logprobs requested, once
without — and finish_reason must be "stop" (enforced by the adapter,
A3). The confidence source of each probe is recorded. If every
probe reports a source that cannot carry a confidence distribution
(none, stub, unattributed — i.e. the server provides no confidence
signal at all), the runner stops with a clear message and writes
NO record: without a confidence source even the distribution the
run exists to check would be invisible (all confidences 0.0).

The test split runs once per seed version: if a test record for
this seed version already exists in the output directory, the
runner refuses. The dev split has no such restriction.

Honest limit: calibration cannot be computed from this seed. The
model judgment is an open prompt with no ground truth — for rules'
unsure cases the truth is undefined (unsure means the rule could
not decide, not a label). This run checks the pipeline: preflight,
truncation (A3), confidence sources, and the confidence
distribution. Calibration needs a closed question with a ground
truth — a separate step, not done here.

Runs only on the operator's hardware (Ollama / llama.cpp server).
Never substitute a cloud model or simulate a run.

Example:
    ollama serve
    ollama pull qwen2.5:3b
    python3 -m examples.compliance_agent.run_seed \
        --base-url http://localhost:11434 --model qwen2.5:3b \
        --split dev --quantization Q4_K_M

base-url may be given with or without a trailing "/v1" — the
adapter strips it (it appends "/v1/chat/completions" itself).
"""

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

from examples.compliance_agent.agent import ComplianceAgent
from friday.local_model import OpenAICompatibleLocalModel

SEED_DIR = Path(__file__).resolve().parent / "corpus"
DEFAULT_OUT_DIR = Path(__file__).resolve().parent / "runs"

# Fixed canonical prompt: the same bytes on every run, so preflight
# results are comparable across servers and versions.
PREFLIGHT_PROMPT = ("Preflight check. Reply with the single word OK "
                    "and nothing else.")

# The agent builds its model prompt from this template (agent.py);
# the record carries the template, not per-document prompts (those
# carry document context). Keep this string in sync with agent.py.
PROMPT_TEMPLATE = ("Compliance finding %s: %s\n"
                   "Shareable context only:\n%s\n"
                   "Give a short judgment: what should the "
                   "reviewer do next?")

# Sources that can carry a calibration signal. Anything else (none,
# stub, unattributed) means the run's confidences would be hollow.
CALIBRATION_SOURCES = ("explicit", "logprobs")


def seed_version(seed_dir=SEED_DIR):
    """Seed version from corpus/VERSION, "unknown" if absent."""
    version_file = Path(seed_dir) / "VERSION"
    try:
        return version_file.read_text(encoding="utf-8").strip() or "unknown"
    except OSError:
        return "unknown"


def load_rows(seed_dir, split):
    rows = []
    with open(Path(seed_dir) / (split + ".jsonl"),
              encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _unpack(result):
    """Adapter result -> (text, confidence, source), A6 rules."""
    if not isinstance(result, (tuple, list)):
        raise ValueError(
            "local model must return a tuple or list, got %s"
            % type(result).__name__)
    if len(result) == 3:
        return tuple(result)
    if len(result) == 2:
        text, confidence = result
        return text, confidence, "unattributed"
    raise ValueError(
        "local model must return (text, confidence) or "
        "(text, confidence, source)")


def preflight(make_adapter):
    """Probe the server with the canonical prompt, twice.

    make_adapter(want_logprobs) builds an adapter. Returns a dict
    with the prompt, per-probe results and "ok": True when at least
    one probe reports a calibration source. A probe that raises
    (finish_reason != stop, no content, transport error) records
    its error type instead of a source.
    """
    probes = []
    for want in (True, False):
        adapter = make_adapter(want)
        try:
            text, confidence, source = _unpack(
                adapter.generate(PREFLIGHT_PROMPT, budget=64))
            probes.append({"want_logprobs": want, "text": text,
                           "confidence": confidence, "source": source})
        except Exception as exc:  # noqa: BLE001 - recorded, not hidden
            entry = {"want_logprobs": want,
                     "error": type(exc).__name__}
            if isinstance(exc, urllib.error.HTTPError):
                entry["code"] = exc.code
            probes.append(entry)
    ok = any(p.get("source") in CALIBRATION_SOURCES for p in probes)
    return {"prompt": PREFLIGHT_PROMPT, "probes": probes, "ok": ok}


def preflight_failure_message(flight):
    """Human-readable preflight failure, or None when ok.

    Two cases are kept apart: a failed request (transport or HTTP
    error — the message names the type and code and hints at
    base-url and the server) versus a received response with no
    usable confidence source.
    """
    if flight["ok"]:
        return None
    errors = [p for p in flight["probes"] if "error" in p]
    if errors:
        detail = []
        for probe in errors:
            if "code" in probe:
                label = "%s %s" % (probe["error"], probe["code"])
            else:
                label = probe["error"]
            if label not in detail:
                detail.append(label)
        return ("PREFLIGHT FAILED: request failed (%s). Check "
                "--base-url (with or without a trailing /v1) and "
                "that the server is running." % ", ".join(detail))
    sources = [p.get("source", "?") for p in flight["probes"]]
    return ("PREFLIGHT FAILED: response received, but every probe "
            "reported no usable confidence source (%s). The server "
            "provides no confidence signal (no logprobs, no explicit "
            "confidence). The run is not recorded: without a "
            "confidence source even the confidence distribution — "
            "the point of the run — would be invisible (all "
            "confidences 0.0)." % ", ".join(sources))


def check_test_once(out_dir, version):
    """Refuse a second test run for the same seed version."""
    test_dir = Path(out_dir) / version / "test"
    prior = sorted(test_dir.glob("*.json")) if test_dir.is_dir() else []
    if prior:
        raise SystemExit(
            "test split already run for seed version %s (%s): "
            "the test split runs once per version, refusing"
            % (version, prior[-1].name))


def _compare(row, report):
    """Seed expectation vs report, same fields as tests/test_seed.py."""
    exp = row["expected"]
    findings = {f["rule_id"]: f["status"] for f in report["findings"]}
    escalated = [e["rule_id"] for e in report["escalated"]
                 if e["reason"] == "low_confidence"]
    r6 = [f for f in report["findings"] if f["rule_id"] == "R6"][0]
    r6_sensitive = "sensitive data present" in r6["detail"]
    details = {
        "verdict": report["verdict"],
        "expected_verdict": exp["verdict"],
        "findings": findings,
        "expected_findings": exp["findings"],
        "escalated": escalated,
        "expected_escalated": exp["escalated"],
        "report_doc_id": report["doc_id"],
        "expected_doc_id": exp["report_doc_id"],
        "r6_sensitive": r6_sensitive,
        "expected_r6_sensitive": exp["r6_sensitive"],
    }
    match = (details["verdict"] == exp["verdict"]
             and findings == exp["findings"]
             and escalated == exp["escalated"]
             and report["doc_id"] == exp["report_doc_id"]
             and r6_sensitive == exp["r6_sensitive"])
    return match, details


def run_seed(adapter, rows, meta):
    """Run rows through fresh agents; return the run record.

    A document whose model call raises is counted as a discarded
    generation (A4 journals the error in the agent's journal) and
    the run continues with the next document.
    """
    results = []
    discarded = 0
    matched = 0
    escalated_decisions = 0
    review_decisions = 0
    for row in rows:
        agent = ComplianceAgent(local_model=adapter)
        try:
            report = agent.review(row["doc"])
        except Exception as exc:  # noqa: BLE001 - counted, not hidden
            discarded += 1
            results.append({"id": row["id"], "discarded": True,
                            "error": type(exc).__name__})
            continue
        match, details = _compare(row, report)
        matched += 1 if match else 0
        escalated_decisions += len(details["escalated"])
        # Per model judgment: the confidence distribution is the
        # point of the run, so the record carries confidence, gate
        # decision and answer length — not just the source.
        reviews = []
        for item in report["escalated"]:
            review = item.get("model_review")
            if review is not None:
                reviews.append({
                    "rule_id": item["rule_id"],
                    "confidence": review["confidence"],
                    "source": review["source"],
                    "gate": review["gate"],
                    "answer_len": len(review["text"]),
                })
        review_decisions += len(reviews)
        results.append({"id": row["id"], "discarded": False,
                        "match": match, "model_reviews": reviews,
                        **details})
    record = dict(meta)
    record["results"] = results
    record["totals"] = {
        "documents": len(rows),
        "matched": matched,
        "mismatched": len(rows) - matched - discarded,
        "discarded_generations": discarded,
        "escalated_decisions": escalated_decisions,
        "model_reviews": review_decisions,
    }
    record["notes"] = [
        "Seed run (pipeline check), not calibration: the seed does "
        "not calibrate the threshold; miss rate from it is not "
        "reported. Calibration is impossible on this seed: the "
        "model judgment is an open prompt with no ground truth, "
        "and for unsure rules the truth is undefined.",
    ]
    return record


def write_record(out_dir, version, split, model, record):
    """Atomic write: temp file + rename, so a crashed run leaves no
    partial record behind (and a partial run does not consume the
    test split's once-per-version slot)."""
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", model)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = Path(out_dir) / version / split
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / ("run-%s-%s.json" % (slug, stamp))
    tmp = directory / (".tmp-" + path.name)
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(record, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    os.replace(tmp, path)
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Regression seed run against a real local model.")
    parser.add_argument("--base-url", default="http://localhost:11434")
    parser.add_argument("--model", default="qwen2.5:3b")
    parser.add_argument("--split", choices=("dev", "test"), default="dev")
    parser.add_argument("--quantization", default="unknown",
                        help="declared by the operator, e.g. Q4_K_M")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    parser.add_argument("--allow-remote", action="store_true")
    parser.add_argument("--allowed-hosts", default="",
                        help="comma-separated, for remote endpoints")
    args = parser.parse_args(argv)

    version = seed_version()
    rows = load_rows(SEED_DIR, args.split)
    allowed = [h.strip() for h in args.allowed_hosts.split(",")
               if h.strip()]

    def make_adapter(want_logprobs):
        return OpenAICompatibleLocalModel(
            args.base_url, args.model, temperature=args.temperature,
            want_logprobs=want_logprobs, allow_remote=args.allow_remote,
            allowed_hosts=allowed)

    try:
        flight = preflight(make_adapter)
    except Exception as exc:  # noqa: BLE001 - preflight must not crash
        print("PREFLIGHT FAILED: could not configure the adapter: "
              "%s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return 2
    message = preflight_failure_message(flight)
    if message is not None:
        print(message, file=sys.stderr)
        return 2

    if args.split == "test":
        check_test_once(args.out_dir, version)

    meta = {
        "tool": "run_seed",
        "kind": "seed-run",
        "date_utc": datetime.now(timezone.utc).isoformat(),
        "seed_version": version,
        "split": args.split,
        "model": args.model,
        "quantization": args.quantization,
        "temperature": args.temperature,
        "base_url": args.base_url,
        "prompt_template": PROMPT_TEMPLATE,
        "prompt_template_sha256": hashlib.sha256(
            PROMPT_TEMPLATE.encode("utf-8")).hexdigest(),
        "preflight": flight,
    }
    record = run_seed(make_adapter(True), rows, meta)
    path = write_record(args.out_dir, version, args.split, args.model,
                        record)
    totals = record["totals"]
    print("seed %s split %s model %s: %d/%d matched, %d discarded, "
          "%d escalated decisions"
          % (version, args.split, args.model, totals["matched"],
             totals["documents"], totals["discarded_generations"],
             totals["escalated_decisions"]))
    print("record: %s" % (path,))
    return 0


if __name__ == "__main__":
    sys.exit(main())
