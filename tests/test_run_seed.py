"""Tests for the seed runner: preflight, once-per-version, run record.

Run from the friday/ staging root:
    python3 -m unittest tests.test_run_seed -v
"""

import http.server
import json
import tempfile
import threading
import unittest
from pathlib import Path

from examples.compliance_agent.run_seed import (
    SEED_DIR,
    check_test_once,
    load_rows,
    preflight,
    run_seed,
    seed_version,
)
from friday.local_model import OpenAICompatibleLocalModel, StubLocalModel


def _start(handler_cls):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def _choice(finish="stop", logprobs=None):
    choice = {"message": {"content": "OK"}, "finish_reason": finish}
    if logprobs is not None:
        choice["logprobs"] = {"content": [{"logprob": v}
                                          for v in logprobs]}
    return choice


class _LogprobsHandler(http.server.BaseHTTPRequestHandler):
    """Returns logprobs only when the request asks for them."""

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        logprobs = [-0.1, -0.2] if body.get("logprobs") else None
        data = json.dumps({"choices": [_choice(logprobs=logprobs)]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class _PlainHandler(http.server.BaseHTTPRequestHandler):
    """Never returns logprobs or an explicit confidence."""

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        data = json.dumps({"choices": [_choice()]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class _LengthHandler(http.server.BaseHTTPRequestHandler):
    """Always truncates: finish_reason length, never stop."""

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        data = json.dumps({"choices": [_choice(finish="length")]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class TestPreflight(unittest.TestCase):
    def _flight(self, handler_cls):
        server, port = _start(handler_cls)
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)

        def make_adapter(want):
            return OpenAICompatibleLocalModel(
                "http://127.0.0.1:%d/v1" % port, "m",
                want_logprobs=want)
        return preflight(make_adapter)

    def test_logprobs_server_passes(self):
        flight = self._flight(_LogprobsHandler)
        self.assertTrue(flight["ok"])
        self.assertEqual(flight["probes"][0]["source"], "logprobs")
        self.assertEqual(flight["probes"][1]["source"], "none")

    def test_plain_server_fails(self):
        flight = self._flight(_PlainHandler)
        self.assertFalse(flight["ok"])
        self.assertEqual([p["source"] for p in flight["probes"]],
                         ["none", "none"])

    def test_truncated_server_fails(self):
        flight = self._flight(_LengthHandler)
        self.assertFalse(flight["ok"])
        self.assertEqual([p["error"] for p in flight["probes"]],
                         ["ValueError", "ValueError"])


class TestOncePerVersion(unittest.TestCase):
    def test_prior_test_record_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            prior = Path(tmp) / "1" / "test"
            prior.mkdir(parents=True)
            (prior / "run-m-20200101T000000Z.json").write_text("{}")
            with self.assertRaises(SystemExit):
                check_test_once(tmp, "1")

    def test_no_prior_record_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            check_test_once(tmp, "1")  # must not raise


class TestRunSeed(unittest.TestCase):
    def test_dev_with_stub_matches_all(self):
        rows = load_rows(SEED_DIR, "dev")
        record = run_seed(StubLocalModel(), rows, {
            "model": "stub", "quantization": "none",
            "temperature": 0.0, "seed_version": seed_version()})
        self.assertEqual(record["totals"]["documents"], 16)
        self.assertEqual(record["totals"]["matched"], 16)
        self.assertEqual(record["totals"]["discarded_generations"], 0)
        self.assertEqual(record["model"], "stub")
        self.assertEqual(record["seed_version"], "1")

    def test_discarded_generation_counted(self):
        class RaisingOnDoc:
            def generate(self, prompt, budget=512):
                if "DEV-007" in prompt:
                    raise RuntimeError("model exploded")
                return "Ask for a corrected document.", 0.85, "stub"

        rows = load_rows(SEED_DIR, "dev")
        record = run_seed(RaisingOnDoc(), rows, {})
        self.assertEqual(record["totals"]["discarded_generations"], 1)
        self.assertEqual(record["totals"]["matched"], 15)
        discarded = [r for r in record["results"] if r["discarded"]]
        self.assertEqual(len(discarded), 1)
        self.assertEqual(discarded[0]["id"], "DEV-007")
        self.assertEqual(discarded[0]["error"], "RuntimeError")


if __name__ == "__main__":
    unittest.main()
