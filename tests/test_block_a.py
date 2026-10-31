"""Block A tests: A1 egress gate, A3 finish_reason, A4 terminal error
event, A5 empty fidelity, A6 confidence source (incl. old 2-tuple
models as "unattributed").

Run from the friday/ staging root:
    python3 -m unittest tests.test_block_a -v
"""

import http.server
import json
import math
import threading
import unittest

from examples.compliance_agent.agent import ComplianceAgent
from examples.compliance_agent.samples import DOC_SENSITIVE
from friday import Journal
from friday.compress import fidelity_check
from friday.local_model import (
    OpenAICompatibleLocalModel,
    StubLocalModel,
)


class _CannedModel(OpenAICompatibleLocalModel):
    """Adapter with a canned server payload, no network."""

    def __init__(self, payload):
        super().__init__("http://127.0.0.1:9/v1", "canned")
        self._payload = payload

    def _post(self, body):
        return self._payload


def _choice(content="judged", finish="stop", **extra):
    choice = {"message": {"content": content}, "finish_reason": finish}
    choice.update(extra)
    return {"choices": [choice]}


class TestA1(unittest.TestCase):
    def test_loopback_accepted(self):
        for url in ("http://localhost:11434/v1",
                    "http://127.0.0.1:11434/v1",
                    "http://[::1]:11434/v1",
                    "https://localhost/v1"):
            OpenAICompatibleLocalModel(url, "m")  # must not raise

    def test_remote_rejected_by_default(self):
        for url in ("http://evil.com/v1",
                    "http://127.0.0.1.evil.com/v1",
                    "http://127.0.0.1@evil.com/v1",
                    "http://0.0.0.0:11434/v1",
                    "http://[::]:11434/v1",
                    "ftp://localhost/v1"):
            with self.assertRaises(ValueError, msg=url):
                OpenAICompatibleLocalModel(url, "m")

    def test_allowlist_exact_match(self):
        # Enabled + listed -> accepted.
        OpenAICompatibleLocalModel("http://evil.com/v1", "m",
                                   allow_remote=True,
                                   allowed_hosts=["evil.com"])
        # Enabled but not listed -> rejected.
        with self.assertRaises(ValueError):
            OpenAICompatibleLocalModel("http://evil.com/v1", "m",
                                       allow_remote=True,
                                       allowed_hosts=["other.com"])
        # Enabled but no list -> rejected.
        with self.assertRaises(ValueError):
            OpenAICompatibleLocalModel("http://evil.com/v1", "m",
                                       allow_remote=True)
        # Listed but not enabled -> rejected.
        with self.assertRaises(ValueError):
            OpenAICompatibleLocalModel("http://evil.com/v1", "m",
                                       allowed_hosts=["evil.com"])
        # Substring trap: listed "evil.com" must not admit a subdomain.
        with self.assertRaises(ValueError):
            OpenAICompatibleLocalModel("http://evil.com.evil2.com/v1",
                                       "m", allow_remote=True,
                                       allowed_hosts=["evil.com"])
        # Unspecified is rejected even when listed.
        with self.assertRaises(ValueError):
            OpenAICompatibleLocalModel("http://0.0.0.0:11434/v1", "m",
                                       allow_remote=True,
                                       allowed_hosts=["0.0.0.0"])


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.send_response(302)
        self.send_header("Location", "/target")
        self.end_headers()


class TestA1Redirect(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), _RedirectHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_redirect_not_followed(self):
        model = OpenAICompatibleLocalModel(
            "http://127.0.0.1:%d/v1" % self.port, "m")
        with self.assertRaises(ValueError):
            model.generate("hello", budget=8)


class TestA3(unittest.TestCase):
    def test_stop_accepted(self):
        model = _CannedModel(_choice())
        text, _conf, _source = model.generate("q", budget=8)
        self.assertEqual(text, "judged")

    def test_length_rejected(self):
        model = _CannedModel(_choice(finish="length"))
        with self.assertRaises(ValueError):
            model.generate("q", budget=8)

    def test_missing_finish_reason_rejected(self):
        payload = {"choices": [{"message": {"content": "judged"}}]}
        model = _CannedModel(payload)
        with self.assertRaises(ValueError):
            model.generate("q", budget=8)

    def test_none_content_rejected(self):
        model = _CannedModel(_choice(content=None))
        with self.assertRaises(ValueError):
            model.generate("q", budget=8)


class TestA5(unittest.TestCase):
    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            fidelity_check(lambda ctx, case: True, [])

    def test_nonempty_unchanged(self):
        decide = lambda ctx, case: len(ctx) > 0
        rate, bad = fidelity_check(decide, [("case 1", 1), ("case 2", 2)])
        self.assertEqual((rate, bad), (1.0, []))
        rate, bad = fidelity_check(decide, [("case 1", 1),
                                            ("hello world, no digits", 2)])
        self.assertEqual(rate, 0.5)
        self.assertEqual(bad, [1])


class TestA6(unittest.TestCase):
    def test_sources(self):
        model = _CannedModel({"choices": [{"message": {"content": "a"},
                                           "finish_reason": "stop"}],
                              "confidence": 0.7})
        _t, conf, source = model.generate("q", budget=8)
        self.assertEqual((conf, source), (0.7, "explicit"))
        model = _CannedModel({"choices": [{
            "message": {"content": "a"}, "finish_reason": "stop",
            "logprobs": {"content": [{"logprob": -0.1},
                                     {"logprob": -0.3}]}}]})
        _t, conf, source = model.generate("q", budget=8)
        self.assertEqual(source, "logprobs")
        self.assertAlmostEqual(conf, math.exp(-0.2), places=6)
        model = _CannedModel(_choice())
        _t, conf, source = model.generate("q", budget=8)
        self.assertEqual((conf, source), (0.0, "none"))
        model = _CannedModel({"choices": [{"message": {"content": "a"},
                                           "finish_reason": "stop"}],
                              "confidence": 5.0})
        _t, conf, source = model.generate("q", budget=8)
        self.assertEqual((conf, source), (0.0, "none"))

    def test_stub_source(self):
        stub = StubLocalModel({"q": ("ans", 0.9)})
        self.assertEqual(stub.generate("q", budget=8),
                         ("ans", 0.9, "stub"))

    def test_old_two_tuple_model_unattributed(self):
        class OldModel:
            def generate(self, prompt, budget=512):
                return "Ask for a corrected document.", 0.85

        agent = ComplianceAgent(local_model=OldModel())
        report = agent.review(DOC_SENSITIVE)
        review = report["escalated"][0]["model_review"]
        self.assertEqual(review["source"], "unattributed")
        events = [e for e in agent.journal.entries()
                  if e["event"] == "model_review"]
        self.assertEqual(events[0]["payload"]["source"], "unattributed")

    def test_new_three_tuple_model_source_recorded(self):
        stub = StubLocalModel({"line amount missing":
                               ("Ask for a corrected document.", 0.85)})
        agent = ComplianceAgent(local_model=stub)
        report = agent.review(DOC_SENSITIVE)
        review = report["escalated"][0]["model_review"]
        self.assertEqual(review["source"], "stub")



class _RaisingModel:
    def generate(self, prompt, budget=512):
        raise RuntimeError("model exploded")


class _FaultyJournal(Journal):
    """Journal that fails to write error events."""

    def append(self, event_type, payload, idempotency_key=None,
               runtime_context=None, occurred_at=None):
        if event_type == "error":
            raise RuntimeError("journal broken")
        return super().append(event_type, payload, idempotency_key,
                              runtime_context, occurred_at)


def _terminals(agent, start):
    return [e["event"] for e in agent.journal.entries()[start:]
            if e["event"] in ("verdict", "reuse", "error")]


class TestA4(unittest.TestCase):
    def test_normal_review_one_verdict(self):
        agent = ComplianceAgent()
        start = len(agent.journal)
        agent.review(DOC_SENSITIVE)
        self.assertEqual(_terminals(agent, start), ["verdict"])

    def test_raising_model_one_error_and_reraise(self):
        agent = ComplianceAgent(local_model=_RaisingModel())
        start = len(agent.journal)
        with self.assertRaises(RuntimeError):
            agent.review(DOC_SENSITIVE)
        self.assertEqual(_terminals(agent, start), ["error"])
        err = [e for e in agent.journal.entries()[start:]
               if e["event"] == "error"][0]
        self.assertEqual(err["payload"]["doc_id"], "DOC-003")
        self.assertEqual(err["payload"]["error"], "RuntimeError")

    def test_reuse_is_terminal(self):
        agent = ComplianceAgent()
        agent.review(DOC_SENSITIVE)
        start = len(agent.journal)
        agent.review(DOC_SENSITIVE)
        self.assertEqual(_terminals(agent, start), ["reuse"])

    def test_journal_failure_does_not_mask_original(self):
        agent = ComplianceAgent(local_model=_RaisingModel(),
                                journal=_FaultyJournal())
        with self.assertRaises(RuntimeError) as ctx:
            agent.review(DOC_SENSITIVE)
        self.assertEqual(str(ctx.exception), "model exploded")


if __name__ == "__main__":
    unittest.main()
