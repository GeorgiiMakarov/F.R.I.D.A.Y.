"""Local model adapter interface.

A local model is anything that implements generate(prompt, budget) and
returns (text, confidence, source). Confidence is the model's own
calibrated estimate that the text is correct; a model that cannot
estimate it must return 0.0 so the router escalates. Source names
where the confidence came from: "explicit" (a confidence field in
the server response), "logprobs" (mean token logprob), "none" (no
signal, confidence 0.0), "stub" (the deterministic test stub).
Consumers accept old two-tuple models too, labelling them
"unattributed" — never crash on them (A6).

Two adapters ship here:

- StubLocalModel: deterministic, for tests and the demo. It never
  pretends to be a real model.
- OpenAICompatibleLocalModel: talks to a local server over HTTP with
  the standard library only (llama.cpp server, Ollama, MLX server, or
  any other OpenAI-compatible endpoint). Confidence comes from, in
  order: an explicit "confidence" field in the response JSON when the
  server provides one; logprobs when the server returns them (mean
  token logprob, exponentiated); otherwise 0.0 (escalate). Servers
  that reject the logprobs parameter get one retry without it.

Serving notes for the 4 GB class (top smartphones and laptops):
- weights: a 4-bit quantised 4B model (~4 GB) leaves room for context
  on devices with 8 GB+ RAM; keep the working budget small (2k tokens
  is a sane default) and let the router escalate anything bigger;
- prefer short, structured outputs (JSON, lists) over free prose:
  small models stay faithful on short outputs and drift on long ones;
- batch and cache: identical prompts must hit memory before they hit
  the model (see Router reuse).
"""

import json
import math
import urllib.error
import urllib.request

__all__ = ["LocalModel", "StubLocalModel", "OpenAICompatibleLocalModel"]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse redirects (A1): a redirect could move the prompt to a
    host the allowlist never approved."""

    handler_order = 100

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("redirects are not followed")


def _validate_base_url(base_url, allow_remote, allowed_hosts):
    """A1: allow loopback by default; a remote host only when
    explicitly enabled AND on the allowlist AND over https (a
    prompt with context must not travel in plaintext).

    The check parses the host (urlparse hostname strips userinfo and
    ports) and compares it — never a substring of the URL string, so
    "127.0.0.1.evil.com" and "http://127.0.0.1@evil.com" do not pass.
    Names are not resolved: only literal "localhost" and loopback IPs
    pass by default (resolving would be a TOCTOU hole). 0.0.0.0 is
    unspecified, not loopback, and is rejected unconditionally.
    """
    import ipaddress
    from urllib.parse import urlparse
    # Normalize: the adapter appends "/v1/chat/completions" itself,
    # so a trailing "/v1" in the input would double it
    # (".../v1/v1/chat/completions" -> 404 on real servers). Both
    # forms are accepted; repeated trailing segments are stripped.
    base_url = base_url.rstrip("/")
    while base_url.lower().endswith("/v1"):
        base_url = base_url[:-3].rstrip("/")
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("base_url scheme must be http or https")
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("base_url has no host")
    if host == "localhost":
        return base_url.rstrip("/")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None
    if addr is not None:
        if addr.is_unspecified:
            raise ValueError(
                "base_url host %r is unspecified, not a target" % host)
        if addr.is_loopback:
            return base_url.rstrip("/")
    if parsed.scheme != "https":
        # A remote prompt carries document context: plaintext http
        # would expose it on the wire, allowlist or not.
        raise ValueError(
            "remote base_url %r must use https" % (base_url,))
    if allow_remote and allowed_hosts:
        if host in {h.lower() for h in allowed_hosts}:
            return base_url.rstrip("/")
    raise ValueError(
        "remote base_url %r is not allowed: enable allow_remote and "
        "list its host in allowed_hosts" % (base_url,))


class LocalModel:
    """Interface: generate(prompt, budget) -> (text, confidence, source)."""

    def generate(self, prompt, budget=2048):
        raise NotImplementedError


class StubLocalModel(LocalModel):
    """Deterministic stub for tests/demo. Not a model."""

    def __init__(self, answers=None):
        self._answers = answers or {}

    def generate(self, prompt, budget=2048):
        for key, (text, confidence) in self._answers.items():
            if key in prompt:
                return text, confidence, "stub"
        return "no stub answer for this prompt", 0.0, "stub"


class OpenAICompatibleLocalModel(LocalModel):
    """HTTP adapter for a local OpenAI-compatible server.

    base_url may be given with or without a trailing "/v1" — it is
    stripped, the adapter always appends "/v1/chat/completions"."""

    def __init__(self, base_url, model, timeout_s=60,
                 want_logprobs=True, allow_remote=False,
                 allowed_hosts=None, temperature=0.0):
        self.base_url = _validate_base_url(base_url, allow_remote,
                                           allowed_hosts)
        self.model = model
        self.timeout_s = timeout_s
        self.want_logprobs = want_logprobs
        self.temperature = temperature
        # No redirect handler except the refusing one (A1): the
        # opener is built explicitly so no default redirect handler
        # can move a request to an unapproved host.
        opener = urllib.request.OpenerDirector()
        opener.add_handler(urllib.request.HTTPHandler())
        try:
            opener.add_handler(urllib.request.HTTPSHandler())
        except Exception:
            pass
        opener.add_handler(urllib.request.HTTPErrorProcessor())
        # Without the default error handler, an unhandled error code
        # makes open() return None instead of raising HTTPError —
        # which would break the 400 logprobs retry in generate().
        opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
        opener.add_handler(_NoRedirectHandler())
        self._opener = opener

    def _post(self, body):
        req = urllib.request.Request(
            self.base_url + "/v1/chat/completions", data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        with self._opener.open(req, timeout=self.timeout_s) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def generate(self, prompt, budget=2048):
        body = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": budget,
            "temperature": self.temperature,
        }
        if self.want_logprobs:
            body["logprobs"] = True
        try:
            payload = self._post(json.dumps(body).encode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code != 400 or not self.want_logprobs:
                raise
            body.pop("logprobs", None)
            payload = self._post(json.dumps(body).encode("utf-8"))
        choice = payload["choices"][0]
        if choice.get("finish_reason") != "stop":
            # A3: a truncated generation is not a complete answer.
            # Only "stop" is accepted; "length", missing or unknown
            # reasons fail closed (A4 journals the error).
            raise ValueError(
                "local model finished with reason %r, not 'stop'"
                % (choice.get("finish_reason"),))
        text = choice["message"]["content"]
        if text is None:
            raise ValueError("local model returned no content")
        if payload.get("confidence") is not None:
            # Validate at the adapter boundary (F-07): an out-of-range
            # or non-finite confidence is treated as absent (0.0,
            # escalate), never passed on. Without this, a bad value
            # crashes the gate downstream with ValueError.
            try:
                conf = float(payload["confidence"])
            except (TypeError, ValueError):
                return text, 0.0, "none"
            if not math.isfinite(conf) or not 0.0 <= conf <= 1.0:
                return text, 0.0, "none"
            return text, conf, "explicit"
        logprobs = (choice.get("logprobs") or {}).get("content") or []
        vals = [item["logprob"] for item in logprobs
                if isinstance(item, dict) and "logprob" in item]
        if vals:
            conf = math.exp(sum(vals) / len(vals))
            return text, min(1.0, max(0.0, conf)), "logprobs"
        return text, 0.0, "none"
