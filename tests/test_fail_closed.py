"""Every fail-closed mode, including streaming, on Anthropic and Foundry.

Streaming is rejected before Presidio and before the mock model. Presidio
failures on the non-streaming chat route return 503 and do not call the model.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from dataclasses import replace
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from stack.errors import PolicyError
from stack.pipeline import Upstream
from stack.server import Handler, build_deps
from tests.support.chat import USER, run_chat
from tests.support.fake_presidio import FakePresidio

REPO = Path(__file__).resolve().parents[1]

FAILURES = ("analyzer_down", "anonymizer_down", "timeout", "http_500", "bad_json", "object_json")
BACKENDS = ("anthropic", "azure", "azure_ai")


def _arm(client, analyzer, failure: str) -> None:
    if failure == "analyzer_down":
        client.analyzer_url = "http://127.0.0.1:9"
    elif failure == "anonymizer_down":
        client.anonymizer_url = "http://127.0.0.1:9"
    else:
        analyzer.set_mode(failure)


def _opened(policy, backend: str):
    if backend == "anthropic":
        return replace(policy, anthropic_baa_enabled=True)
    if backend == "azure_ai":
        return replace(policy, foundry=replace(policy.foundry, azure_ai_enabled=True))
    return policy


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("failure", FAILURES)
def test_presidio_failure_blocks_before_the_model(backend, failure, policy, presidio_services, audit):
    client, analyzer, _anonymizer = presidio_services
    _arm(client, analyzer, failure)
    result, upstream = run_chat(
        backend,
        _opened(policy, backend),
        client,
        audit,
        body={"messages": [{"role": "user", "content": "Chart MRN-SYN-0001234 for Testy McFakerson."}]},
    )
    assert isinstance(result, PolicyError)
    assert result.status == 503
    assert result.code == "presidio_unavailable"
    assert "MRN-SYN" not in result.message
    assert "Testy" not in result.message
    assert upstream.calls == []


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("failure", FAILURES)
def test_streaming_is_rejected_even_when_presidio_is_down(backend, failure, policy, presidio_services, audit):
    client, analyzer, _anonymizer = presidio_services
    _arm(client, analyzer, failure)
    result, upstream = run_chat(
        backend,
        policy,
        client,
        audit,
        body={"stream": True, "messages": [{"role": "user", "content": "Chart MRN-SYN-0001234."}]},
    )
    assert isinstance(result, PolicyError)
    assert result.code == "streaming_disabled"
    assert result.status == 403
    assert "MRN-SYN" not in result.message
    assert upstream.calls == []


@pytest.mark.parametrize("backend", BACKENDS)
def test_streaming_flag_blocks_a_non_stream_request(backend, policy, presidio_services, audit):
    client, _analyzer, _anonymizer = presidio_services
    forced = replace(policy, streaming_enabled=True)
    result, upstream = run_chat(backend, forced, client, audit, body={"stream": False})
    assert isinstance(result, PolicyError)
    assert result.code == "streaming_disabled"
    assert upstream.calls == []


@pytest.mark.parametrize(
    "path",
    [
        "/v1/completions",
        "/v1/embeddings",
        "/v1/responses",
        "/v1/messages",
        "/v1/files",
        "/v1/batches",
        "/anthropic/v1/messages",
    ],
)
def test_untested_routes_never_call_the_model(path, policy, presidio_services, audit):
    client, _analyzer, _anonymizer = presidio_services
    result, upstream = run_chat("azure", policy, client, audit, path=path)
    assert isinstance(result, PolicyError)
    assert result.code == "route_disabled"
    assert upstream.calls == []


class _Gateway:
    def __init__(self, httpd, upstream, presidio, analyzer, anonymizer):
        self.httpd = httpd
        self.upstream = upstream
        self.presidio = presidio
        self.analyzer = analyzer
        self.anonymizer = anonymizer
        host, port = httpd.server_address
        self.url = f"http://{host}:{port}"

    def post(self, path: str, body, headers: dict | None = None):
        payload = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        sent = {
            "Content-Type": "application/json",
            "Authorization": "Bearer gateway-test-key",
            "X-Entra-App-Roles": "phi",
        }
        if headers:
            sent.update(headers)
        request = urllib.request.Request(
            self.url + path,
            data=payload,
            headers=sent,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.analyzer.stop()
        self.anonymizer.stop()


@pytest.fixture
def gateway(tmp_path, monkeypatch, recognizers, policy):
    analyzer = FakePresidio(recognizers, policy.mask_score_threshold)
    anonymizer = FakePresidio(recognizers, policy.mask_score_threshold)
    monkeypatch.setenv("POLICY_PATH", str(REPO / "litellm" / "policy.yaml"))
    monkeypatch.setenv("RECOGNIZER_DIR", str(REPO / "presidio" / "recognizers"))
    monkeypatch.setenv("AUDIT_SQLITE_PATH", str(tmp_path / "audit.db"))
    monkeypatch.setenv("PRESIDIO_ANALYZER_API_BASE", analyzer.url)
    monkeypatch.setenv("PRESIDIO_ANONYMIZER_API_BASE", anonymizer.url)
    monkeypatch.setenv("PRESIDIO_TIMEOUT", "0.3")
    monkeypatch.setenv("ANTHROPIC_BAA_ENABLED", "false")
    monkeypatch.setenv("ALLOW_AZURE_AI_THIRD_PARTY", "false")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "dep-placeholder")
    monkeypatch.setenv("AZURE_OPENAI_MODEL_FAMILY", "gpt-4.1")
    monkeypatch.setenv("AZURE_OPENAI_REGION", "eastus2")
    monkeypatch.setenv("AZURE_API_BASE", "https://cap-eastus2.openai.azure.com/")
    _policy, foundry, presidio, audit = build_deps()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.gateway_client_key = "gateway-test-key"  # type: ignore[attr-defined]
    httpd.deps = (_policy, foundry, presidio, audit)  # type: ignore[attr-defined]
    upstream = Upstream()
    httpd.upstream = upstream  # type: ignore[attr-defined]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    gate = _Gateway(httpd, upstream, presidio, analyzer, anonymizer)
    yield gate
    gate.stop()
    thread.join(timeout=5)


def _chat_body(**extra):
    body = {
        "model": "azure/dep-placeholder",
        "messages": [{"role": "user", "content": "Chart MRN-SYN-0001234 for Testy McFakerson."}],
        "max_tokens": 16,
    }
    body.update(extra)
    return body


def test_http_malformed_json_is_400(gateway):
    status, headers, raw = gateway.post(
        "/v1/chat/completions",
        b"{'not: json}",
        {"X-OpenWebUI-User-Id": USER},
    )
    assert status == 400
    assert headers["Content-Type"].startswith("application/json")
    assert b"MRN-SYN" not in raw
    assert gateway.upstream.calls == []


def test_http_streaming_is_json_not_an_event_stream(gateway):
    status, headers, raw = gateway.post(
        "/v1/chat/completions",
        _chat_body(stream=True),
        {"X-OpenWebUI-User-Id": USER},
    )
    body = json.loads(raw)
    assert status == 403
    assert body["error"]["code"] == "streaming_disabled"
    assert "text/event-stream" not in headers.get("Content-Type", "")
    assert b"data:" not in raw
    assert b"MRN-SYN" not in raw
    assert gateway.upstream.calls == []


def test_http_analyzer_down_is_503(gateway):
    gateway.presidio.analyzer_url = "http://127.0.0.1:9"
    status, _headers, raw = gateway.post(
        "/v1/chat/completions",
        _chat_body(),
        {"X-OpenWebUI-User-Id": USER},
    )
    body = json.loads(raw)
    assert status == 503
    assert body["error"]["code"] == "presidio_unavailable"
    assert "MRN-SYN" not in body["error"]["message"]
    assert gateway.upstream.calls == []


def test_http_timeout_is_503(gateway):
    gateway.analyzer.set_mode("timeout")
    status, _headers, raw = gateway.post(
        "/v1/chat/completions",
        _chat_body(),
        {"X-OpenWebUI-User-Id": USER},
    )
    assert status == 503
    assert json.loads(raw)["error"]["code"] == "presidio_unavailable"
    assert gateway.upstream.calls == []


def test_http_success_redacts_before_upstream(gateway):
    status, _headers, raw = gateway.post(
        "/v1/chat/completions",
        _chat_body(),
        {"X-OpenWebUI-User-Id": USER},
    )
    assert status == 200
    sent = gateway.upstream.calls[0]["messages"][0]["content"]
    assert "MRN-SYN-0001234" not in sent
    assert "Testy McFakerson" not in sent
    assert "<MRN>" in sent
    assert "MRN-SYN-0001234" not in raw.decode()
