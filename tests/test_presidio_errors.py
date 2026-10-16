"""Presidio HTTP errors must not log or return exception text."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

pytest.importorskip("flask")
from werkzeug.exceptions import BadRequest

ROOT = Path(__file__).resolve().parents[1]
MARKER = "SYNTHETIC-MARKER-not-phi"


class _AnalyzerRequest:
    def __init__(self, payload):
        payload = payload or {}
        kind = payload.get("_raise")
        if kind == "type":
            raise TypeError(MARKER)
        if kind == "fatal":
            raise RuntimeError(MARKER)
        self.text = payload.get("text")
        self.language = payload.get("language")
        self.correlation_id = None
        self.score_threshold = None
        self.entities = None
        self.return_decision_process = None
        self.ad_hoc_recognizers = None
        self.context = None
        self.allow_list = None
        self.allow_list_match = None
        self.regex_flags = None


class _Engine:
    def get_supported_entities(self, language):
        if language == "boom":
            raise RuntimeError(MARKER)
        return ["PERSON"]

    def get_recognizers(self, language):
        if language == "boom":
            raise RuntimeError(MARKER)
        return []


class _Provider:
    def __init__(self, **_kwargs):
        return None

    def create_engine(self):
        return _Engine()


class _Batch:
    def __init__(self, engine):
        self.engine = engine


class _InvalidParamError(Exception):
    def __init__(self, err_msg=""):
        self.err_msg = err_msg
        super().__init__(err_msg)


class _Convertor:
    @staticmethod
    def operators_config_from_json(value):
        if value == "invalid":
            raise _InvalidParamError(MARKER)
        if value == "boom":
            raise RuntimeError(MARKER)
        if value == "http":
            raise BadRequest(MARKER)
        return {}

    @staticmethod
    def check_custom_operator(_config):
        return False

    @staticmethod
    def analyzer_results_from_json(_value):
        return []

    @staticmethod
    def deanonymize_entities_from_json(_content):
        return []


class _Anonymizer:
    def anonymize(self, **_kwargs):
        raise AssertionError("anonymize should not run when the request already failed")

    def get_anonymizers(self):
        return []


class _Deanonymizer:
    def get_deanonymizers(self):
        return []


def _module(name: str, **attrs):
    module = types.ModuleType(name)
    module.__path__ = []
    for key, value in attrs.items():
        setattr(module, key, value)
    sys.modules[name] = module
    return module


def _install_stubs() -> None:
    _module(
        "presidio_analyzer",
        AnalyzerEngine=object,
        AnalyzerEngineProvider=_Provider,
        AnalyzerRequest=_AnalyzerRequest,
        BatchAnalyzerEngine=_Batch,
    )
    _module("presidio_anonymizer", AnonymizerEngine=_Anonymizer, DeanonymizeEngine=_Deanonymizer)
    _module("presidio_anonymizer.entities", InvalidParamError=_InvalidParamError)
    _module("presidio_anonymizer.services")
    _module("presidio_anonymizer.services.app_entities_convertor", AppEntitiesConvertor=_Convertor)


def _load(relative: str, name: str):
    _install_stubs()
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _assert_hidden(response, output: str, exception_name: str) -> None:
    body = response.get_json()
    text = response.get_data(as_text=True)
    assert MARKER not in text
    assert MARKER not in output
    assert body["error"] == "request failed"
    assert body["request_id"] in output
    assert exception_name in output
    assert len(body["request_id"]) == 32


def test_analyzer_hides_exception_text(capsys):
    app = _load("presidio/server/analyzer/app.py", "analyzer_app_under_test").create_app()
    client = app.test_client()
    fatal = client.post("/analyze", json={"_raise": "fatal"})
    output = capsys.readouterr().out
    assert fatal.status_code == 500
    _assert_hidden(fatal, output, "RuntimeError")

    typed = client.post("/analyze", json={"_raise": "type"})
    output = capsys.readouterr().out
    assert typed.status_code == 400
    _assert_hidden(typed, output, "TypeError")

    recognizers = client.get("/recognizers?language=boom")
    output = capsys.readouterr().out
    assert recognizers.status_code == 500
    _assert_hidden(recognizers, output, "RuntimeError")

    entities = client.get("/supportedentities?language=boom")
    output = capsys.readouterr().out
    assert entities.status_code == 500
    _assert_hidden(entities, output, "RuntimeError")


def test_anonymizer_hides_exception_text(capsys):
    app = _load("presidio/server/anonymizer/app.py", "anonymizer_app_under_test").create_app()
    client = app.test_client()
    invalid = client.post("/anonymize", json={"text": "hello", "anonymizers": "invalid"})
    output = capsys.readouterr().out
    assert invalid.status_code == 422
    _assert_hidden(invalid, output, "InvalidParamError")

    fatal = client.post("/anonymize", json={"text": "hello", "anonymizers": "boom"})
    output = capsys.readouterr().out
    assert fatal.status_code == 500
    _assert_hidden(fatal, output, "RuntimeError")

    http_error = client.post("/anonymize", json={"text": "hello", "anonymizers": "http"})
    output = capsys.readouterr().out
    assert http_error.status_code == 400
    _assert_hidden(http_error, output, "BadRequest")


def test_presidio_refuses_dev_server_and_wildcard_bind(monkeypatch):
    analyzer = _load("presidio/server/analyzer/app.py", "analyzer_bind_under_test")
    anonymizer = _load("presidio/server/anonymizer/app.py", "anonymizer_bind_under_test")
    for module in (analyzer, anonymizer):
        with pytest.raises(SystemExit, match="Flask development server"):
            module.main()
        for host in ("::", "[::]", "0.0.0.0", ""):
            monkeypatch.setenv("BIND_HOST", host)
            with pytest.raises(SystemExit, match="wildcard"):
                module._bind_host()
        monkeypatch.setenv("BIND_HOST", "127.0.0.1")
        assert module._bind_host() == "127.0.0.1"
