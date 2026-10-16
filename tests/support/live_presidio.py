"""In-process Presidio analyzer and anonymizer from the pinned 2.2.362 servers.

The HTTP apps under presidio/server are the Microsoft 2.2.362 modules. Tests
load those modules and serve them on 127.0.0.1. Nothing here starts Docker.
"""

from __future__ import annotations

import importlib.util
import threading
import time
import urllib.request
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from stack.presidio_client import PresidioClient

ROOT = Path(__file__).resolve().parents[2]
ANALYZER_VERSION = "2.2.362"
ANONYMIZER_VERSION = "2.2.362"
SPACY_MODEL_VERSION = "3.8.0"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _require_pins() -> None:
    expected = {
        "presidio-analyzer": ANALYZER_VERSION,
        "presidio-anonymizer": ANONYMIZER_VERSION,
        "en-core-web-lg": SPACY_MODEL_VERSION,
    }
    missing = []
    for dist, pin in expected.items():
        try:
            found = version(dist)
        except PackageNotFoundError:
            missing.append(dist)
            continue
        if found != pin:
            raise RuntimeError(f"{dist} {found} is installed; CI pins {pin}")
    if missing:
        raise RuntimeError(
            "pinned Presidio is not installed ("
            + ", ".join(missing)
            + "). Install with pip --require-hashes -r requirements/presidio-analyzer.txt "
            "-r requirements/presidio-anonymizer.txt -r requirements/spacy-model.txt"
        )


class LivePresidio:
    def __init__(self) -> None:
        _require_pins()
        analyzer = _load_module(
            "presidio_analyzer_http",
            ROOT / "presidio" / "server" / "analyzer" / "app.py",
        ).create_app()
        anonymizer = _load_module(
            "presidio_anonymizer_http",
            ROOT / "presidio" / "server" / "anonymizer" / "app.py",
        ).create_app()
        self._servers = [self._serve(analyzer), self._serve(anonymizer)]
        self.analyzer_url = self._servers[0][0]
        self.anonymizer_url = self._servers[1][0]
        for url, needle in (
            (self.analyzer_url, "Presidio Analyzer"),
            (self.anonymizer_url, "Presidio Anonymizer"),
        ):
            self._wait_health(url, needle)

    def client(self, recognizers, threshold: float, timeout: float = 10.0) -> PresidioClient:
        return PresidioClient(
            self.analyzer_url,
            self.anonymizer_url,
            timeout=timeout,
            recognizers=recognizers,
            threshold=threshold,
        )

    def stop(self) -> None:
        for _url, server, thread in self._servers:
            server.shutdown()
            thread.join(timeout=5)

    def _serve(self, app) -> tuple[str, object, threading.Thread]:
        from werkzeug.serving import make_server

        server = make_server("127.0.0.1", 0, app, threaded=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}"
        return url, server, thread

    @staticmethod
    def _wait_health(url: str, needle: str) -> None:
        deadline = time.time() + 30
        last = ""
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(url + "/health", timeout=2) as response:
                    body = response.read().decode("utf-8")
                if needle in body:
                    return
                last = body
            except Exception as exc:
                last = f"{type(exc).__name__}: {exc}"
                time.sleep(0.1)
        raise RuntimeError(f"{url} did not report {needle}: {last}")
