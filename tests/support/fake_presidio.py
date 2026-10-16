"""In-process Presidio analyzer and anonymizer for acceptance tests."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from stack.masking import find_spans


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        mode = self.server.mode  # type: ignore[attr-defined]
        if mode == "timeout":
            time.sleep(2)
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        if mode == "http_500":
            payload = b'{"error":"synthetic failure"}'
            self._send(500, payload)
            return
        if mode == "bad_json":
            self._send(200, b"not-json")
            return
        if mode == "object_json":
            self._send(200, b'{"error":"not a list"}')
            return
        body = json.loads(raw.decode("utf-8"))
        if self.path.startswith("/analyze"):
            spans = find_spans(body["text"], self.server.recognizers, self.server.threshold)  # type: ignore[attr-defined]
            result = [
                {"entity_type": span.entity, "start": span.start, "end": span.end, "score": span.score}
                for span in spans
            ]
            self._send(200, json.dumps(result).encode("utf-8"))
            return
        text = body["text"]
        spans = sorted(body.get("analyzer_results") or [], key=lambda item: item["start"], reverse=True)
        for span in spans:
            text = text[: span["start"]] + f"<{span['entity_type']}>" + text[span["end"] :]
        self._send(200, json.dumps({"text": text}).encode("utf-8"))

    def _send(self, status: int, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args) -> None:
        return


class FakePresidio:
    def __init__(self, recognizers, threshold: float):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.recognizers = recognizers  # type: ignore[attr-defined]
        self.httpd.threshold = threshold  # type: ignore[attr-defined]
        self.httpd.mode = "ok"  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address
        return f"http://{host}:{port}"

    def set_mode(self, mode: str) -> None:
        self.httpd.mode = mode  # type: ignore[attr-defined]

    def stop(self) -> None:
        self.httpd.shutdown()
        self.thread.join(timeout=2)
