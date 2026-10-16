"""HTTP client for the official Presidio analyzer and anonymizer.

Any transport error, non-2xx response, or body that is not the documented JSON
shape raises PresidioUnavailable. Callers must not fall back to local masking.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from stack.errors import PolicyError, PresidioUnavailable
from stack.masking import Recognizer, presidio_ad_hoc, residual_entities


class PresidioClient:
    def __init__(self, analyzer_url: str, anonymizer_url: str, timeout: float, recognizers: list[Recognizer], threshold: float):
        self.analyzer_url = analyzer_url.rstrip("/")
        self.anonymizer_url = anonymizer_url.rstrip("/")
        self.timeout = timeout
        self.recognizers = recognizers
        self.threshold = threshold

    def mask_text(self, text: str) -> tuple[str, list[str]]:
        if text == "":
            return "", []
        entities_payload = self._analyze(text)
        kept = [item for item in entities_payload if float(item.get("score") or 0) >= self.threshold]
        masked = text if not kept else self._anonymize(text, kept)
        left = residual_entities(masked, self.recognizers, self.threshold)
        if left:
            raise PolicyError("residual_phi", "known PHI pattern remained after masking", status=503)
        types = sorted({item["entity_type"] for item in kept})
        return masked, types

    def _analyze(self, text: str) -> list[dict]:
        payload = {
            "text": text,
            "language": "en",
            "score_threshold": self.threshold,
            "entities": sorted({rec.entity for rec in self.recognizers} | {"PERSON", "US_SSN", "PHONE_NUMBER", "EMAIL_ADDRESS", "CREDIT_CARD", "LOCATION"}),
            "ad_hoc_recognizers": presidio_ad_hoc(self.recognizers),
        }
        body = self._post(f"{self.analyzer_url}/analyze", payload)
        if isinstance(body, dict):
            raise PresidioUnavailable("analyzer returned an object")
        if not isinstance(body, list):
            raise PresidioUnavailable("analyzer returned malformed json")
        cleaned = []
        for item in body:
            if not isinstance(item, dict):
                raise PresidioUnavailable("analyzer item malformed")
            if "entity_type" not in item or "start" not in item or "end" not in item:
                raise PresidioUnavailable("analyzer item missing fields")
            cleaned.append(item)
        return cleaned

    def _anonymize(self, text: str, results: list[dict]) -> str:
        anonymizers = {"DEFAULT": {"type": "replace", "new_value": "<REDACTED>"}}
        for item in results:
            anonymizers[item["entity_type"]] = {
                "type": "replace",
                "new_value": f"<{item['entity_type']}>",
            }
        payload = {"text": text, "analyzer_results": results, "anonymizers": anonymizers}
        body = self._post(f"{self.anonymizer_url}/anonymize", payload)
        if not isinstance(body, dict) or "text" not in body or not isinstance(body["text"], str):
            raise PresidioUnavailable("anonymizer returned malformed json")
        return body["text"]

    def _post(self, url: str, payload: dict):
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        if not url.startswith(("http://", "https://")):
            raise PresidioUnavailable("refusing non-http presidio url")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # nosec B310
                raw = response.read()
                status = response.status
        except urllib.error.HTTPError as exc:
            raise PresidioUnavailable(f"presidio http {exc.code}") from exc
        except Exception as exc:
            raise PresidioUnavailable(f"presidio unreachable: {type(exc).__name__}") from exc
        if status >= 400:
            raise PresidioUnavailable(f"presidio http {status}")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PresidioUnavailable("malformed json") from exc
