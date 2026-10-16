"""Pattern masking shared by recall tests and the mock Presidio.

Production requests still go to the Presidio HTTP services. This module is the
recognizer definition runner: custom entities, the synthetic deny-list, and
the residual check that blocks known PHI patterns Presidio failed to mask.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern[str]
    score: float


@dataclass(frozen=True)
class Recognizer:
    entity: str
    patterns: tuple[Pattern, ...]


@dataclass(frozen=True)
class Span:
    entity: str
    start: int
    end: int
    score: float


_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/])")


def load_recognizers(directory: Path) -> list[Recognizer]:
    recognizers: list[Recognizer] = []
    for path in sorted(directory.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        patterns = tuple(
            Pattern(
                name=item["name"],
                regex=re.compile(item["regex"]),
                score=float(item["score"]),
            )
            for item in raw["patterns"]
        )
        recognizers.append(Recognizer(entity=raw["entity"], patterns=patterns))
    if not recognizers:
        raise FileNotFoundError(f"no recognizers in {directory}")
    return recognizers


def presidio_ad_hoc(recognizers: list[Recognizer]) -> list[dict]:
    """JSON recognizers LiteLLM and the Presidio analyzer accept."""
    payload = []
    for rec in recognizers:
        payload.append(
            {
                "name": f"{rec.entity}Recognizer",
                "supported_language": "en",
                "supported_entity": rec.entity,
                "patterns": [
                    {"name": pat.name, "regex": pat.regex.pattern, "score": pat.score}
                    for pat in rec.patterns
                ],
            }
        )
    return payload


def find_spans(text: str, recognizers: list[Recognizer], threshold: float) -> list[Span]:
    spans: list[Span] = []
    for match in _BASE64_RE.finditer(text):
        token = match.group(1)
        decoded = _decode_base64(token)
        if decoded is None:
            continue
        if find_spans_raw(decoded, recognizers, threshold):
            spans.append(Span("OBFUSCATED_PHI", match.start(1), match.end(1), 0.99))
    spans.extend(find_spans_raw(text, recognizers, threshold))
    return _resolve(spans)


def find_spans_raw(text: str, recognizers: list[Recognizer], threshold: float) -> list[Span]:
    found: list[Span] = []
    for rec in recognizers:
        for pat in rec.patterns:
            if pat.score < threshold:
                continue
            for match in pat.regex.finditer(text):
                if match.start() == match.end():
                    continue
                found.append(Span(rec.entity, match.start(), match.end(), pat.score))
    return found


def mask_text(text: str, recognizers: list[Recognizer], threshold: float) -> tuple[str, list[str]]:
    spans = find_spans(text, recognizers, threshold)
    if not spans:
        return text, []
    pieces = []
    cursor = 0
    entities: list[str] = []
    for span in spans:
        pieces.append(text[cursor : span.start])
        pieces.append(f"<{span.entity}>")
        entities.append(span.entity)
        cursor = span.end
    pieces.append(text[cursor:])
    return "".join(pieces), entities


def residual_entities(text: str, recognizers: list[Recognizer], threshold: float) -> list[str]:
    return [span.entity for span in find_spans(text, recognizers, threshold)]


def _decode_base64(token: str) -> str | None:
    padded = token + ("=" * (-len(token) % 4))
    try:
        raw = base64.b64decode(padded, validate=True)
    except Exception:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _resolve(spans: list[Span]) -> list[Span]:
    ordered = sorted(spans, key=lambda s: (s.start, -s.score, -(s.end - s.start)))
    chosen: list[Span] = []
    cursor = -1
    for span in ordered:
        if span.start < cursor:
            continue
        chosen.append(span)
        cursor = span.end
    return chosen
