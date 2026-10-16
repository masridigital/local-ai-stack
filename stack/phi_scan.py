"""Detect raw synthetic PHI in logs, audit rows, and error bodies."""

from __future__ import annotations

from stack.masking import Recognizer, residual_entities


def contains_raw_phi(text: str, recognizers: list[Recognizer], threshold: float) -> bool:
    if not text:
        return False
    return bool(residual_entities(text, recognizers, threshold))
