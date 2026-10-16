from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from stack.audit import AuditLog
from stack.masking import load_recognizers
from stack.policy import load_policy
from stack.presidio_client import PresidioClient
from tests.support.fake_presidio import FakePresidio


@pytest.fixture(scope="module")
def recognizers():
    return load_recognizers(ROOT / "presidio" / "recognizers")


@pytest.fixture(scope="module")
def policy():
    return load_policy(ROOT / "litellm" / "policy.yaml")


@pytest.fixture
def presidio_services(recognizers, policy):
    analyzer = FakePresidio(recognizers, policy.mask_score_threshold)
    anonymizer = FakePresidio(recognizers, policy.mask_score_threshold)
    client = PresidioClient(
        analyzer.url,
        anonymizer.url,
        timeout=0.3,
        recognizers=recognizers,
        threshold=policy.mask_score_threshold,
    )
    yield client, analyzer, anonymizer
    analyzer.stop()
    anonymizer.stop()


@pytest.fixture
def audit(tmp_path, recognizers, policy):
    return AuditLog(tmp_path / "audit.db", recognizers, policy.mask_score_threshold)
