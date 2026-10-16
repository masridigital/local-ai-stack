"""Per-entity recall against the pinned Presidio HTTP services.

Fixtures are clinical prose with realistic identifier shapes and fictional values.
The analyzer and anonymizer are the vendored 2.2.362 apps, not the regex stand-in.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from faker import Faker

from stack.errors import PolicyError
from stack.masking import residual_entities
from tests.fixtures.realistic import HEADER, SEED, build, emails
from tests.support.chat import run_chat
from tests.support.live_presidio import ANALYZER_VERSION, ANONYMIZER_VERSION, SPACY_MODEL_VERSION, LivePresidio

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "realistic_synthetic.json"


@pytest.fixture(scope="module")
def corpus():
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert payload == build()
    return payload


@pytest.fixture(scope="module")
def live(recognizers, policy):
    server = LivePresidio()
    client = server.client(recognizers, policy.mask_score_threshold)
    yield server, client
    server.stop()


def test_fixture_is_synthetic_and_deterministic(corpus):
    text = FIXTURE.read_text(encoding="utf-8")
    assert HEADER in text
    assert corpus["seed"] == SEED
    assert emails() == [
        "nanderson@example.com",
        "rgray@example.com",
        "zacharyjohnson@example.com",
        "kmoore@example.com",
    ]
    fake = Faker("en_US")
    Faker.seed(SEED)
    assert fake.user_name() == "nanderson"
    for row in corpus["samples"]:
        assert row["value"] in row["text"]
        entity = row["entity"]
        value = row["value"]
        if entity == "US_SSN":
            assert value.startswith(("000", "666", "900"))
        elif entity == "EMAIL_ADDRESS":
            assert value.endswith("@example.com")
        elif entity == "PHONE_NUMBER":
            assert value[:3] == "555"
        elif entity == "PERSON":
            assert value in {"Testy McFakerson", "Jane Synthetic-Doe", "Pat Placeholder"}
        elif entity == "CREDIT_CARD":
            assert "4111" in value
        elif entity == "DOB":
            assert "1900" in value or "1901" in value
        elif entity == "NPI":
            assert value.startswith("NPI")
            assert "000000000" in value or "123456789" in value
    for row in corpus["negative"]:
        assert "Testy" not in row
        assert "@" not in row
        assert "555-" not in row


def test_live_services_are_pinned_presidio(live):
    server, _client = live
    from importlib.metadata import version

    assert version("presidio-analyzer") == ANALYZER_VERSION
    assert version("presidio-anonymizer") == ANONYMIZER_VERSION
    assert version("en-core-web-lg") == SPACY_MODEL_VERSION
    import urllib.request

    analyzer = urllib.request.urlopen(server.analyzer_url + "/health", timeout=5).read().decode()
    anonymizer = urllib.request.urlopen(server.anonymizer_url + "/health", timeout=5).read().decode()
    assert analyzer == "Presidio Analyzer service is up"
    assert anonymizer == "Presidio Anonymizer service is up"


def test_per_entity_recall(corpus, live, policy, recognizers):
    _server, client = live
    hits: dict[str, list[bool]] = {entity: [] for entity in policy.recall_floors}
    for row in corpus["samples"]:
        results = client._analyze(row["text"])
        start = row["text"].index(row["value"])
        end = start + len(row["value"])
        detected = any(
            item["entity_type"] == row["entity"]
            and float(item.get("score") or 0) >= policy.mask_score_threshold
            and item["start"] < end
            and item["end"] > start
            for item in results
        )
        hits[row["entity"]].append(detected)
        masked, types = client.mask_text(row["text"])
        assert row["value"] not in masked
        assert row["entity"] in types
        assert not residual_entities(masked, recognizers, policy.mask_score_threshold)
    assert set(hits) == set(policy.recall_floors)
    for entity, floor in policy.recall_floors.items():
        values = hits[entity]
        assert len(values) >= 4, entity
        recall = sum(values) / len(values)
        assert recall >= floor, f"{entity} recall {recall:.2f} < {floor}"


def test_negatives_are_not_masked(corpus, live, recognizers, policy):
    _server, client = live
    for text in corpus["negative"]:
        masked, types = client.mask_text(text)
        assert masked == text
        assert types == []
        assert not residual_entities(masked, recognizers, policy.mask_score_threshold)


def test_chart_redacts_every_entity(corpus, live, recognizers, policy):
    _server, client = live
    masked, types = client.mask_text(corpus["chart"])
    for row in corpus["chart_values"]:
        assert row["value"] not in masked
        assert row["entity"] in types
    assert not residual_entities(masked, recognizers, policy.mask_score_threshold)


def test_adversarial_patterns(corpus, live, recognizers, policy):
    _server, client = live
    for row in corpus["adversarial"]:
        if row.get("encoding") == "base64":
            with pytest.raises(PolicyError) as exc:
                client.mask_text(row["text"])
            assert exc.value.code == "residual_phi"
            assert row["value"] not in exc.value.message
            continue
        masked, types = client.mask_text(row["text"])
        assert row["value"] not in masked
        assert row["entity"] in types
        assert not residual_entities(masked, recognizers, policy.mask_score_threshold)


def test_live_pre_and_post_call(corpus, live, policy, audit):
    from dataclasses import replace

    _server, client = live
    opened = replace(policy, anthropic_baa_enabled=True)
    result, upstream = run_chat(
        "azure",
        policy,
        client,
        audit,
        body={"messages": [{"role": "user", "content": corpus["chart"]}]},
        mock_response=corpus["chart"],
    )
    assert getattr(result, "status", None) == 200
    sent = upstream.calls[0]["messages"][0]["content"]
    returned = result.body["choices"][0]["message"]["content"]
    for row in corpus["chart_values"]:
        assert row["value"] not in sent
        assert row["value"] not in returned
    anthropic, anthropic_upstream = run_chat(
        "anthropic",
        opened,
        client,
        audit,
        body={"messages": [{"role": "user", "content": corpus["chart"]}]},
        mock_response="synthetic ok",
    )
    assert anthropic.status == 200
    assert anthropic.backend == "anthropic"
    forwarded = anthropic_upstream.calls[0]["messages"][0]["content"]
    for row in corpus["chart_values"]:
        assert row["value"] not in forwarded
