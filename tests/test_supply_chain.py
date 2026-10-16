"""Native supply chain: hash pins stand in for image digests. No Docker."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_no_docker_artifacts():
    for relative in ("docker-compose.yml", "images.lock.yaml", "compose.yaml"):
        assert not (ROOT / relative).exists(), relative
    services = yaml.safe_load((ROOT / "deploy" / "services.yaml").read_text(encoding="utf-8"))
    assert services["docker"] is False
    assert services["runtime"] == "native"
    install = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    assert "docker compose" not in install
    assert "--require-hashes" in install


def test_requirement_locks_are_hash_pinned():
    services = yaml.safe_load((ROOT / "deploy" / "services.yaml").read_text(encoding="utf-8"))
    seen = []
    for app in services["apps"]:
        for relative in app["requirements"]:
            seen.append(relative)
            text = (ROOT / relative).read_text(encoding="utf-8")
            assert "--hash=sha256:" in text, relative
    analyzer = (ROOT / "requirements" / "presidio-analyzer.txt").read_text(encoding="utf-8")
    anonymizer = (ROOT / "requirements" / "presidio-anonymizer.txt").read_text(encoding="utf-8")
    model = (ROOT / "requirements" / "spacy-model.txt").read_text(encoding="utf-8")
    litellm = (ROOT / "requirements" / "litellm.txt").read_text(encoding="utf-8")
    assert "presidio-analyzer[server]==2.2.362" in analyzer
    assert "spacy==3.8." in analyzer
    assert "presidio-anonymizer[server]==2.2.362" in anonymizer
    assert "en_core_web_lg-3.8.0" in model
    assert "--hash=sha256:" in model
    assert "litellm[proxy]==1.105.1" in litellm
    assert "requirements/presidio-analyzer.txt" in seen
    assert "requirements/spacy-model.txt" in seen


def test_ci_installs_pinned_presidio_without_docker():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "docker compose" not in workflow
    assert "docker:" not in workflow
    assert "ubuntu-24.04" in workflow
    assert "--require-hashes" in workflow
    assert "requirements/presidio-analyzer.txt" in workflow
    assert "requirements/presidio-anonymizer.txt" in workflow
    assert "requirements/spacy-model.txt" in workflow
    assert "aquasecurity/trivy-action@v0.36.0" in workflow
    assert "gitleaks/gitleaks-action@v2" in workflow
    assert "pytest" in workflow
    assert "bandit" in workflow
    assert "shellcheck" in workflow
