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
    assert "actions/checkout@11d5960a326750d5838078e36cf38b85af677262" in workflow
    assert "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" in workflow
    assert "gitleaks/gitleaks-action@ff98106e4c7b2bc287b24eaf42907196329070c7" in workflow
    assert "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25" in workflow
    assert "fetch-depth: 0" in workflow
    assert "contents: read" in workflow
    assert "nftables" in workflow
    assert "pip install -r requirements-dev.txt" in workflow
    assert "GITLEAKS_VERSION" not in workflow
    assert "install_gitleaks" not in workflow
    assert "gitleaks/gitleaks-action@v2" not in workflow
    assert "aquasecurity/trivy-action@v0.36.0" not in workflow
    assert "pytest" in workflow
    assert "bandit" in workflow
    assert "shellcheck" in workflow
