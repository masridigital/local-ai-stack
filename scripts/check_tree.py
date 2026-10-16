"""Repo checks used by deploy/install.sh --check and by CI."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.egress_owners import load_destinations, render_owner_rules, render_user_rules

WILDCARD_HOST = ".".join(("0", "0", "0", "0"))
FORBIDDEN_TUNNEL_TARGETS = ("open-webui", "litellm", "policy-gateway", "presidio", "postgres")
HARDENING = ("ProtectSystem=strict", "NoNewPrivileges=yes", "PrivateTmp=yes", "CapabilityBoundingSet=")


def main() -> None:
    errors = check()
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        raise SystemExit(1)
    print("check ok")


def check() -> list[str]:
    errors: list[str] = []
    for relative in ("docker-compose.yml", "images.lock.yaml", "policy-gateway/Dockerfile", "deploy/cloudflared/docker-compose.yml"):
        if (ROOT / relative).exists():
            errors.append(f"docker artifact still present: {relative}")
    services = yaml.safe_load((ROOT / "deploy" / "services.yaml").read_text(encoding="utf-8"))
    if services.get("docker") is not False or services.get("runtime") != "native":
        errors.append("services.yaml is not a native runtime")
    install = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    if "docker compose" in install or "docker.io" in install:
        errors.append("install.sh still installs or starts Docker")
    for app in services["apps"]:
        unit_path = ROOT / "deploy" / "systemd" / app["unit"]
        unit = unit_path.read_text(encoding="utf-8")
        if f"User={app['user']}" not in unit:
            errors.append(f"{app['unit']} user mismatch")
        if f"{app['bind']}:{app['port']}" not in unit and f"PORT={app['port']}" not in unit:
            errors.append(f"{app['unit']} is not bound to {app['bind']}:{app['port']}")
        for line in HARDENING:
            if line not in unit:
                errors.append(f"{app['unit']} missing {line}")
        if "CapabilityBoundingSet=\n" not in unit and not unit.endswith("CapabilityBoundingSet=\n"):
            # empty bounding set, not a leftover capability
            if "CapabilityBoundingSet=" in unit and "CapabilityBoundingSet=CAP_" in unit:
                errors.append(f"{app['unit']} keeps a capability")
        for cred in app["credentials"]:
            if f"LoadCredential={cred}:" not in unit:
                errors.append(f"{app['unit']} missing LoadCredential {cred}")
        if app["opt"] not in install:
            errors.append(f"install.sh does not mention {app['opt']}")
        if "--require-hashes" not in install:
            errors.append("install.sh does not require hashes")
        for req in app["requirements"]:
            text = (ROOT / req).read_text(encoding="utf-8")
            if "--hash=sha256:" not in text:
                errors.append(f"{req} is not hash-pinned")
    if "en_core_web_lg-3.8.0" not in (ROOT / "requirements" / "spacy-model.txt").read_text(encoding="utf-8"):
        errors.append("spaCy model is not pinned to en_core_web_lg 3.8.0")
    if "spacy==3.8." not in (ROOT / "requirements" / "presidio-analyzer.txt").read_text(encoding="utf-8"):
        errors.append("analyzer lock is not on spaCy 3.8")
    litellm_lock = (ROOT / "requirements" / "litellm.txt").read_text(encoding="utf-8").lower()
    if "litellm[proxy]==1.105.1" not in litellm_lock:
        errors.append("litellm lock is not 1.105.1")
    if "langfuse" in litellm_lock or "sentry-sdk" in litellm_lock:
        errors.append("litellm lock includes a telemetry package")
    if "open-webui==0.12.2" not in (ROOT / "requirements" / "open-webui.txt").read_text(encoding="utf-8"):
        errors.append("open-webui lock is not 0.12.2")
    policy = yaml.safe_load((ROOT / "litellm" / "policy.yaml").read_text(encoding="utf-8"))
    if policy["anthropic_baa_enabled"] is not False:
        errors.append("Anthropic BAA switch must default off")
    if policy["streaming_enabled"] is not False:
        errors.append("streaming must default off")
    if policy["foundry"]["azure_ai_enabled"] is not False:
        errors.append("azure_ai must default off")
    if policy["foundry"]["abuse_monitoring_opt_out"] is not False:
        errors.append("abuse-monitoring opt-out must default off")
    raw = load_destinations(ROOT / "deploy" / "egress-destinations.yaml")
    user_rules = (ROOT / "deploy" / "ufw" / "user.rules").read_text(encoding="utf-8")
    owner_rules = (ROOT / "deploy" / "ufw" / "owner.rules").read_text(encoding="utf-8")
    if user_rules != render_user_rules(raw):
        errors.append("ufw user.rules drifted from egress-destinations.yaml")
    if owner_rules != render_owner_rules(raw, {}):
        errors.append("ufw owner.rules drifted from egress-destinations.yaml")
    if "default deny incoming" not in user_rules or "default deny outgoing" not in user_rules:
        errors.append("ufw rules are not default deny")
    if WILDCARD_HOST in user_rules or "argotunnel" in user_rules or "docker.io" in user_rules:
        errors.append("ufw rules allow the world, cloudflared, or a container registry")
    if "--uid-owner policy-gateway -j REJECT" not in owner_rules:
        errors.append("policy-gateway is missing a default egress reject")
    tunnel = (ROOT / "deploy" / "cloudflared" / "config.yml").read_text(encoding="utf-8").lower()
    for target in FORBIDDEN_TUNNEL_TARGETS:
        if target in tunnel:
            errors.append(f"cloudflared config mentions {target}")
    if "http_status:404" not in tunnel:
        errors.append("cloudflared config must sink to http_status:404")
    caddy = (ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8")
    if "127.0.0.1" not in caddy or "bind" not in caddy:
        errors.append("Caddyfile does not bind loopback by default")
    scanned = []
    scanned.extend((ROOT / "deploy" / "systemd").glob("*"))
    scanned.append(ROOT / "deploy" / "Caddyfile")
    scanned.append(ROOT / "deploy" / "install.sh")
    scanned.extend((ROOT / "presidio" / "server").rglob("*.py"))
    scanned.append(ROOT / "stack" / "server.py")
    for path in scanned:
        if not path.is_file():
            continue
        if WILDCARD_HOST in path.read_text(encoding="utf-8"):
            errors.append(f"{path.relative_to(ROOT)} mentions a wildcard host address")
    site = (ROOT / "ansible" / "site.yml").read_text(encoding="utf-8")
    for role in (
        "common",
        "secrets",
        "postgres",
        "presidio_analyzer",
        "presidio_anonymizer",
        "litellm",
        "policy_gateway",
        "open_webui",
        "caddy",
        "wireguard",
        "cloudflared",
        "firewall",
        "retention",
    ):
        if role not in site:
            errors.append(f"ansible site is missing {role}")
    python_role = (ROOT / "ansible" / "roles" / "python_app" / "tasks" / "main.yml").read_text(encoding="utf-8")
    if "--require-hashes" not in python_role:
        errors.append("ansible python_app role does not require hashes")
    return errors


if __name__ == "__main__":
    main()
