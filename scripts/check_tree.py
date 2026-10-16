"""Repo checks used by deploy/install.sh --check and by CI."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

WILDCARD_HOST = ".".join(("0", "0", "0", "0"))
ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_TUNNEL_TARGETS = ("open-webui", "litellm", "policy-gateway", "presidio", "postgres")


def main() -> None:
    errors = check()
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        raise SystemExit(1)
    print("check ok")


def check() -> list[str]:
    errors: list[str] = []
    compose_path = ROOT / "docker-compose.yml"
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    text = compose_path.read_text(encoding="utf-8")
    if WILDCARD_HOST in text:
        errors.append("compose publishes or mentions a wildcard host address")
    if "env_file" in compose.get("services", {}):
        errors.append("compose uses env_file")
    for name, service in compose["services"].items():
        if "env_file" in service:
            errors.append(f"{name} uses env_file")
        ports = service.get("ports") or []
        if name != "caddy" and ports:
            errors.append(f"{name} publishes a host port")
        if name == "caddy":
            for port in ports:
                rendered = str(port)
                if WILDCARD_HOST in rendered or not ("127.0.0.1" in rendered or "LAN_BIND_IP" in rendered):
                    errors.append(f"caddy port is not loopback or LAN_BIND_IP: {rendered}")
    networks = compose["networks"]
    for name in ("edge", "guard", "models"):
        if not networks[name].get("internal"):
            errors.append(f"network {name} is not internal")
    webui_nets = set(compose["services"]["open-webui"]["networks"])
    litellm_nets = set(compose["services"]["litellm"]["networks"])
    if webui_nets & litellm_nets:
        errors.append("open-webui shares a network with litellm")
    if "egress" in webui_nets or "edge" in litellm_nets:
        errors.append("network split is wrong")
    if "cloudflared" in text or "argotunnel" in text:
        errors.append("main compose references cloudflared")
    images = yaml.safe_load((ROOT / "images.lock.yaml").read_text(encoding="utf-8"))["images"]
    for key, image in images.items():
        if key == "policy_gateway_base":
            dockerfile = (ROOT / "policy-gateway" / "Dockerfile").read_text(encoding="utf-8")
            if image not in dockerfile:
                errors.append("policy gateway base image is not pinned in the Dockerfile")
            continue
        if key == "cloudflared":
            cloud = (ROOT / "deploy" / "cloudflared" / "docker-compose.yml").read_text(encoding="utf-8")
            if image not in cloud:
                errors.append("cloudflared image is not pinned")
            continue
        if image not in text:
            errors.append(f"compose is missing pinned image {image}")
    policy = yaml.safe_load((ROOT / "litellm" / "policy.yaml").read_text(encoding="utf-8"))
    if policy["anthropic_baa_enabled"] is not False:
        errors.append("Anthropic BAA switch must default off")
    if policy["streaming_enabled"] is not False:
        errors.append("streaming must default off")
    if policy["foundry"]["azure_ai_enabled"] is not False:
        errors.append("azure_ai must default off")
    if policy["foundry"]["abuse_monitoring_opt_out"] is not False:
        errors.append("abuse-monitoring opt-out must default off")
    rules = (ROOT / "deploy" / "ufw" / "user.rules").read_text(encoding="utf-8")
    if "default deny incoming" not in rules or "default deny outgoing" not in rules:
        errors.append("ufw rules are not default deny")
    if f"{WILDCARD_HOST}/0" in rules or "argotunnel" in rules:
        errors.append("ufw rules allow the world or cloudflared")
    tunnel = (ROOT / "deploy" / "cloudflared" / "config.yml").read_text(encoding="utf-8").lower()
    for target in FORBIDDEN_TUNNEL_TARGETS:
        if target in tunnel:
            errors.append(f"cloudflared config mentions {target}")
    if "http_status:404" not in tunnel:
        errors.append("cloudflared config must sink to http_status:404")
    return errors


if __name__ == "__main__":
    main()
