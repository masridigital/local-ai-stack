"""Open WebUI and LiteLLM have no Cloudflare Tunnel route.

Cap declined a Cloudflare BAA. The tunnel file is a 404 sink and the unit stays disabled.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PHI_NAMES = ("open-webui", "open_webui", "litellm", "policy-gateway", "presidio", "postgres")
PHI_PORTS = ("8080", "4000", "8088", "3000", "3001")


def test_cloudflared_ingress_is_only_a_404_sink():
    text = (ROOT / "deploy" / "cloudflared" / "config.yml").read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    ingress = document["ingress"]
    assert ingress == [{"service": "http_status:404"}]
    assert all("hostname" not in rule for rule in ingress)
    lowered = text.lower()
    for name in PHI_NAMES:
        assert name not in lowered
    for port in PHI_PORTS:
        assert port not in text
    for needle in ("trycloudflare", "argotunnel", "service: http://", "service: https://"):
        assert needle not in lowered


def test_tunnel_unit_and_installer_stay_disabled():
    unit = (ROOT / "deploy" / "systemd" / "cloudflared.service").read_text(encoding="utf-8")
    assert "IPAddressDeny=any" in unit
    lowered = unit.lower()
    for name in ("open-webui", "litellm", "8080", "4000"):
        assert name not in lowered
    install = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    assert "systemctl disable --now cloudflared.service" in install
    assert "systemctl enable cloudflared" not in install
    ansible = (ROOT / "ansible" / "roles" / "cloudflared" / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "enabled: false" in ansible
    assert "state: stopped" in ansible
    egress = yaml.safe_load((ROOT / "deploy" / "egress-destinations.yaml").read_text(encoding="utf-8"))
    assert egress["cloudflared_enabled"] is False
    tunnel_dest = next(item for item in egress["destinations"] if item["name"] == "cloudflared")
    assert tunnel_dest["enabled"] is False
    assert "region1.v2.argotunnel.com" in tunnel_dest["hosts"]


def test_open_webui_and_litellm_bind_loopback_not_a_tunnel():
    services = yaml.safe_load((ROOT / "deploy" / "services.yaml").read_text(encoding="utf-8"))
    assert services["runtime"] == "native"
    assert services["docker"] is False
    by_name = {app["name"]: app for app in services["apps"]}
    for name in ("open-webui", "litellm", "policy-gateway"):
        assert by_name[name]["bind"] == "127.0.0.1"
    for unit_name in ("open-webui.service", "litellm.service", "policy-gateway.service"):
        unit = (ROOT / "deploy" / "systemd" / unit_name).read_text(encoding="utf-8")
        assert "127.0.0.1" in unit
        assert "argotunnel" not in unit
        assert "trycloudflare" not in unit
        assert "cloudflared" not in unit.lower()
    caddy = (ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8")
    assert "reverse_proxy 127.0.0.1:8080" in caddy
    assert "webui.lan.internal" in caddy
    assert "cloudflare" not in caddy.lower()
    assert "argotunnel" not in caddy
    webui = (ROOT / "deploy" / "env" / "open-webui.env").read_text(encoding="utf-8")
    assert "OPENAI_API_BASE_URL=http://127.0.0.1:8088/v1" in webui
    assert "cloudflare" not in webui.lower()
    from scripts.check_tree import check

    assert check() == []
