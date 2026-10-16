"""Open WebUI and LiteLLM have no Cloudflare Tunnel route.

Cap declined a Cloudflare BAA. Main does not ship cloudflared.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_cloudflared_is_not_shipped():
    assert not (ROOT / "deploy" / "cloudflared").exists()
    assert not (ROOT / "deploy" / "systemd" / "cloudflared.service").exists()
    assert not (ROOT / "ansible" / "roles" / "cloudflared").exists()
    install = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    assert "apt-get remove -y cloudflared" in install
    assert "systemctl disable --now cloudflared.service" in install
    assert "rm -rf /etc/cloudflared" in install
    assert "systemctl enable cloudflared" not in install
    egress = yaml.safe_load((ROOT / "deploy" / "egress-destinations.yaml").read_text(encoding="utf-8"))
    assert "cloudflared_enabled" not in egress
    assert all(item.get("name") != "cloudflared" for item in egress["destinations"])
    from scripts.check_tree import check

    assert check() == []


def test_open_webui_and_litellm_bind_loopback_not_a_tunnel():
    services = yaml.safe_load((ROOT / "deploy" / "services.yaml").read_text(encoding="utf-8"))
    assert services["runtime"] == "native"
    assert services["docker"] is False
    by_name = {app["name"]: app for app in services["apps"]}
    assert by_name["litellm"]["bind"] == "127.0.0.2"
    assert by_name["open-webui"]["bind"] == "127.0.0.1"
    assert by_name["policy-gateway"]["bind"] == "127.0.0.1"
    litellm = (ROOT / "deploy" / "systemd" / "litellm.service").read_text(encoding="utf-8")
    assert "BIND_HOST=127.0.0.2" in litellm
    webui_unit = (ROOT / "deploy" / "systemd" / "open-webui.service").read_text(encoding="utf-8")
    gateway = (ROOT / "deploy" / "systemd" / "policy-gateway.service").read_text(encoding="utf-8")
    for unit in (litellm, webui_unit, gateway):
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
    assert ":4000" not in webui
    assert "cloudflare" not in webui.lower()
