"""Create a non-admin LiteLLM virtual key for the policy gateway.

The key is limited to the model names Open WebUI sends. It is not the master
key and it is not a wildcard. The secret is written to a 0600 file and is not
printed.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

GATEWAY_MODELS = ("claude-sonnet", "claude-haiku", "claude-opus", "foundry-gpt")
FOUNDRY_ONLY = ("foundry-gpt",)


def models_for(baa_enabled: bool) -> list[str]:
    if baa_enabled:
        return list(GATEWAY_MODELS)
    return list(FOUNDRY_ONLY)


def request_body(baa_enabled: bool) -> dict:
    models = models_for(baa_enabled)
    if "*" in models or not models:
        raise SystemExit("refusing an unscoped virtual key")
    return {"models": models, "key_alias": "policy-gateway"}


def write_key(dest: Path, key: str) -> None:
    if not key or "\n" in key or "\x00" in key:
        raise SystemExit("LiteLLM returned an empty key")
    dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    tmp.write_text(key, encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, dest)
    os.chmod(dest, 0o600)


def fetch_key(base_url: str, master_key: str, baa_enabled: bool, timeout: float = 10.0) -> str:
    payload = json.dumps(request_body(baa_enabled)).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/key/generate",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {master_key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
        body = json.loads(response.read().decode("utf-8"))
    key = body.get("key") or (body.get("info") or {}).get("token") or ""
    if not isinstance(key, str):
        raise SystemExit("LiteLLM key response was not a string")
    return key


def main() -> None:
    dest = Path(os.environ.get("VIRTUAL_KEY_DEST", "/etc/policy-gateway/litellm_virtual_key"))
    master_path = Path(os.environ.get("LITELLM_MASTER_KEY_FILE", "/etc/litellm/litellm_master_key"))
    base_url = os.environ.get("LITELLM_BASE_URL", "http://127.0.0.2:4000")
    baa = os.environ.get("ANTHROPIC_BAA_ENABLED", "false") == "true"
    if dest.is_file() and os.environ.get("SCOPE_VIRTUAL_KEY_FORCE", "") != "1":
        print("virtual key already present")
        return
    master = master_path.read_text(encoding="utf-8").strip()
    if not master:
        raise SystemExit("master key file is empty")
    key = fetch_key(base_url, master, baa)
    write_key(dest, key)
    print("virtual key written")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print("virtual key was not written", file=sys.stderr)
        raise SystemExit(1) from exc
