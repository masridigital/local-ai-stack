"""Forward a masked chat request to LiteLLM. The provider key never lives here."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from stack.errors import PolicyError


_DROPPED_IDENTITY = frozenset({"x-openwebui-user-name", "x-openwebui-user-email"})


class LiteLLMUpstream:
    def __init__(self, base_url: str, api_key: str, timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def complete(self, payload: dict, team_id: str | None = None) -> dict:
        forward = {key: value for key, value in payload.items() if not str(key).startswith("_")}
        if forward.get("stream") is True:
            raise PolicyError("streaming_disabled", "refusing to stream to LiteLLM")
        if not self.base_url.startswith(("http://", "https://")):
            raise PolicyError("upstream_invalid", "LiteLLM URL must be http or https", status=502)
        data = json.dumps(forward).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        if team_id:
            headers["x-litellm-team-id"] = team_id
        for name in list(headers):
            if name.lower() in _DROPPED_IDENTITY:
                del headers[name]
        request = urllib.request.Request(
            f"{self.base_url}/v1/chat/completions",
            data=data,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # nosec B310
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise PolicyError("upstream_rejected", "LiteLLM rejected the request", status=502) from exc
        except Exception as exc:
            raise PolicyError("upstream_unreachable", "LiteLLM unreachable", status=502) from exc
        if not isinstance(body, dict):
            raise PolicyError("upstream_invalid", "LiteLLM returned malformed json", status=502)
        return body
