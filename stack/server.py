"""Small HTTP front for the policy gateway. Binds to loopback unless BIND_HOST is set."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from stack.audit import AuditLog, PostgresAudit
from stack.errors import PolicyError
from stack.masking import load_recognizers
from stack.pipeline import handle_chat, record_config_change
from stack.upstream import LiteLLMUpstream
from stack.policy import FoundryRuntime, load_policy
from stack.presidio_client import PresidioClient


ROOT = Path(os.environ.get("STACK_ROOT", "/app"))


def build_deps():
    policy_path = Path(os.environ.get("POLICY_PATH", ROOT / "litellm" / "policy.yaml"))
    recognizer_dir = Path(os.environ.get("RECOGNIZER_DIR", ROOT / "presidio" / "recognizers"))
    runtime = {
        "anthropic_baa_enabled": os.environ.get("ANTHROPIC_BAA_ENABLED", "false").lower() == "true",
        "azure_ai_enabled": os.environ.get("ALLOW_AZURE_AI_THIRD_PARTY", "false").lower() == "true",
        "abuse_monitoring_opt_out": os.environ.get("FOUNDRY_ABUSE_MONITORING_OPT_OUT", "false").lower() == "true",
    }
    policy = load_policy(policy_path, runtime)
    recognizers = load_recognizers(recognizer_dir)
    dsn_file = os.environ.get("AUDIT_DATABASE_URL_FILE", "")
    if dsn_file:
        audit = PostgresAudit(Path(dsn_file).read_text(encoding="utf-8").strip(), recognizers, policy.mask_score_threshold)
    else:
        audit = AuditLog(
            Path(os.environ.get("AUDIT_SQLITE_PATH", "/var/lib/local-ai-stack/audit.db")),
            recognizers,
            policy.mask_score_threshold,
        )
    record_config_change(audit, policy, os.environ.get("CONFIG_ACTOR", "system:deploy"), policy_path.read_bytes())
    presidio = PresidioClient(
        os.environ["PRESIDIO_ANALYZER_API_BASE"],
        os.environ["PRESIDIO_ANONYMIZER_API_BASE"],
        timeout=float(os.environ.get("PRESIDIO_TIMEOUT", "5")),
        recognizers=recognizers,
        threshold=policy.mask_score_threshold,
    )
    foundry = FoundryRuntime(
        deployment=os.environ.get("AZURE_OPENAI_DEPLOYMENT", ""),
        model_family=os.environ.get("AZURE_OPENAI_MODEL_FAMILY", ""),
        region=os.environ.get("AZURE_OPENAI_REGION", ""),
        api_base=os.environ.get("AZURE_API_BASE", ""),
    )
    return policy, foundry, presidio, audit


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802
        if self.path.split("?", 1)[0] in {"/health", "/health/liveliness", "/health/readiness"}:
            self._send(200, {"status": "ok"})
            return
        self._send(403, {"error": {"code": "route_disabled", "message": "route is not enabled"}})

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._send(400, {"error": {"code": "invalid_json", "message": "request body must be json"}})
            return
        policy, foundry, presidio, audit = self.server.deps  # type: ignore[attr-defined]
        user_id = self.headers.get("X-OpenWebUI-User-Id")
        headers = {key: value for key, value in self.headers.items()}
        try:
            result = handle_chat(
                path=self.path.split("?", 1)[0],
                headers=headers,
                body=body,
                user_id=user_id,
                policy=policy,
                foundry=foundry,
                presidio=presidio,
                upstream=self.server.upstream,  # type: ignore[attr-defined]
                audit=audit,
            )
        except PolicyError as exc:
            self._send(exc.status, {"error": {"code": exc.code, "message": exc.message}})
            return
        self._send(result.status, result.body)

    def log_message(self, fmt: str, *args) -> None:
        # Access logs stay free of request bodies. BaseHTTPRequestHandler would
        # otherwise write the request line only, which is still more than we need.
        return

    def _send(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def bind_address() -> str:
    host = os.environ.get("BIND_HOST", "127.0.0.1")
    if not host or host.startswith("0."):
        raise SystemExit("refusing wildcard bind")
    return host


def main() -> None:
    policy, foundry, presidio, audit = build_deps()
    server = ThreadingHTTPServer((bind_address(), int(os.environ.get("GATEWAY_PORT", "8088"))), Handler)
    server.deps = (policy, foundry, presidio, audit)  # type: ignore[attr-defined]
    key_path = os.environ.get("LITELLM_API_KEY_FILE", "")
    api_key = Path(key_path).read_text(encoding="utf-8").strip() if key_path else os.environ.get("LITELLM_API_KEY", "")
    server.upstream = LiteLLMUpstream(os.environ["LITELLM_BASE_URL"], api_key)  # type: ignore[attr-defined]
    server.serve_forever()


if __name__ == "__main__":
    main()
