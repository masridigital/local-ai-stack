"""REST API server for analyzer.

Vendored from microsoft/presidio tag 2.2.362 (MIT).
Local changes: bind 127.0.0.1 unless BIND_HOST is set, refuse a wildcard bind
including IPv6 ``::``, keep werkzeug access logs at ERROR, and return a
generic error body. The process is started by gunicorn, not Flask's
development server.
"""
import json
import logging
import os
import uuid
from logging.config import fileConfig
from pathlib import Path
from typing import Tuple

from flask import Flask, Response, jsonify, request
from presidio_analyzer import (
    AnalyzerEngine,
    AnalyzerEngineProvider,
    AnalyzerRequest,
    BatchAnalyzerEngine,
)
from werkzeug.exceptions import HTTPException

DEFAULT_PORT = "3000"
DEFAULT_BATCH_SIZE = "500"
DEFAULT_N_PROCESS = "1"

LOGGING_CONF_FILE = "logging.ini"

WELCOME_MESSAGE = r"""
 _______  _______  _______  _______ _________ ______  _________ _______
(  ____ )(  ____ )(  ____ \(  ____ \\__   __/(  __  \ \__   __/(  ___  )
| (    )|| (    )|| (    \/| (    \/   ) (   | (  \  )   ) (   | (   ) |
| (____)|| (____)|| (__    | (_____    | |   | |   ) |   | |   | |   | |
|  _____)|     __)|  __)   (_____  )   | |   | |   | |   | |   | |   | |
| (      | (\ (   | (            ) |   | |   | |   ) |   | |   | |   | |
| )      | ) \ \__| (____/\/\____) |___) (___| (__/  )___) (___| (___) |
|/       |/   \__/(_______/\_______)\_______/(______/ \_______/(_______)
"""


class Server:
    """HTTP Server for calling Presidio Analyzer."""

    def __init__(self):
        fileConfig(Path(Path(__file__).parent, LOGGING_CONF_FILE))
        self.logger = logging.getLogger("presidio-analyzer")
        self.logger.setLevel(os.environ.get("LOG_LEVEL", self.logger.level))
        self.app = Flask(__name__)

        analyzer_conf_file = os.environ.get("ANALYZER_CONF_FILE")
        nlp_engine_conf_file = os.environ.get("NLP_CONF_FILE")
        recognizer_registry_conf_file = os.environ.get("RECOGNIZER_REGISTRY_CONF_FILE")

        self.logger.info("Starting analyzer engine")
        self.engine: AnalyzerEngine = AnalyzerEngineProvider(
            analyzer_engine_conf_file=analyzer_conf_file,
            nlp_engine_conf_file=nlp_engine_conf_file,
            recognizer_registry_conf_file=recognizer_registry_conf_file,
        ).create_engine()

        self.batch_engine = BatchAnalyzerEngine(self.engine)
        self.logger.info(WELCOME_MESSAGE)

        @self.app.route("/health")
        def health() -> str:
            """Return basic health probe result."""
            return "Presidio Analyzer service is up"

        @self.app.route("/analyze", methods=["POST"])
        def analyze() -> Tuple[str, int]:
            """Execute the analyzer function."""
            # Parse the request params
            try:
                req_data = AnalyzerRequest(request.get_json())
                if not req_data.text:
                    raise Exception("No text provided")

                batch_request = isinstance(req_data.text, list)
                batch = req_data.text if batch_request else [req_data.text]

                if not req_data.language:
                    raise Exception("No language provided")
                else:
                    # Make sure the language is supported by the engine.
                    self.engine.get_supported_entities(req_data.language)

                iterator = self.batch_engine.analyze_iterator(
                    texts=batch,
                    batch_size=min(
                        len(batch),
                        int(os.environ.get("BATCH_SIZE", DEFAULT_BATCH_SIZE))
                    ),
                    language=req_data.language,
                    correlation_id=req_data.correlation_id,
                    score_threshold=req_data.score_threshold,
                    entities=req_data.entities,
                    return_decision_process=req_data.return_decision_process,
                    ad_hoc_recognizers=req_data.ad_hoc_recognizers,
                    context=req_data.context,
                    allow_list=req_data.allow_list,
                    allow_list_match=req_data.allow_list_match,
                    regex_flags=req_data.regex_flags,
                    n_process=min(
                        len(batch),
                        int(os.environ.get("N_PROCESS", DEFAULT_N_PROCESS))
                    )
                )
                results = []
                for recognizer_result_list in iterator:
                    _exclude_attributes_from_dto(recognizer_result_list)
                    results.append(recognizer_result_list)

                return Response(
                    json.dumps(
                        results if batch_request else results[0],
                        default=lambda o: o.to_dict(),
                        sort_keys=True,
                    ),
                    content_type="application/json",
                )
            except TypeError as te:
                return jsonify(_failure(self.logger, te)), 400

            except Exception as e:
                return jsonify(_failure(self.logger, e)), 500

        @self.app.route("/recognizers", methods=["GET"])
        def recognizers() -> Tuple[str, int]:
            """Return a list of supported recognizers."""
            language = request.args.get("language")
            try:
                recognizers_list = self.engine.get_recognizers(language)
                names = [o.name for o in recognizers_list]
                return jsonify(names), 200
            except Exception as e:
                return jsonify(_failure(self.logger, e)), 500

        @self.app.route("/supportedentities", methods=["GET"])
        def supported_entities() -> Tuple[str, int]:
            """Return a list of supported entities."""
            language = request.args.get("language")
            try:
                entities_list = self.engine.get_supported_entities(language)
                return jsonify(entities_list), 200
            except Exception as e:
                return jsonify(_failure(self.logger, e)), 500

        @self.app.errorhandler(HTTPException)
        def http_exception(e):
            return jsonify(_failure(self.logger, e)), e.code


def _exclude_attributes_from_dto(recognizer_result_list):
    excluded_attributes = [
        "recognition_metadata",
    ]
    for result in recognizer_result_list:
        for attr in excluded_attributes:
            if hasattr(result, attr):
                delattr(result, attr)


def create_app():  # noqa: D103
    server = Server()
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    return server.app


def _failure(logger: logging.Logger, exc: BaseException) -> dict:
    """Log the class name and a request id. Never log or return exc text."""
    request_id = uuid.uuid4().hex
    logger.error("request failed request_id=%s exception=%s", request_id, type(exc).__name__)
    return {"error": "request failed", "request_id": request_id}


def _bind_host() -> str:
    host = os.environ.get("BIND_HOST", "127.0.0.1").strip()
    if not host or host.startswith("0.") or host.startswith("::") or host.startswith("[::"):
        raise SystemExit("refusing wildcard bind")
    return host


def main() -> None:
    raise SystemExit("refusing the Flask development server; use the gunicorn unit")


if __name__ == "__main__":
    main()
