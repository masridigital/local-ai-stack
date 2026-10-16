"""REST API server for anonymizer.

Vendored from microsoft/presidio tag 2.2.362 (MIT).
Local changes: bind 127.0.0.1 unless BIND_HOST is set, refuse a wildcard bind
including IPv6 ``::``, keep werkzeug access logs at ERROR, and return a
generic error body. The process is started by gunicorn, not Flask's
development server.
"""
import logging
import os
import uuid
from logging.config import fileConfig
from pathlib import Path

from flask import Flask, Response, jsonify, request
from presidio_anonymizer import AnonymizerEngine, DeanonymizeEngine
from presidio_anonymizer.entities import InvalidParamError
from presidio_anonymizer.services.app_entities_convertor import AppEntitiesConvertor
from werkzeug.exceptions import BadRequest, HTTPException

DEFAULT_PORT = "3000"

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
    """Flask server for anonymizer."""

    def __init__(self):
        fileConfig(Path(Path(__file__).parent, LOGGING_CONF_FILE))
        self.logger = logging.getLogger("presidio-anonymizer")
        self.logger.setLevel(os.environ.get("LOG_LEVEL", self.logger.level))
        self.app = Flask(__name__)
        self.logger.info("Starting anonymizer engine")
        self.anonymizer = AnonymizerEngine()
        self.deanonymize = DeanonymizeEngine()
        self.logger.info(WELCOME_MESSAGE)

        @self.app.route("/health")
        def health() -> str:
            """Return basic health probe result."""
            return "Presidio Anonymizer service is up"

        @self.app.route("/anonymize", methods=["POST"])
        def anonymize() -> Response:
            content = request.get_json()
            if not content:
                raise BadRequest("Invalid request json")

            anonymizers_config = AppEntitiesConvertor.operators_config_from_json(
                content.get("anonymizers")
            )
            if AppEntitiesConvertor.check_custom_operator(anonymizers_config):
                raise BadRequest("Custom type anonymizer is not supported")

            analyzer_results = AppEntitiesConvertor.analyzer_results_from_json(
                content.get("analyzer_results")
            )
            anoymizer_result = self.anonymizer.anonymize(
                text=content.get("text", ""),
                analyzer_results=analyzer_results,
                operators=anonymizers_config,
            )
            return Response(anoymizer_result.to_json(), mimetype="application/json")

        @self.app.route("/deanonymize", methods=["POST"])
        def deanonymize() -> Response:
            content = request.get_json()
            if not content:
                raise BadRequest("Invalid request json")
            text = content.get("text", "")
            deanonymize_entities = AppEntitiesConvertor.deanonymize_entities_from_json(
                content
            )
            deanonymize_config = AppEntitiesConvertor.operators_config_from_json(
                content.get("deanonymizers")
            )
            deanonymized_response = self.deanonymize.deanonymize(
                text=text, entities=deanonymize_entities, operators=deanonymize_config
            )
            return Response(
                deanonymized_response.to_json(), mimetype="application/json"
            )

        @self.app.route("/anonymizers", methods=["GET"])
        def anonymizers():
            """Return a list of supported anonymizers."""
            return jsonify(self.anonymizer.get_anonymizers())

        @self.app.route("/deanonymizers", methods=["GET"])
        def deanonymizers():
            """Return a list of supported deanonymizers."""
            return jsonify(self.deanonymize.get_deanonymizers())

        @self.app.errorhandler(InvalidParamError)
        def invalid_param(err):
            return jsonify(_failure(self.logger, err)), 422

        @self.app.errorhandler(HTTPException)
        def http_exception(e):
            return jsonify(_failure(self.logger, e)), e.code

        @self.app.errorhandler(Exception)
        def server_error(e):
            return jsonify(_failure(self.logger, e)), 500

def create_app(): # noqa
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
