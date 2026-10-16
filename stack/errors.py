"""Errors returned to clients. Messages must not echo prompt or response text."""


class PolicyError(Exception):
    def __init__(self, code: str, message: str, status: int = 403):
        self.code = code
        self.message = message
        self.status = status
        super().__init__(message)


class PresidioUnavailable(PolicyError):
    def __init__(self, message: str = "presidio unavailable"):
        super().__init__("presidio_unavailable", message, status=503)
