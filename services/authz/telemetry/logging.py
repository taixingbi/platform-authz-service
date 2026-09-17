"""Structured JSON logging for authz-service.

Ported from bedrock-gateway-app's services/gateway/telemetry/logging.py --
same shape (one JSON object per line: ts -> level -> service -> environment
-> logger -> request_id -> trace_id -> span_id -> session_id ->
<event-specific fields> -> message -> error) so an authorize decision
here and a chat request log over there can be cross-referenced by
request_id/trace_id, and both services' log lines carry the same
service/environment identity fields for filtering across CloudWatch
log groups.

trace_id/span_id are pulled automatically from whatever OTel span is
current when the log call happens (telemetry/otel.py) -- omitted
entirely when there is none, never fabricated. session_id comes from
`session_id_ctx`, set by main.py's /v1/authorize handler from the
inbound X-Session-Id header (gateway-api's HttpIamTenantResolver
forwards its own) -- empty/absent when the caller didn't send one, no
invented value.
"""
from __future__ import annotations

import contextvars
import json
import logging
import sys
import time
from typing import Any, Optional

from opentelemetry import trace

_RESERVED_LOGRECORD_KEYS = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "taskName",
}

session_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("authz_session_id", default="")


class JsonFormatter(logging.Formatter):
    """Renders a LogRecord as one ordered JSON object per line."""

    def __init__(self, *, service: str = "", environment: str = "") -> None:
        super().__init__()
        self._service = service
        self._environment = environment

    def format(self, record: logging.LogRecord) -> str:
        extra = {
            k: v
            for k, v in record.__dict__.items()
            if k not in _RESERVED_LOGRECORD_KEYS and not k.startswith("_")
        }
        request_id = extra.pop("request_id", None)
        error = extra.pop("error", None)

        ordered: dict[str, Any] = {
            "ts": _iso_ts(record.created),
            "level": record.levelname,
            "service": self._service,
            "environment": self._environment,
            "logger": record.name,
            "request_id": request_id,
        }

        span_context = trace.get_current_span().get_span_context()
        if span_context.is_valid:
            ordered["trace_id"] = format(span_context.trace_id, "032x")
            ordered["span_id"] = format(span_context.span_id, "016x")

        session_id = session_id_ctx.get()
        if session_id:
            ordered["session_id"] = session_id

        ordered.update(extra)
        ordered["message"] = record.getMessage()
        if error is not None:
            ordered["error"] = error
        elif record.exc_info:
            ordered["error"] = self.formatException(record.exc_info)

        return json.dumps(ordered, default=str)


def _iso_ts(epoch_seconds: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(epoch_seconds)) + (
        f".{int((epoch_seconds % 1) * 1000):03d}Z"
    )


def configure_logging(
    service_name: str, level: str = "INFO", *, service: str = "", environment: str = ""
) -> None:
    """Configure the root logger to emit structured JSON on stdout.

    `service_name` names the logger whose level this sets -- unrelated
    to `service`/`environment`, the fixed identity fields stamped onto
    every emitted line (see module docstring).

    Idempotent -- safe to call more than once (e.g. once from app startup,
    once from a test fixture).
    """
    root = logging.getLogger()
    root.setLevel(level.upper())

    root.handlers = [h for h in root.handlers if not isinstance(h, _AuthzStreamHandler)]

    handler = _AuthzStreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service=service, environment=environment))
    root.addHandler(handler)

    logging.getLogger(service_name).setLevel(level.upper())


class _AuthzStreamHandler(logging.StreamHandler):
    """Marker subclass so configure_logging() can find/replace its own handler."""


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def log_event(
    logger: logging.Logger,
    level: str,
    message: str,
    *,
    request_id: Optional[str] = None,
    error: Optional[str] = None,
    **fields: Any,
) -> None:
    """Emit one structured log line.

    Example:
        log_event(
            logger, "INFO", "authorize decision",
            request_id=req_id, decision="ALLOW", tenant_id="finance",
            application_id="finance-manual-smoke-test", policy_id=POLICY_ID,
        )
    """
    log_fn = getattr(logger, level.lower(), logger.info)
    log_fn(message, extra={"request_id": request_id, "error": error, **fields})
