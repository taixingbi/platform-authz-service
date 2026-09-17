"""OpenTelemetry tracing for authz-service.

Ported from bedrock-gateway-app's services/gateway/telemetry/otel.py --
same shape (console exporter by default, OTLP HTTP when
OTEL_EXPORTER_OTLP_ENDPOINT is set) so both services' tracing setup and
CloudWatch output are identical.

`configure_tracing()` is idempotent, same convention as
telemetry/logging.py's configure_logging().

Unlike gateway-api, this service's own top-level span (see main.py's
`/v1/authorize` handler) is always a CHILD of the caller's span --
gateway-api's HttpIamTenantResolver injects a W3C traceparent header on
every call, which main.py extracts before starting the span, so both
services' spans land in the SAME trace instead of two unrelated ones.
"""
from __future__ import annotations

from typing import Any, Optional

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

_configured = False


def configure_tracing(service_name: str, *, otlp_endpoint: Optional[str] = None) -> trace.Tracer:
    global _configured
    if not _configured:
        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        if otlp_endpoint:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            exporter: Any = OTLPSpanExporter(endpoint=otlp_endpoint)
        else:
            # Same "one compact line per span" fix as bedrock-gateway-app's
            # otel.py -- the default formatter's ~30-line pretty-print
            # gets split by the awslogs driver into that many separate,
            # individually-useless CloudWatch events per span.
            exporter = ConsoleSpanExporter(formatter=lambda span: span.to_json(indent=None) + "\n")
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _configured = True
    return trace.get_tracer(service_name)


def set_span_attributes(span: trace.Span, **attributes: Any) -> None:
    """Sets only non-None attributes -- OTel attribute values can't be None."""
    for key, value in attributes.items():
        if value is not None:
            span.set_attribute(key, value)
