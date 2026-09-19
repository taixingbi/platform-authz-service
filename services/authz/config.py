"""Environment-driven configuration (M12). Same "config.py is the only
place that reads os.environ" convention as bedrock-gateway-app's
config.py.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return int(raw)


@dataclass(frozen=True)
class Settings:
    aws_region: str
    host: str
    port: int
    service_name: str
    log_level: str

    # Identity fields stamped onto every structured JSON log line -- see
    # telemetry/logging.py's module docstring. Distinct from
    # service_name, which names the logger to set the level on.
    service: str
    environment: str

    # Principal mapping (AWS_IAM/SigV4 path) -- same two-layer shape as
    # bedrock-gateway-app's LayeredIamTenantResolver: a file (hand-
    # configured, git/PR-reviewed) plus an optional DynamoDB overlay
    # for onboarding-provisioned grants (M11). Read-only here -- writes
    # stay owned by bedrock-gateway-app's onboarding/provisioning.py.
    iam_tenants_path: str
    provisioned_principal_mappings_table_name: str  # empty -> file-only

    # Plan section 35.4 -- versioned PDP rules. Empty/missing file
    # means no rules (every decision falls through to the
    # default-allow-known-principal behavior this service already had
    # before policy_engine.py existed).
    authz_rules_path: str

    # Empty -> ConsoleSpanExporter (dev default); set -> OTLP HTTP to a
    # real backend. Same "seam + fallback" shape as bedrock-gateway-app's
    # own config.py -- see telemetry/otel.py.
    otel_exporter_otlp_endpoint: str


def load_settings() -> Settings:
    return Settings(
        aws_region=os.environ.get("AWS_REGION", "us-east-1"),
        host=os.environ.get("AUTHZ_HOST", "0.0.0.0"),
        port=_env_int("AUTHZ_PORT", 8080),
        service_name=os.environ.get("SERVICE_NAME", "authz-service"),
        service=os.environ.get("SERVICE", "platform-authz-service"),
        environment=os.environ.get("ENVIRONMENT", "dev"),
        log_level=os.environ.get("LOG_LEVEL", "INFO"),
        iam_tenants_path=os.environ.get("IAM_TENANTS_PATH", "policies/iam_tenants.yaml"),
        provisioned_principal_mappings_table_name=os.environ.get(
            "PROVISIONED_PRINCIPAL_MAPPINGS_TABLE_NAME", ""
        ),
        authz_rules_path=os.environ.get("AUTHZ_RULES_PATH", "policies/authz_rules.yaml"),
        otel_exporter_otlp_endpoint=os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
    )
