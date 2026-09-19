"""App factory + entrypoint for the authz-service (M12, plan section 5).

Run locally:
    python -m services.authz.main

Run under uvicorn directly (what the Dockerfile does):
    uvicorn services.authz.main:app --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

import uuid
from typing import List, Optional

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from opentelemetry.propagate import extract
from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import Settings, load_settings
from .models import AuthorizeRequest, AuthorizeResponse
from .policy_engine import PolicyRule, evaluate, load_rules_from_yaml
from .resolver import AuthzError, DynamoDbIamTenantResolver, FileIamTenantResolver, IamTenantResolver, LayeredIamTenantResolver
from .telemetry.logging import configure_logging, get_logger, log_event, session_id_ctx
from .telemetry.otel import configure_tracing, set_span_attributes

# Identity-resolution failure has its own fixed policy id -- a
# genuinely different kind of decision from a policy_engine.py rule
# match (the principal isn't even mapped to a tenant yet, so there's
# no tenant_id/roles to evaluate rules against).
UNKNOWN_PRINCIPAL_POLICY_ID = "iam-principal-mapping-v1"


def create_app(
    settings: Optional[Settings] = None,
    iam_tenant_resolver: Optional[IamTenantResolver] = None,
    authz_rules: Optional[List[PolicyRule]] = None,
) -> FastAPI:
    settings = settings or load_settings()
    configure_logging(
        settings.service_name, settings.log_level, service=settings.service, environment=settings.environment
    )
    logger = get_logger(settings.service_name)
    tracer = configure_tracing(settings.service_name, otlp_endpoint=settings.otel_exporter_otlp_endpoint or None)

    if iam_tenant_resolver is None:
        file_resolver = FileIamTenantResolver(settings.iam_tenants_path)
        if settings.provisioned_principal_mappings_table_name:
            iam_tenant_resolver = LayeredIamTenantResolver(
                primary=DynamoDbIamTenantResolver(
                    table_name=settings.provisioned_principal_mappings_table_name,
                    region=settings.aws_region,
                ),
                fallback=file_resolver,
            )
        else:
            iam_tenant_resolver = file_resolver

    if authz_rules is None:
        authz_rules = load_rules_from_yaml(settings.authz_rules_path)

    app = FastAPI(title="Bedrock Authorization Service")
    app.state.settings = settings
    app.state.iam_tenant_resolver = iam_tenant_resolver

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    @app.post("/v1/authorize", response_model=AuthorizeResponse)
    async def authorize(body: AuthorizeRequest, request: Request) -> AuthorizeResponse:
        # Reuse the caller's request_id (HttpIamTenantResolver forwards
        # its own) so this decision log line correlates with the
        # gateway.chat/gateway.access lines for the SAME request, instead
        # of minting an unrelated ID every time.
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        # Never invented when absent (unlike request_id) -- a random
        # session_id wouldn't actually group anything. See
        # bedrock-gateway-app's telemetry/logging.py for the same
        # reasoning on its own session_id_ctx.
        session_id = request.headers.get("x-session-id") or ""
        # W3C traceparent, when gateway-api sent one (HttpIamTenantResolver
        # always does) -- makes this span a CHILD of the caller's span
        # (same trace_id), not the root of an unrelated trace.
        parent_context = extract(dict(request.headers))

        session_token = session_id_ctx.set(session_id)
        try:
            with tracer.start_as_current_span("authorize", context=parent_context) as span:
                set_span_attributes(
                    span, request_id=request_id, subject=body.identity.subject, action=body.action,
                    session_id=session_id or None,
                )
                try:
                    grant = iam_tenant_resolver.resolve(body.identity.subject)
                except AuthzError as exc:
                    log_event(
                        logger, "INFO", "authorize decision",
                        request_id=request_id,
                        subject=body.identity.subject,
                        action=body.action, policy_id=UNKNOWN_PRINCIPAL_POLICY_ID, decision="DENY",
                    )
                    set_span_attributes(span, decision="DENY", policy_id=UNKNOWN_PRINCIPAL_POLICY_ID)
                    return AuthorizeResponse(
                        decision="DENY", policy_id=UNKNOWN_PRINCIPAL_POLICY_ID, policy_version=1, reason=str(exc)
                    )

                # Plan section 35.4: real rule evaluation, not just "is
                # the principal known" -- resource/context only
                # actually influence anything for a caller that sends
                # them (see policy_engine.py's module docstring on
                # gateway-api's current call site not doing so yet).
                decision = evaluate(
                    authz_rules,
                    tenant_id=grant.tenant_id,
                    roles=grant.roles,
                    action=body.action,
                    resource_id=body.resource.id if body.resource else None,
                    context=body.context,
                )

                log_event(
                    logger, "INFO", "authorize decision",
                    request_id=request_id,
                    subject=body.identity.subject, tenant_id=grant.tenant_id, application_id=grant.application_id,
                    action=body.action, policy_id=decision.policy_id, policy_version=decision.policy_version,
                    decision=decision.decision,
                )
                set_span_attributes(
                    span, decision=decision.decision, tenant_id=grant.tenant_id,
                    application_id=grant.application_id, policy_id=decision.policy_id,
                    policy_version=decision.policy_version,
                )
                return AuthorizeResponse(
                    decision=decision.decision,
                    tenant_id=grant.tenant_id,
                    application_id=grant.application_id,
                    roles=grant.roles,
                    policy_id=decision.policy_id,
                    policy_version=decision.policy_version,
                    reason=decision.reason,
                )
        finally:
            session_id_ctx.reset(session_token)

    @app.get("/v1/grants")
    async def list_grants() -> dict:
        """Not part of the authorize contract -- lets bedrock-gateway-app's
        admin API (GET /v1/admin/applications) enumerate configured
        grants the same way it already does against a local
        IamTenantResolver, via HttpIamTenantResolver.list_grants()."""
        grants = iam_tenant_resolver.list_grants()
        return {
            "grants": {
                arn: {"tenant_id": g.tenant_id, "application_id": g.application_id, "roles": g.roles}
                for arn, g in grants.items()
            }
        }

    async def invalid_request_body(request: Request, exc: RequestValidationError) -> JSONResponse:
        first_error = exc.errors()[0]
        return JSONResponse(
            {"error": {"code": "INVALID_REQUEST", "message": first_error.get("msg", "invalid request")}},
            status_code=400,
        )

    app.add_exception_handler(RequestValidationError, invalid_request_body)
    return app


try:
    app = create_app()
except Exception:  # pragma: no cover - config-only failures at import time
    import traceback

    traceback.print_exc()
    app = None


if __name__ == "__main__":
    import uvicorn

    settings = load_settings()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port)
