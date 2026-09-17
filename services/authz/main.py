"""App factory + entrypoint for the authz-service (M12, plan section 5).

Run locally:
    python -m services.authz.main

Run under uvicorn directly (what the Dockerfile does):
    uvicorn services.authz.main:app --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import Settings, load_settings
from .models import AuthorizeRequest, AuthorizeResponse
from .resolver import AuthzError, DynamoDbIamTenantResolver, FileIamTenantResolver, IamTenantResolver, LayeredIamTenantResolver
from .telemetry.logging import configure_logging, get_logger, log_event

# The one real rule this MVP enforces: is the principal known at all.
# ABAC / a real policy engine (Section 5.1's "policy engine" box) is
# intentionally NOT faked here -- there are no ABAC rules anywhere in
# this platform today to port, and claiming otherwise would be
# dishonest. This is the same "scope down, don't fabricate" call M9
# made for canary/rollback.
POLICY_ID = "iam-principal-mapping-v1"


def create_app(settings: Optional[Settings] = None, iam_tenant_resolver: Optional[IamTenantResolver] = None) -> FastAPI:
    settings = settings or load_settings()
    configure_logging(
        settings.service_name, settings.log_level, service=settings.service, environment=settings.environment
    )
    logger = get_logger(settings.service_name)

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
        try:
            grant = iam_tenant_resolver.resolve(body.identity.subject)
        except AuthzError as exc:
            log_event(
                logger, "INFO", "authorize decision",
                request_id=request_id, decision="DENY", subject=body.identity.subject,
                action=body.action, policy_id=POLICY_ID,
            )
            return AuthorizeResponse(decision="DENY", policy_id=POLICY_ID, reason=str(exc))

        log_event(
            logger, "INFO", "authorize decision",
            request_id=request_id, decision="ALLOW", subject=body.identity.subject,
            action=body.action, tenant_id=grant.tenant_id, application_id=grant.application_id,
            policy_id=POLICY_ID,
        )
        return AuthorizeResponse(
            decision="ALLOW",
            tenant_id=grant.tenant_id,
            application_id=grant.application_id,
            roles=grant.roles,
            policy_id=POLICY_ID,
            reason="principal is mapped",
        )

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
