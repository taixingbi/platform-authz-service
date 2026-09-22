"""App factory + entrypoint for the authz-service (M12, plan section 5).

Wires dependencies (settings, attribute resolver, policy rules,
logging/tracing) and builds the app; the actual routes live in
api/routes.py's build_router() -- see that module's docstring for why
it's a factory too, not a plain module-level APIRouter.

Run locally:
    python -m services.authz.main

Run under uvicorn directly (what the Dockerfile does):
    uvicorn services.authz.main:app --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse

from .api.routes import build_router
from .attributes.cache import CachedIamTenantResolver
from .attributes.resolver import (
    DynamoDbIamTenantResolver,
    FileIamTenantResolver,
    IamTenantResolver,
    LayeredIamTenantResolver,
)
from .config import Settings, load_settings
from .policy.engine import PolicyRule, load_rules_from_yaml
from .telemetry.logging import configure_logging, get_logger
from .telemetry.otel import configure_tracing


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
                primary=CachedIamTenantResolver(
                    DynamoDbIamTenantResolver(
                        table_name=settings.provisioned_principal_mappings_table_name,
                        region=settings.aws_region,
                    ),
                    ttl_s=settings.principal_grant_cache_ttl_s,
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

    app.include_router(build_router(
        iam_tenant_resolver=iam_tenant_resolver,
        authz_rules=authz_rules,
        settings=settings,
        tracer=tracer,
        logger=logger,
    ))

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
