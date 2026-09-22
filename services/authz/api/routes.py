"""HTTP routes for the authz-service's own API surface (the PDP's
exposed contract -- the PEP is whatever calls this service, e.g.
bedrock-runtime-gateway's HttpIamTenantResolver or
platform-control-plane's admin routes, not this service itself).

Handlers are built by `build_router()`, not defined at module scope,
because each one closes over its call's `iam_tenant_resolver`/
`authz_rules`/`settings`/`tracer`/`logger` -- the same dependency-
injection shape `main.create_app()` already used before this file
existed (settings/resolver/rules passed in directly, no FastAPI
`Depends()` indirection), just moved one level down so `main.py` only
wires dependencies instead of also defining routes.
"""
from __future__ import annotations

import uuid
from typing import List

from fastapi import APIRouter, Request
from opentelemetry.propagate import extract

from ..attributes.resolver import AuthzError, IamTenantResolver
from ..config import Settings
from ..policy.engine import PolicyRule, evaluate
from ..telemetry.logging import log_event, session_id_ctx
from ..telemetry.otel import set_span_attributes
from .models import AuthorizeRequest, AuthorizeResponse

# Identity-resolution failure has its own fixed policy id -- a
# genuinely different kind of decision from a policy/engine.py rule
# match (the principal isn't even mapped to a tenant yet, so there's
# no tenant_id/roles to evaluate rules against).
UNKNOWN_PRINCIPAL_POLICY_ID = "iam-principal-mapping-v1"


def build_router(
    *,
    iam_tenant_resolver: IamTenantResolver,
    authz_rules: List[PolicyRule],
    settings: Settings,
    tracer,
    logger,
) -> APIRouter:
    router = APIRouter()

    @router.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    @router.post("/v1/authorize", response_model=AuthorizeResponse)
    async def authorize(body: AuthorizeRequest, request: Request) -> AuthorizeResponse:
        # Reuse the caller's request_id (HttpIamTenantResolver forwards
        # its own) so this decision log line correlates with the
        # gateway.chat/gateway.access lines for the SAME request, instead
        # of minting an unrelated ID every time.
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        # Never invented when absent (unlike request_id) -- a random
        # session_id wouldn't actually group anything. See
        # bedrock-runtime-gateway-app's telemetry/logging.py for the same
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
                # them (see policy/engine.py's module docstring on
                # gateway-api's current call site not doing so yet).
                decision = evaluate(
                    authz_rules,
                    tenant_id=grant.tenant_id,
                    roles=grant.roles,
                    action=body.action,
                    resource_id=body.resource.id if body.resource else None,
                    context=body.context,
                    default_allow=settings.default_allow_unmatched,
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

    @router.get("/v1/grants")
    async def list_grants() -> dict:
        """Not part of the authorize contract -- lets bedrock-runtime-gateway-app's
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

    return router
