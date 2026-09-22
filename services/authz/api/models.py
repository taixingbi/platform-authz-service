"""POST /v1/authorize request/response shapes (M12, plan section 5.2)."""
from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class Identity(BaseModel):
    subject: str = Field(min_length=1, description="IAM principal ARN.")
    auth_type: Literal["aws_iam"] = Field(
        description=(
            "Only 'aws_iam' is implemented (M12 MVP scope, plan section 5.3) -- the "
            "JWT/OIDC path's tenant/application/roles already come from the token's own "
            "claims (bedrock-runtime-gateway-app's identity_from_claims), so there is no separate "
            "principal-mapping lookup for it to extract yet."
        ),
    )


class Resource(BaseModel):
    type: str = "model"
    id: str = "*"


class AuthorizeRequest(BaseModel):
    identity: Identity
    action: str = Field(min_length=1)
    resource: Optional[Resource] = None
    context: dict = Field(default_factory=dict)


class AuthorizeResponse(BaseModel):
    decision: Literal["ALLOW", "DENY"]
    tenant_id: Optional[str] = None
    application_id: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    policy_id: str
    # Plan section 35.4 -- which version of `policy_id`'s rule produced
    # this decision (services/authz/policy/engine.py's PolicyRule.version).
    # 1 for the fixed identity-resolution policies (principal unknown,
    # default-allow-known-principal) that predate real rule versioning.
    policy_version: int = 1
    reason: str
