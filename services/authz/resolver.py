"""Principal mapping (M12): maps a verified AWS_IAM principal ARN to
the tenant_id/application_id/roles it should have -- the extracted
half of bedrock-gateway-app's auth/aws_iam.py (FileIamTenantResolver +
DynamoDbIamTenantResolver + LayeredIamTenantResolver), ported here
read-only. Signature verification (SigV4, done by API Gateway; JWT,
done by bedrock-gateway-app itself) never happens here -- this module
only maps an already-trusted identity to a policy decision.

Read-only, deliberately: onboarding-provisioned grants (M11) are
written by bedrock-gateway-app's onboarding/provisioning.py into the
same DynamoDB table this reads from. Two services writing to the same
table would be a real consistency hazard; one writes, both read.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Protocol

import yaml


class AuthzError(Exception):
    """Raised when a principal cannot be resolved. `code` maps to the
    public error body, same convention as bedrock-gateway-app's
    AuthError."""

    def __init__(self, message: str, *, code: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class IamPrincipalGrant:
    tenant_id: str
    application_id: str
    roles: List[str] = field(default_factory=list)


class IamTenantResolver(Protocol):
    def resolve(self, principal_arn: str) -> IamPrincipalGrant:
        """Raises AuthzError(code="UNKNOWN_IAM_PRINCIPAL") if unmapped."""
        ...

    def list_grants(self) -> Dict[str, IamPrincipalGrant]:
        ...


class FileIamTenantResolver:
    """Loads `policies/iam_tenants.yaml`'s `iam_principals` map once at
    startup -- identical matching semantics to bedrock-gateway-app's
    resolver of the same name (exact ARN wins; a "*"-suffixed pattern
    matches any ARN sharing that prefix, for assumed-role session-name
    wildcards)."""

    def __init__(self, path: str):
        self._exact: Dict[str, IamPrincipalGrant] = {}
        self._prefixes: Dict[str, IamPrincipalGrant] = {}

        if not path or not os.path.exists(path):
            return

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        for arn_pattern, entry in (data.get("iam_principals") or {}).items():
            grant = IamPrincipalGrant(
                tenant_id=entry["tenant_id"],
                application_id=entry["application_id"],
                roles=list(entry.get("roles") or []),
            )
            if arn_pattern.endswith("*"):
                self._prefixes[arn_pattern[:-1]] = grant
            else:
                self._exact[arn_pattern] = grant

    def resolve(self, principal_arn: str) -> IamPrincipalGrant:
        grant = self._exact.get(principal_arn)
        if grant is not None:
            return grant

        for prefix, candidate in self._prefixes.items():
            if principal_arn.startswith(prefix):
                return candidate

        raise AuthzError(
            f"no tenant mapping for IAM principal '{principal_arn}'", code="UNKNOWN_IAM_PRINCIPAL"
        )

    def list_grants(self) -> Dict[str, IamPrincipalGrant]:
        merged: Dict[str, IamPrincipalGrant] = dict(self._exact)
        merged.update({f"{prefix}*": grant for prefix, grant in self._prefixes.items()})
        return merged


class DynamoDbIamTenantResolver:
    """Read-only view of the same `provisioned-principal-mappings`
    table bedrock-gateway-app's onboarding/provisioning.py writes to
    (M11) -- see this module's docstring for why it's read-only here."""

    def __init__(self, *, table_name: str, region: str):
        import boto3

        self._table = boto3.resource("dynamodb", region_name=region).Table(table_name)

    def resolve(self, principal_arn: str) -> IamPrincipalGrant:
        response = self._table.get_item(Key={"principal_arn": principal_arn})
        item = response.get("Item")
        if item is None:
            raise AuthzError(
                f"no tenant mapping for IAM principal '{principal_arn}'", code="UNKNOWN_IAM_PRINCIPAL"
            )
        return IamPrincipalGrant(
            tenant_id=item["tenant_id"],
            application_id=item["application_id"],
            roles=list(item.get("roles", [])),
        )

    def list_grants(self) -> Dict[str, IamPrincipalGrant]:
        merged: Dict[str, IamPrincipalGrant] = {}
        kwargs: Dict[str, object] = {}
        while True:
            response = self._table.scan(**kwargs)
            for item in response.get("Items", []):
                merged[item["principal_arn"]] = IamPrincipalGrant(
                    tenant_id=item["tenant_id"],
                    application_id=item["application_id"],
                    roles=list(item.get("roles", [])),
                )
            if "LastEvaluatedKey" not in response:
                break
            kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
        return merged


class LayeredIamTenantResolver:
    """DynamoDB (onboarding-provisioned) checked first, file (hand-
    configured) second -- same layering as bedrock-gateway-app's
    resolver of the same name."""

    def __init__(self, *, primary: IamTenantResolver, fallback: IamTenantResolver):
        self._primary = primary
        self._fallback = fallback

    def resolve(self, principal_arn: str) -> IamPrincipalGrant:
        try:
            return self._primary.resolve(principal_arn)
        except AuthzError:
            return self._fallback.resolve(principal_arn)

    def list_grants(self) -> Dict[str, IamPrincipalGrant]:
        merged = dict(self._fallback.list_grants())
        merged.update(self._primary.list_grants())
        return merged
