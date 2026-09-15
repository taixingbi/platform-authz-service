# bedrock-authz-service

M12 for the [bedrock-gateway](../bedrock-gateway-app) platform (see
`plan.md` Section 5). A standalone authorization service (PDP —
policy decision point), called internally over HTTP by
`bedrock-gateway-app` (the PEP — policy enforcement point), separating
"is this caller allowed to do this" from "verify who this caller is"
and "actually do it".

## Scope (M12 MVP)

Only the AWS_IAM/SigV4 path's principal mapping is extracted here —
matching this milestone's own scoped-down plan (plan.md Section 5.3).
The JWT/OIDC path's tenant_id/application_id/roles already come from
the verified token's own claims (`bedrock-gateway-app`'s
`identity_from_claims`) — there's no separate mapping lookup to
extract for it yet, so `POST /v1/authorize` only accepts
`auth_type: "aws_iam"`.

There is no real ABAC or policy-engine logic here beyond "is this
principal known" — this platform has no ABAC rules anywhere today to
port, and this service doesn't fabricate any. `policy_id` in every
response names the actual rule applied (`iam-principal-mapping-v1`),
not a placeholder for rules that don't exist.

## API

```
POST /v1/authorize
{
  "identity": { "subject": "arn:aws:iam::...:role/x", "auth_type": "aws_iam" },
  "action": "llm.invoke",
  "resource": { "type": "model", "id": "*" },
  "context": {}
}
```

```json
{
  "decision": "ALLOW",
  "tenant_id": "search",
  "application_id": "search-dev",
  "roles": ["developer"],
  "policy_id": "iam-principal-mapping-v1",
  "reason": "principal is mapped"
}
```

`GET /v1/grants` — every configured principal -> grant (file +
onboarding-provisioned DynamoDB, if configured), for
`bedrock-gateway-app`'s admin API to enumerate the same way it already
does against a local resolver.

## Local development

```bash
./scripts/sync-policies.sh   # pulls policies/iam_tenants.yaml from a sibling bedrock-gateway-policies checkout
poetry install --with dev
poetry run python -m services.authz.main
poetry run python -m unittest discover -s services/authz/tests -t .
```

## Integration with bedrock-gateway-app

`bedrock-gateway-app`'s `auth/aws_iam.py` gets a new
`HttpIamTenantResolver` implementing the exact same `IamTenantResolver`
Protocol `FileIamTenantResolver`/`DynamoDbIamTenantResolver`/
`LayeredIamTenantResolver` already satisfy — wired in at `main.py`
when `AUTHZ_SERVICE_URL` is configured, falling back to the existing
in-process resolvers otherwise. No route handler or pipeline stage
changes: this is a drop-in swap behind an existing seam, not a rewrite
of the request path.
