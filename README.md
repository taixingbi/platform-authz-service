# platform-authz-service

M12 for the [bedrock-gateway](../bedrock-runtime-gateway-app) platform (see
`plan.md` Section 5). A standalone authorization service (PDP —
policy decision point), called internally over HTTP by
`bedrock-runtime-gateway-app` (the PEP — policy enforcement point), separating
"is this caller allowed to do this" from "verify who this caller is"
and "actually do it".

## Scope (M12 MVP)

Only the AWS_IAM/SigV4 path's principal mapping is extracted here —
matching this milestone's own scoped-down plan (plan.md Section 5.3).
The JWT/OIDC path's tenant_id/application_id/roles already come from
the verified token's own claims (`bedrock-runtime-gateway-app`'s
`identity_from_claims`) — there's no separate mapping lookup to
extract for it yet, so `POST /v1/authorize` only accepts
`auth_type: "aws_iam"`.

Real versioned rule evaluation now exists (`services/authz/
policy_engine.py`, plan section 35.4): a priority-ordered list of
`PolicyRule`s (each with `action`, `tenant_id`, `roles_any_of`,
`denied_resource_ids`, `max_data_classification`, `priority`),
first-match-wins, loaded from `policies/authz_rules.yaml`. A resolved,
known principal whose request matches no rule falls through to a
configurable default -- `default-allow-known-principal-v1` (the
migration-friendly default) or, when `AUTHZ_DEFAULT_ALLOW=false` (a
regulated production environment, plan section 35.17),
`default-deny-no-matching-rule-v1` instead: "known identity" and
"authorized identity" are not the same thing, and an unmatched
request in prod should be denied, not silently allowed through a
default nobody explicitly wrote. `bedrock-runtime-gateway-app`'s own gateway
now makes a real, resource/context-carrying call into this engine
after the requested model is resolved (plan section 35.16), not just
the identity-only call at authentication time -- so `resource`/
`context`-scoped rules fire against real traffic, not only this
service's own tests.

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
  "policy_id": "default-allow-known-principal-v1",
  "policy_version": 1,
  "reason": "no matching rule -- default allow for a known principal"
}
```

`policy_id` names whichever rule (or default) actually produced the
decision: a custom rule's own id, `default-allow-known-principal-v1`
/ `default-deny-no-matching-rule-v1` for the no-match fallback (see
above), or `iam-principal-mapping-v1` specifically for the "principal
isn't mapped to a tenant at all" case -- a genuinely different kind
of decision from a policy-engine rule match, since there's no
tenant_id/roles yet to evaluate rules against.

`GET /v1/grants` — every configured principal -> grant (file +
onboarding-provisioned DynamoDB, if configured), for
`bedrock-runtime-gateway-app`'s admin API to enumerate the same way it already
does against a local resolver.

## Local development

```bash
./scripts/sync-policies.sh   # pulls policies/iam_tenants.yaml from a sibling platform-policy-definitions checkout
poetry install --with dev
poetry run python -m services.authz.main
poetry run python -m unittest discover -s services/authz/tests -t .
```

## Infra & CI

This repo owns two independent Terraform roots, each with its own
state and its own `fmt-validate`/`plan`/`apply-dev` CI jobs
(`.github/workflows/terraform.yml`, `dev` auto-applies on every push
to `main`, matching every other repo in this platform):

- `environments/dev/` — the real ECS/ALB service, security groups, and
  ACM cert (issued from `platform-foundation`'s shared Private CA).
- `ci_identity/` — this repo's own GitHub Actions IAM roles
  (`gha-authz-deploy-dev`/`-prod`, `gha-authz-infra-plan`,
  `gha-authz-infra-apply-dev`). Added 2026-09-21 as part of a
  platform-wide Terraform-ownership migration: these roles used to be
  defined centrally in `platform-foundation`, moved here via
  `terraform import` (never deleted/recreated, so the ARNs and this
  repo's own GitHub Environment variables never changed). `gha-authz-
  infra-apply-dev`'s own policy is scoped to manage only
  `gha-authz-*`-named roles (including itself) -- it can't touch any
  other repo's roles.

## First deploy's real gotcha: ECR immutable tags + partial failure

The very first "Deploy to dev" run failed on `iam:PassRole` (the
deploy role could pass the ECS execution role but not the task role —
fixed in `bedrock-runtime-gateway-infra`'s `environments/global`). The image
had already built and pushed successfully *before* that failure, so
re-running the same CI job hit ECR's immutable-tag protection:
`tag invalid: ... already exists ... and cannot be overwritten`
(`modules/ecr`'s lifecycle policy only expires `sha-*`-tagged images,
it doesn't make them mutable). CI can't recover from this on its own —
re-running always tries to rebuild+push the same commit's tag.

Fixed by hand: `aws ecs register-task-definition` combining the
already-pushed image with the (by-then-fixed) task definition's real
env vars, then `aws ecs update-service` to roll it out — the same
"the artifact already exists, just point the service at it" recovery
`bedrock-runtime-gateway-app` and `bedrock-gateway-portal` needed for similar
mid-flight infra races earlier in this platform's history. If a
deploy ever fails *after* the image push step, don't just re-run the
job — check whether the image already exists in ECR first.

## Integration with bedrock-runtime-gateway-app

`bedrock-runtime-gateway-app`'s `auth/aws_iam.py` gets a new
`HttpIamTenantResolver` implementing the exact same `IamTenantResolver`
Protocol `FileIamTenantResolver`/`DynamoDbIamTenantResolver`/
`LayeredIamTenantResolver` already satisfy — wired in at `main.py`
when `AUTHZ_SERVICE_URL` is configured, falling back to the existing
in-process resolvers otherwise. No route handler or pipeline stage
changes: this is a drop-in swap behind an existing seam, not a rewrite
of the request path.
