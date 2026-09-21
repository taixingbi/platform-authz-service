output "role_arns" {
  description = "Set as AWS_AUTHZ_DEPLOY_ROLE_ARN_DEV / _PROD, AWS_AUTHZ_INFRA_PLAN_ROLE_ARN, AWS_AUTHZ_INFRA_APPLY_DEV_ROLE_ARN in this repo's own GitHub Environment variables -- unchanged from before this migration."
  value       = module.github_oidc.role_arns
}
