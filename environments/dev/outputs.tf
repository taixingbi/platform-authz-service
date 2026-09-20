output "alb_dns_name" {
  description = "Internal ALB DNS name -- resolvable within the VPC, used directly as AUTHZ_SERVICE_URL by bedrock-gateway-infra's gateway-api task (no API Gateway in front). Once authz_service's Terraform lives only here, bedrock-gateway-infra looks this up via a data source (e.g. data \"aws_lb\" \"authz\" { name = \"gateway-dev-authz-alb\" }) rather than a module reference -- same loose-coupling convention as every other cross-repo lookup in this platform."
  value       = module.authz_service.alb_dns_name
}
