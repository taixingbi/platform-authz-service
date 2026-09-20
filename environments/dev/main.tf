terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

locals {
  name_prefix = "gateway-dev-authz"
}

# --- Cross-repo lookups (plan section 36) ----------------------------------
#
# Deliberately loose coupling to bedrock-gateway-infra, matching the
# EXACT convention platform-api-gateway's own environments/dev/main.tf
# already established: name-based data source lookups, not
# `terraform_remote_state`, not resource duplication. bedrock-gateway-
# infra keeps owning every genuinely shared resource (the VPC, the
# private CA, the ops_alerts SNS topic, cross-service DynamoDB
# tables); this repo only ever reads them, never manages their
# lifecycle.

# VPC/subnets are derived from the ALB lookup, same idiom platform-
# api-gateway's own data.aws_lb.gateway already uses for vpc_id --
# one named lookup instead of a separate data source per attribute.
data "aws_lb" "gateway" {
  name = "gateway-dev-alb"
}

data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_lb.gateway.vpc_id]
  }
  filter {
    name   = "tag:Name"
    values = ["gateway-dev-private-*"]
  }
}

# Only gateway-api (bedrock-runtime-gateway's own ECS task) may call
# this service -- not API Gateway, not the internet. Looked up by the
# fixed name modules/ecs_service/main.tf's aws_security_group.service
# resource already uses.
data "aws_security_group" "gateway_task" {
  name = "gateway-dev-service"
}

data "aws_sns_topic" "ops_alerts" {
  name = "gateway-dev-ops-alerts"
}

data "aws_dynamodb_table" "provisioned_principal_mappings" {
  name = "gateway-dev-provisioned-principal-mappings"
}

# ACM Private CA has no tag-based data source (unlike every other
# lookup on this page) -- the only way to reference an existing one is
# its ARN directly. Confirmed live via `aws acm-pca list-certificate-
# authorities` rather than guessed at. Real recurring cost
# (~$400/month) already being paid for by bedrock-gateway-infra's own
# aws_acmpca_certificate_authority.internal -- this repo does not
# create a second one, only points at the existing one. Update this if
# that CA is ever recreated (its ARN would change).
locals {
  private_ca_arn = "arn:aws:acm-pca:us-east-1:646821141010:certificate-authority/328ba585-7400-4565-bad3-6bfda5c0196d"
}

module "ecr_authz" {
  source = "git::https://github.com/taixingbi/bedrock-gateway-infra.git//modules/ecr?ref=main"

  repository_name = local.name_prefix
  environment     = "dev"
}

module "authz_service" {
  source = "git::https://github.com/taixingbi/bedrock-gateway-infra.git//modules/authz_service?ref=main"

  name_prefix        = local.name_prefix
  environment        = "dev"
  aws_region         = var.aws_region
  vpc_id             = data.aws_lb.gateway.vpc_id
  private_subnet_ids = data.aws_subnets.private.ids
  log_group_name     = "/ai-platform/ecs/platform-authz-service-dev"

  private_ca_arn = local.private_ca_arn
  sns_topic_arn  = data.aws_sns_topic.ops_alerts.arn

  caller_security_group_id = data.aws_security_group.gateway_task.id

  # No image has been pushed on a first apply -- CI registers the real
  # task definition revision on its first deploy, same convention
  # every other service's first apply already uses.
  image = "${module.ecr_authz.repository_url}:bootstrap"

  task_cpu    = 512
  task_memory = 1024

  provisioned_principal_mappings_table_arn = data.aws_dynamodb_table.provisioned_principal_mappings.arn

  container_env = {
    AWS_REGION                                = var.aws_region
    SERVICE_NAME                              = local.name_prefix
    ENVIRONMENT                               = "dev"
    LOG_LEVEL                                 = "INFO"
    IAM_TENANTS_PATH                          = "policies/iam_tenants.yaml"
    PROVISIONED_PRINCIPAL_MAPPINGS_TABLE_NAME = data.aws_dynamodb_table.provisioned_principal_mappings.name
    OTEL_EXPORTER_OTLP_ENDPOINT               = "http://localhost:4318/v1/traces"
  }
}
