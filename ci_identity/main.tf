# This repo's own CI identity (deploy-dev/prod, infra plan, infra
# apply-dev) -- Terraform-ownership migration from platform-foundation
# (2026-09-21): these 4 IAM roles already existed, created and managed
# by platform-foundation/environments/global's module "github_oidc_authz"
# call. Moved here via `terraform import` (never delete/recreate) so
# this repo owns its own CI permissions going forward, same as every
# other repo in this platform-wide migration -- see
# platform-foundation's own environments/global/main.tf for the ones
# still pending. ARNs are unchanged; this repo's GitHub Environment
# variables (AWS_AUTHZ_DEPLOY_ROLE_ARN_DEV/_PROD,
# AWS_AUTHZ_INFRA_PLAN_ROLE_ARN, AWS_AUTHZ_INFRA_APPLY_DEV_ROLE_ARN)
# do not need to change.
#
# A separate Terraform root from environments/dev -- own state file,
# own (infrequent) apply -- since these roles aren't scoped to just the
# dev environment (the prod deploy role lives here too, even though
# environments/prod doesn't exist yet for this repo's own infra).

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

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

# --- Deploy roles: push to ECR, register+deploy a task definition. No
# worker split, one service, matching bedrock-gateway-portal's simpler
# CI shape rather than bedrock-runtime-gateway's own app/ half's
# two-service one. ------------------------------------------------------

data "aws_iam_policy_document" "authz_deploy" {
  for_each = { dev = "gateway-dev-authz", prod = "gateway-prod-authz" }

  statement {
    sid = "PushToEcr"
    actions = [
      "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage", "ecr:BatchCheckLayerAvailability",
      "ecr:PutImage", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload",
    ]
    resources = ["arn:aws:ecr:${var.aws_region}:${local.account_id}:repository/${each.value}*"]
  }

  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid       = "DeployToEcs"
    actions   = ["ecs:DescribeServices", "ecs:UpdateService"]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "ecs:cluster"
      values   = ["arn:aws:ecs:${var.aws_region}:${local.account_id}:cluster/${each.value}*"]
    }
  }

  statement {
    sid       = "RegisterTaskDefinition"
    actions   = ["ecs:RegisterTaskDefinition", "ecs:DescribeTaskDefinition"]
    resources = ["*"]
  }

  statement {
    sid     = "PassTaskRoles"
    actions = ["iam:PassRole"]
    # Both the execution role and the task role -- ECS
    # RegisterTaskDefinition needs to pass both when a task
    # definition specifies task_role_arn too, not just
    # execution_role_arn (confirmed live: this deploy failed with
    # "not authorized to perform: iam:PassRole on ...-task").
    resources = [
      "arn:aws:iam::${local.account_id}:role/${each.value}*-execution",
      "arn:aws:iam::${local.account_id}:role/${each.value}*-task",
    ]
  }
}

# --- This repo's own Terraform plan/apply-dev roles (environments/dev
# -- see migrate-authz-service-state.sh for the original app-side state
# migration). Scoped to exactly what modules/ecr + modules/authz_service
# touch: EC2 (its own security groups), ELBv2 (its own ALB/target
# group/listener), ECS, ECR, ACM (the private-CA-issued cert -- no
# acm-pca permission needed since the CA itself is referenced by a
# hardcoded ARN local, not created or read via a data source here), IAM
# (its own execution/task roles, name-scoped), application-autoscaling,
# CloudWatch (log group + alarms), plus read-only DynamoDB/SNS for the
# two cross-repo data-source lookups (the provisioned_principal_mappings
# table and ops_alerts topic -- bedrock-runtime-gateway owns both,
# platform-authz-service only ever reads them). No apply-prod yet:
# environments/prod doesn't exist for this repo until the pre-existing
# "no private CA in prod" decision is resolved.
data "aws_iam_policy_document" "authz_infra_plan" {
  statement {
    sid = "ReadOnly"
    actions = [
      "ec2:Describe*",
      "elasticloadbalancing:Describe*",
      "ecs:Describe*", "ecs:List*",
      "ecr:Describe*", "ecr:List*", "ecr:GetLifecyclePolicy",
      "logs:Describe*", "logs:List*",
      "iam:Get*", "iam:List*",
      "sts:GetCallerIdentity",
      # Describe*, not just DescribeTable: refreshing an
      # aws_dynamodb_table data source also calls
      # DescribeContinuousBackups/DescribeTimeToLive.
      # ListTagsOfResource (not the usual *ListTagsForResource*
      # pattern -- DynamoDB's action name breaks that convention) is
      # also called reading the table's tags.
      "dynamodb:Describe*", "dynamodb:ListTagsOfResource",
      "sns:GetTopicAttributes", "sns:ListTopics", "sns:ListTagsForResource",
      "acm:Describe*", "acm:Get*", "acm:List*",
      "application-autoscaling:Describe*", "application-autoscaling:ListTagsForResource",
      "cloudwatch:Describe*", "cloudwatch:List*", "cloudwatch:Get*",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "TerraformStateS3"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::*tfstate*", "arn:aws:s3:::*tfstate*/*"]
  }
}

data "aws_iam_policy_document" "authz_infra_apply" {
  statement {
    sid       = "Ec2Broad"
    actions   = ["ec2:*"]
    resources = ["*"]
  }
  statement {
    sid       = "ElbBroad"
    actions   = ["elasticloadbalancing:*"]
    resources = ["*"]
  }
  statement {
    sid       = "EcsBroad"
    actions   = ["ecs:*"]
    resources = ["*"]
  }
  statement {
    sid       = "EcrBroad"
    actions   = ["ecr:*"]
    resources = ["*"]
  }
  statement {
    sid       = "LogsBroad"
    actions   = ["logs:*"]
    resources = ["*"]
  }
  statement {
    sid       = "AcmBroad"
    actions   = ["acm:*"]
    resources = ["*"]
  }
  statement {
    sid       = "AppAutoscalingBroad"
    actions   = ["application-autoscaling:*"]
    resources = ["*"]
  }
  statement {
    sid       = "CloudWatchBroad"
    actions   = ["cloudwatch:*"]
    resources = ["*"]
  }
  # Read-only: bedrock-runtime-gateway owns both the
  # provisioned_principal_mappings table and the ops_alerts SNS topic --
  # this repo only ever looks them up by name (data source), never
  # manages their lifecycle.
  statement {
    sid       = "DynamoDbReadOnly"
    actions   = ["dynamodb:Describe*", "dynamodb:ListTagsOfResource"]
    resources = ["*"]
  }
  # Learned live wiring ci_identity into CI: this role never had a
  # generic iam:Get*/List* grant (only authz_infra_plan did) -- fine
  # while this role only ever wrote gateway-*-authz-*/gha-authz-* roles
  # directly, but ci_identity's own module.github_oidc also reads the
  # account-wide OIDC provider via data source during apply now, not
  # just plan, and 403'd on iam:ListOpenIDConnectProviders.
  statement {
    sid       = "OidcProviderReadOnly"
    actions   = ["iam:ListOpenIDConnectProviders", "iam:GetOpenIDConnectProvider"]
    resources = ["*"]
  }
  statement {
    sid       = "SnsReadOnly"
    actions   = ["sns:GetTopicAttributes", "sns:ListTopics", "sns:ListTagsForResource"]
    resources = ["*"]
  }
  # IAM role names ARE predictable (gateway-{dev,prod}-authz-{execution,task}),
  # so scoped by name. Also covers this repo's OWN CI roles
  # (gha-authz-*, managed by this same ci_identity root -- the
  # Terraform-ownership migration moved them here, so this role now
  # needs to manage its own OIDC roles going forward) -- deliberately
  # still NOT the wider gha-* namespace every other repo's own roles
  # live under; this repo can only ever touch its own.
  statement {
    sid = "ManageAuthzServiceRoles"
    actions = [
      "iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:UpdateRole",
      "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:GetRolePolicy",
      "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies", "iam:TagRole", "iam:UntagRole", "iam:PassRole",
    ]
    resources = [
      "arn:aws:iam::${local.account_id}:role/gateway-*-authz-*",
      "arn:aws:iam::${local.account_id}:role/gha-authz-*",
    ]
  }
  # application-autoscaling's service-linked role.
  statement {
    sid       = "AppAutoscalingServiceLinkedRole"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["arn:aws:iam::${local.account_id}:role/aws-service-role/ecs.application-autoscaling.amazonaws.com/*"]
    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values   = ["ecs.application-autoscaling.amazonaws.com"]
    }
  }
  statement {
    sid       = "TerraformStateS3"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::*tfstate*", "arn:aws:s3:::*tfstate*/*"]
  }
}

module "github_oidc" {
  source = "git::https://github.com/taixingbi/platform-foundation.git//modules/github_oidc?ref=main"

  # The account-wide OIDC provider is owned by platform-foundation
  # (formally imported into its state, see that repo's own
  # github_oidc_infra module call) -- every other repo, this one
  # included, only ever references it via data source.
  create_oidc_provider = false
  github_org           = var.github_org
  github_repo          = "platform-authz-service"

  roles = {
    dev = {
      role_name   = "gha-authz-deploy-dev"
      policy_json = data.aws_iam_policy_document.authz_deploy["dev"].json
    }
    prod = {
      role_name   = "gha-authz-deploy-prod"
      policy_json = data.aws_iam_policy_document.authz_deploy["prod"].json
    }
    plan = {
      role_name   = "gha-authz-infra-plan"
      policy_json = data.aws_iam_policy_document.authz_infra_plan.json
    }
    apply-dev = {
      role_name   = "gha-authz-infra-apply-dev"
      policy_json = data.aws_iam_policy_document.authz_infra_apply.json
    }
  }
}
