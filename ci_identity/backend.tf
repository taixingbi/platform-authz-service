terraform {
  backend "s3" {
    bucket       = "bedrock-gateway-tfstate-646821141010"
    key          = "platform-authz-service/ci-identity/terraform.tfstate"
    region       = "us-east-1"
    use_lockfile = true
    encrypt      = true
  }
}
