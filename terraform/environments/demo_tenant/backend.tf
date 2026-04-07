# Remote state is isolated per environment via unique key.
terraform {
  backend "s3" {
    bucket         = "secamo-poc-tfstate-760659115776"
    key            = "environments/demo_tenant/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    dynamodb_table = "secamo-poc-tfstate-lock"
  }
}
