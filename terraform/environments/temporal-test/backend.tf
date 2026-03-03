# ──────────────────────────────────────────────────────────────
# Remote State — S3 + DynamoDB locking
# ──────────────────────────────────────────────────────────────
# Uses the same backend as poc, but a separate state key.

terraform {
  backend "s3" {
    bucket         = "secamo-poc-tfstate-760659115776"
    key            = "environments/temporal-test/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    dynamodb_table = "secamo-poc-tfstate-lock"
  }
}
