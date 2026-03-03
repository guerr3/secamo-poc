# ──────────────────────────────────────────────────────────────
# Remote State — S3 + DynamoDB locking
# ──────────────────────────────────────────────────────────────
#
# Pre-requisites (create manually or via bootstrap script):
#   1. S3 bucket:       secamo-poc-tfstate-<account_id>
#   2. DynamoDB table:  secamo-poc-tfstate-lock
#      - Partition key: LockID (String)
#      - Billing mode:  PAY_PER_REQUEST

terraform {
  backend "s3" {
    bucket         = "secamo-poc-tfstate-760659115776"
    key            = "environments/poc/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    dynamodb_table = "secamo-poc-tfstate-lock"
  }
}
