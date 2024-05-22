#############################
# Terraform backend
#############################

terraform {
  backend "s3" {
    bucket = "api-app-deployment"                    # bucket for terraform state file, should be exist
    key    = "codepipeline-config/terraform.tfstate" # object name in the bucket to save terraform file
    region = "us-east-1"                             # region where the bucket is created
  }
}
