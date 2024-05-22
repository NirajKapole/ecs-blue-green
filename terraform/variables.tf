#variables
variable "region" {
  default = "us-east-1"
}

variable "aws_account_id" {
  default = "173291265853"
}

variable "service_name" {
  type    = string
  default = "r-site-svc"
}

variable "service_container" {
  default = "public.ecr.aws/docker/library/nginx:stable-alpine"
}

variable "container_port" {
  default = "8000"
}

variable "memory_reserv" {
  default = "1000"
}


variable "s3_bucket_name" {
  default = "codepipeline-bucket-stare-artifacts"
}

variable "instance_type" {
  default = "t3.small"
}

# variable "route53_hosted_zone_name" {
#   default = "yourdomain.com"
# }

# variable "route53_subdomain_name" {
#   default = "nginx-app"
# }

# variable "sns_endpoint" {
#   default = "your_email"
# }

variable "repository_name" {
  default = "gitlab_repo"
}

variable "branch_name" {
  default = "ecs-test1"
}
