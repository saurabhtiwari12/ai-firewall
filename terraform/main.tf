terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Uncomment to use remote state
  # backend "s3" {
  #   bucket         = "ai-firewall-tfstate"
  #   key            = "production/terraform.tfstate"
  #   region         = var.region
  #   encrypt        = true
  #   dynamodb_table = "ai-firewall-tflock"
  # }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

module "vpc" {
  source = "./aws"

  project_name = var.project_name
  environment  = var.environment
  region       = var.region
}

module "eks" {
  source = "./aws"

  project_name       = var.project_name
  environment        = var.environment
  cluster_name       = var.cluster_name
  node_count         = var.node_count
  node_instance_type = var.node_instance_type
}
