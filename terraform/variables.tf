variable "region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name of the project used for resource naming"
  type        = string
  default     = "ai-firewall"
}

variable "environment" {
  description = "Deployment environment (dev, staging, production)"
  type        = string
  default     = "production"
  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "environment must be dev, staging, or production."
  }
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "ai-firewall-eks"
}

variable "node_count" {
  description = "Number of worker nodes in the EKS node group"
  type        = number
  default     = 3
}

variable "node_instance_type" {
  description = "EC2 instance type for EKS worker nodes"
  type        = string
  default     = "t3.large"
}

variable "mongodb_instance_class" {
  description = "DocumentDB/RDS instance class for MongoDB"
  type        = string
  default     = "db.t3.medium"
}
