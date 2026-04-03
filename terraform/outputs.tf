output "cluster_endpoint" {
  description = "EKS cluster API server endpoint"
  value       = try(module.eks.cluster_endpoint, "")
  sensitive   = false
}

output "cluster_name" {
  description = "EKS cluster name"
  value       = var.cluster_name
}

output "vpc_id" {
  description = "VPC ID hosting the AI Firewall cluster"
  value       = try(module.vpc.vpc_id, "")
}

output "region" {
  description = "AWS region where resources are deployed"
  value       = var.region
}
