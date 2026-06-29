output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer - use this to access the app"
  value       = aws_lb.main.dns_name
}

output "ecr_repository_url" {
  description = "ECR repository URL - used in the pipeline to push the Docker image"
  value       = aws_ecr_repository.app.repository_url
}

output "ecs_cluster_name" {
  description = "ECS cluster name - used in the pipeline to trigger deployments"
  value       = aws_ecs_cluster.main.name
}

output "ecs_service_name" {
  description = "ECS service name - used in the pipeline to update the service"
  value       = aws_ecs_service.app.name
}

output "github_actions_role_arn" {
  description = "IAM role ARN for GitHub Actions OIDC - add this to GitHub repository secrets"
  value       = aws_iam_role.github_actions.arn
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "private_subnet_ids" {
  description = "Private subnet IDs where Fargate tasks run"
  value       = aws_subnet.private[*].id
}