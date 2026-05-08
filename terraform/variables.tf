variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "eu-central-1"
}

variable "project_name" {
  description = "Project name used for naming all resources"
  type        = string
  default     = "shift-left-thesis"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (ALB lives here)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets (Fargate tasks live here)"
  type        = list(string)
  default     = ["10.0.3.0/24", "10.0.4.0/24"]
}

variable "availability_zones" {
  description = "Availability zones to use in eu-central-1"
  type        = list(string)
  default     = ["eu-central-1a", "eu-central-1b"]
}

variable "container_port" {
  description = "Port the Flask application listens on"
  type        = number
  default     = 5000
}

variable "fargate_cpu" {
  description = "Fargate task CPU units (256 = 0.25 vCPU)"
  type        = number
  default     = 256
}

variable "fargate_memory" {
  description = "Fargate task memory in MB"
  type        = number
  default     = 512
}