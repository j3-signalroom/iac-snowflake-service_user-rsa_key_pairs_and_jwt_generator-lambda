# Create an ECR Repository
resource "aws_ecr_repository" "lambda_ecr" {
  name = local.repo_name
}

# Get the login command from ECR to authenticate Docker to your registry
data "aws_ecr_authorization_token" "auth" {}

# Build Docker Image and Push to ECR
resource "null_resource" "docker_build_and_push" {
  provisioner "local-exec" {
    command = <<EOT
      aws ecr get-login-password --region ${var.aws_region} | docker login --username AWS --password-stdin ${aws_ecr_repository.lambda_ecr.repository_url}
      docker build -t local.repo_name .
      docker tag local.repo_name:latest ${aws_ecr_repository.lambda_ecr.repository_url}:latest
      docker push ${aws_ecr_repository.lambda_ecr.repository_url}:latest
    EOT
  }
  
  # This ensures the ECR repository is created before the Docker build/push steps
  depends_on = [aws_ecr_repository.lambda_ecr]
}

# IAM role for Lambda execution
resource "aws_iam_role" "lambda_exec_role" {
  name = "lambda_exec_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

# Attach the AWSLambdaBasicExecutionRole policy to the role
resource "aws_iam_role_policy_attachment" "lambda_exec_policy_attach" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
