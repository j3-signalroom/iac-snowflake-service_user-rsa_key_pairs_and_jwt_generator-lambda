# Create an ECR Repository
resource "aws_ecr_repository" "lambda_ecr" {
  name = local.repo_name
}

# Get the login command from ECR to authenticate Docker to your registry
data "aws_ecr_authorization_token" "auth" {}

# Authenticate Docker to your AWS ECR
resource "null_resource" "aws_ecr_login" {
  provisioner "local-exec" {
    command = "aws ecr get-login-password --region ${var.aws_region} ${var.aws_profile} | docker login --username AWS --password-stdin ${aws_ecr_repository.lambda_ecr.repository_url}"
  }
  
  # This ensures the ECR repository is created before the Docker build/push steps
  depends_on = [aws_ecr_repository.lambda_ecr]
}

resource "null_resource" "docker_build" {
  triggers = {
    order = null_resource.aws_ecr_login.id
  }
  provisioner "local-exec" {
    command = "docker build -t local.repo_name ."
  }
}

resource "null_resource" "docker_tag" {
  triggers = {
    order = null_resource.docker_build.id
  }
  provisioner "local-exec" {
    command = "docker tag local.repo_name:latest ${aws_ecr_repository.lambda_ecr.repository_url}:latest"
  }
}

resource "null_resource" "docker_push" {
  triggers = {
    order = null_resource.docker_tag.id
  }
  provisioner "local-exec" {
    command = "docker push ${aws_ecr_repository.lambda_ecr.repository_url}:latest"
  }
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
