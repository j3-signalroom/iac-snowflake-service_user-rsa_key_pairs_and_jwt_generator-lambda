# Create an ECR Repository
resource "aws_ecr_repository" "lambda_ecr" {
  name = "iac-snowflake_user-rsa_key_generator"
}

# Get the login command from ECR to authenticate Docker to your registry
data "aws_ecr_authorization_token" "auth" {}

# Build Docker Image and Push to ECR
resource "null_resource" "docker_build_and_push" {
  provisioner "local-exec" {
    command = <<EOT
      aws ecr get-login-password --region ${var.aws_region} | docker login --username AWS --password-stdin ${aws_ecr_repository.lambda_ecr.repository_url}
      docker build -t my-repo .
      docker tag my-repo:latest ${aws_ecr_repository.lambda_ecr.repository_url}:latest
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

# Lambda function
resource "aws_lambda_function" "my_lambda" {
  function_name = "my-lambda-function"

  # Provide the IAM role
  role = aws_iam_role.lambda_exec_role.arn

  # Specify the container image URI from ECR
  image_uri = aws_ecr_repository.lambda_ecr.repository_url

  # (Optional) Specify the amount of memory and timeout
  memory_size = 128
  timeout     = 30

  # This ensures the ECR repository has the docker image before the Lambda function is created
  depends_on = [null_resource.docker_build_and_push]
}

# (Optional) Create a CloudWatch log group for the Lambda function
resource "aws_cloudwatch_log_group" "lambda_log_group" {
  name              = "/aws/lambda/my-lambda-function"
  retention_in_days = 7
}

# (Optional) Invoke the Lambda function using Terraform's local-exec provisioner
resource "null_resource" "invoke_lambda" {
  provisioner "local-exec" {
    command = <<EOT
      aws lambda invoke \
        --function-name ${aws_lambda_function.my_lambda.function_name} \
        --region ${var.aws_region} \
        --payload '{}' \
        response.json
    EOT
  }

  depends_on = [aws_lambda_function.my_lambda]
}
