
# Create IAM Role Policy to attach with Lambda function
resource "aws_iam_role_policy" "rds_rotation_policy" {
  name = var.lambda_rotation_policy_for_rds
  role = aws_iam_role.rds_rotation_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "rds:ModifyDBInstance",
          "rds:DescribeDBInstances",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:UpdateSecretVersionStage",
          "secretsmanager:GetRandomPassword",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "ec2:CreateNetworkInterface",
          "ec2:DeleteNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DetachNetworkInterface",
          "ec2:DescribeSubnets",
          "ec2:AssignPrivateIpAddresses",
          "ec2:UnassignPrivateIpAddresses"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action = [
          "secretsmanager:TagResource"
        ]
        Effect = "Allow"
        Resource = [
          "arn:aws:secretsmanager:*:*:secret:prod/rds/*",
          "arn:aws:secretsmanager:*:*:secret:staging/rds/*"
        ]
      },
      {
        Action = [
          "rds:ModifyDBCluster",
          "rds:DescribeDBClusters"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# Create IAM Role
resource "aws_iam_role" "rds_rotation_role" {
  name = "rds-rotation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Effect = "Allow"
        Sid    = ""
      }
    ]
  })
}

# Create IAM policy for lambda invoke function along with AWS Account ID.
resource "aws_iam_policy" "lambda_condition_policy" {
  name        = "lambda_condition_policy"
  description = "Policy with condition for Secrets Manager"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "SecretsManagerRDSMySQLRotationSingleUser"
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = "arn:aws:lambda:${var.aws_region}:${var.aws_account_id}:function:${var.lambda_function_name}"
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = var.aws_account_id
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_condition_policy_attachment" {
  role       = aws_iam_role.rds_rotation_role.name
  policy_arn = aws_iam_policy.lambda_condition_policy.arn
}