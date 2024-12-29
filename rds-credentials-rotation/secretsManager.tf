
# Create random number for secret name
resource "random_integer" "random" {
  min = 1000
  max = 9999
}

# Create Secret for RDS
resource "aws_secretsmanager_secret" "rds_secret" {
  name        = "${var.account_prod}/${var.rds_database}/${var.secretmanager_secret_name}/${random_integer.random.result}"
  description = "RDS credentials for MySQL"
}

# Set RDS variables for connection and rotation
resource "aws_secretsmanager_secret_version" "rds_secret_version" {
  secret_id = aws_secretsmanager_secret.rds_secret.id
  secret_string = jsonencode({
    username             = var.db_username
    password             = var.db_password
    engine               = var.db_engine
    host                 = var.db_host
    port                 = var.db_port
    dbInstanceIdentifier = var.rds_database
  })
}

# Set credential rotation rule in secret manager
resource "aws_secretsmanager_secret_rotation" "rds_secret_rotation" {
  secret_id           = aws_secretsmanager_secret.rds_secret.id
  rotation_lambda_arn = aws_lambda_function.rds_rotation_lambda.arn

  rotation_rules {
    automatically_after_days = 1
  }
}

output "rds_secret_arn" {
  value = aws_secretsmanager_secret.rds_secret.arn
}