
# Create lambda function along with environment variable for succesfull rds connection.
resource "aws_lambda_function" "rds_rotation_lambda" {
  function_name = var.lambda_function_name
  role          = aws_iam_role.rds_rotation_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.9"

  filename         = "rds-rotation-function.zip" # Upload your Lambda zip file here
  source_code_hash = filebase64sha256("rds-rotation-function.zip")

  environment {
    variables = {
      EXCLUDE_CHARACTERS         = "/@\"'\\ "
      EXCLUDE_LOWERCASE          = "false"
      EXCLUDE_NUMBERS            = "false"
      EXCLUDE_PUNCTUATION        = "false"
      EXCLUDE_UPPERCASE          = "false"
      PASSWORD_LENGTH            = "32"
      REQUIRE_EACH_INCLUDED_TYPE = "true"
      SECRETS_MANAGER_ENDPOINT   = "https://secretsmanager.ap-southeast-1.amazonaws.com"
    }
  }
}

resource "aws_lambda_permission" "allow_secretsmanager_invocation" {
  statement_id  = "AllowSecretsManagerInvoke"
  action        = "lambda:InvokeFunction"
  principal     = "secretsmanager.amazonaws.com"
  function_name = aws_lambda_function.rds_rotation_lambda.arn
}
