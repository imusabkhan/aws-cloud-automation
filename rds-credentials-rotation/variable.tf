
variable "aws_region" {
    description = "The AWS Region to deploy resources in"
    type = string
    default = "ap-southeast-1"
}

variable "aws_account_id" {
    description = "The AWS Accound ID"
    type = string
    default = "000000000000"
}

variable "lambda_function_name" {
    description = "The lambda function will which perform the rds credentials rotation"
    type = string
    default = "rds-rotation-lambda-final"
}


variable "lambda_rotation_policy_for_rds" {
    description = "This is lambda rotation policy name"
    type = string
    default = "rds-rotation-policy"
}

variable "account_prod" {
    description = "This is the prod account"
    type = string
    default = "prod"
}

variable "rds_database" {
    description = "This is the database name"
    type = string
    default = "demodb-1"
}

variable "secretmanager_secret_name" {
    description = "This is the secret name"
    type = string
    default = "admin-user"
}

variable "db_username" {
  description = "The username for the database"
  type        = string
  default     = "admin"
}

variable "db_password" {
  description = "The password for the database"
  type        = string
  default     = "admin123"
}

variable "db_engine" {
  description = "The database engine"
  type        = string
  default     = "mysql"
}

variable "db_host" {
  description = "The host of the database"
  type        = string
  default     = "hackme.c180e280qan1.ap-southeast-1.rds.amazonaws.com"
}

variable "db_port" {
  description = "The port for the database"
  type        = string
  default     = "3306"
}
