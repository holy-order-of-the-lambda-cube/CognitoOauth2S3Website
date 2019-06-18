variable "acm_certificate_arn" {
	description = "The SSL certificate for the domain"
	type        = string
}

variable "auth_domain" {
	description = "The fully qualified domain name for authentication. For instance 'auth.xyz.com'"
	type        = string
}

variable "aws_account_id" {
	description = "The account id of the aws account this is being deployed to"
	type        = string
}

variable "cognito_region" {
	default     = "us-east-1"
	description = "The region that the cognito user pool is located in"
	type        = string
}

variable "cognito_user_pool" {
	description = "The identifier for the cognito user pool to be used"
	type        = string
}

variable "domain" {
	description = "The fully qualified domain name of the secure site. For instance 'private.xyz.com'"
	type        = string
}

variable "github_branch" {
	default     = "master"
	description = "The GitHub branch to pull the lambda function from"
	type        = string
}

variable "github_oauth_token" {
	default     = "github_token"
	description = "A secrets manager secret name in us-east-1 that holds an Oauth token to access github. This need only public access to pull the open source project into the codepipeline, so having no scopes defined will suffice and should be preferred. The secret should be in the form '{\"token\":\"<Oauth Token>\"}"
	type        = string
}

variable "github_owner" {
	default     = "holy-order-of-the-lambda-cube"
	description = "The GitHub owner to pull the lambda function from"
	type        = string
}

variable "github_repo" {
	default     = "CognitoOauth2S3Website"
	description = "The GitHub repo to pull the lambda function from"
	type        = string
}

variable "hosted_zone_id" {
	description = "The route53 zone id for the domain"
	type        = string
}

variable "name_prefix" {
	default     = ""
	description = "A prefix for AWS names so that second invocations of the module will not clash"
	type        = string
}

variable "populate_site" {
	default     = true
	description = "If true, will put a placeholder index.html into the s3 bucket containing the secure site"
	type        = bool
}

variable "site_region" {
	default     = "us-east-1"
	description = "The region that the site is hosted in"
	type        = string
}
