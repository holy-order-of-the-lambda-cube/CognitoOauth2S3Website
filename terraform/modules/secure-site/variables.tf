variable "aws_account_id" {
	description = "The account id of the aws account this is being deployed to"
	type        = string
}

variable "domain" {
	description = "The fully qualified domain name of the secure site. For instance 'private.xyz.com'"
	type        = string
}

variable "auth_domain" {
	description = "The fully qualified domain name for authentication. For instance 'auth.xyz.com'"
	type        = string
}

variable "cognito_user_pool" {
	description = "The identifier for the cognito user pool to be used"
	type        = string
}

variable "acm_certificate_arn" {
	description = "The SSL certificate for the domain"
	type        = string
}

variable "hosted_zone_id" {
	description = "The route53 zone id for the domain"
	type        = string
}

variable "stage" {
	default     = "prod"
	description = "The name of the deployment stage, such as test or prod"
	type        = string
}

variable "site_region" {
	default     = "us-east-1"
	description = "The region that the site is hosted in"
	type        = string
}

variable "cognito_region" {
	default     = "us-east-1"
	description = "The region that the cognito user pool is located in"
	type        = string
}

variable "github_oauth_token" {
	description = "An Oauth token to access github. This need only public access to pull the open source project into the codepipeline, so having no scopes defined will suffice and should be preferred."
	type        = string
}
