variable "acm_certificate_arn" {
	description = "An arn for certificate for the tld from AWS Certificate Manager"
	type        = string
}

variable "auth_prefix" {
	default     = "auth."
	description = "A domain prefix for cognito authentication"
	type        = string
}

variable "aws_account_id" {
	description = "The account id of the aws account this is being deployed to"
	type        = string
}

variable "cognito_aws_region" {
	default     = "us-east-1"
	description = "The region where the cognito user pool is located"
	type        = string
}

variable "cognito_user_pool" {
	description = "The user pool of the cognito instance that is used to log into the app"
	type        = string
}

variable "github_oauth_token" {
	default     = "github_token"
	description = "An Oauth token to access github. This need only public access to pull the open source project into the codepipeline, so having no scopes defined will suffice and should be preferred."
	type        = string
}

variable "hosted_zone_id" {
	description = "The route53 hosted zone id for the domain"
	type        = string
}

variable "secure_prefix" {
	default     = "private."
	description = "A domain prefix for the secure site"
	type        = string
}

variable "site_aws_region" {
	default     = "us-east-1"
	description = "The region hosting the secure site"
	type        = string
}

variable "tld" {
	description = "The top level domain where the application is hosted"
	type        = string
}
