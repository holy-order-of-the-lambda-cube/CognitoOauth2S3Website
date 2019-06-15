# This is a root terraform script to load and execute the module directly for a standalone install
module "secure-site" {
	source = "./modules/secure-site"
	aws_account_id = var.aws_account_id
	domain = "${var.secure_prefix}${var.tld}"
	auth_domain = "${var.auth_prefix}${var.tld}"
	cognito_user_pool = var.cognito_user_pool
	acm_certificate_arn = var.acm_certificate_arn
	hosted_zone_id = var.hosted_zone_id
	site_region = var.site_aws_region
	cognito_region = var.cognito_aws_region
	github_oauth_token = var.github_oauth_token
}
