# This is where the webslte is located
provider "aws" {
	alias = "site"
	region = var.site_region
	version = "~> 2.14.0"
}

# This is where the cognito user pool is located
provider "aws" {
	alias = "cognito"
	region = var.cognito_region
	version = "~> 2.14.0"
}

# We need to deploy lambda@edge functions in us-east-1
provider "aws" {
	alias = "us-east-1"
	region = "us-east-1"
	version = "~> 2.14.0"
}

# This bucket will hold the SAM template build artifacts
resource "aws_s3_bucket" "build-artifacts" {
	provider      = aws.us-east-1
	bucket_prefix = "c-build-artifacts-${var.stage}"
	force_destroy = true

	server_side_encryption_configuration {
		rule {
			apply_server_side_encryption_by_default {
				sse_algorithm = "aws:kms"
			}
		}
	}

	lifecycle_rule {
		enabled                                = true
		abort_incomplete_multipart_upload_days = 2

		expiration {
			days = 180
		}

		noncurrent_version_expiration {
			days = 30
		}
	}

	versioning {
		enabled = false
	}
}

# Website that requires authentication
# Server side encryption is not KMS because cloudfront can't decrypt KMS
resource "aws_s3_bucket" "secure-site" {
	provider      = aws.site
	bucket        = "${var.domain}"
	force_destroy = true

	server_side_encryption_configuration {
		rule {
			apply_server_side_encryption_by_default {
				sse_algorithm = "AES256"
			}
		}
	}
}

# This bucket holds the codepipeline artifacts
resource "aws_s3_bucket" "codepipeline" {
	# Locate in us-east-1 since we are deploying the lambda@edge function here
	provider      = aws.us-east-1
	bucket_prefix = "c-codepipeline-${var.stage}"
	force_destroy = true

	server_side_encryption_configuration {
		rule {
			apply_server_side_encryption_by_default {
				sse_algorithm = "aws:kms"
			}
		}
	}

	lifecycle_rule {
		enabled                                = true
		abort_incomplete_multipart_upload_days = 2

		expiration {
			days = 180
		}

		noncurrent_version_expiration {
			days = 30
		}
	}

	versioning {
		enabled = true
	}
}

# Security in depth restrictions on buckets to avoid any public access
resource "aws_s3_bucket_public_access_block" "build-artifacts" {
	provider                = aws.us-east-1
	bucket                  = aws_s3_bucket.build-artifacts.id
	block_public_acls       = true
	block_public_policy     = true
	ignore_public_acls      = true
	restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "codepipeline" {
	provider                = aws.us-east-1
	bucket                  = aws_s3_bucket.codepipeline.id
	block_public_acls       = true
	block_public_policy     = true
	ignore_public_acls      = true
	restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "secure-site" {
	provider                = aws.site
	depends_on              = [aws_s3_bucket_policy.secure-site]
	bucket                  = aws_s3_bucket.secure-site.id
	block_public_acls       = true
	block_public_policy     = true
	ignore_public_acls      = true
	restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "secure-site" {
	provider = aws.site
	bucket   = aws_s3_bucket.secure-site.id
	policy   = data.aws_iam_policy_document.s3-secure-site.json
}

resource "aws_cloudfront_origin_access_identity" "secure-site" {
	provider = aws.us-east-1
	comment  = "Secure website identity"
}

# Map the auth portal to the cognito cloudfront disto
resource "aws_route53_record" "secure-site" {
	provider = aws.site

	zone_id  = var.hosted_zone_id
	name     = "${var.auth_domain}"
	type     = "A"

	alias {
		evaluate_target_health = "false"
		name                   = aws_cognito_user_pool_domain.secure-site.cloudfront_distribution_arn

		# This zone_id is the cloudfront zone_id. Always the same for any cloudfront distribution.
		zone_id                = "Z2FDTNDATAQYW2"
	}
}

resource "aws_cognito_user_pool_client" "secure-site" {
	provider                             = aws.cognito
	name                                 = "secure-site"
	allowed_oauth_flows                  = ["code"]
	allowed_oauth_flows_user_pool_client = true
	allowed_oauth_scopes                 = ["openid"]
	callback_urls                        = ["https://${var.domain}/index.html"]
	generate_secret                      = true
	refresh_token_validity               = 1
	supported_identity_providers         = ["COGNITO"]
	user_pool_id                         = var.cognito_user_pool
}

resource "aws_cognito_user_pool_domain" "secure-site" {
	provider        = aws.cognito
	domain          = "${var.auth_domain}"
	certificate_arn = var.acm_certificate_arn
	user_pool_id    = var.cognito_user_pool
}

# The codepipeline to build the cloudfront distribution and lambda@edge function
resource "aws_codepipeline" "secure-site" {
	provider = aws.us-east-1
	name     = "c-pipe-secure-site-${var.stage}"
	role_arn = aws_iam_role.codepipeline.arn

	# Pipeline fails permission check sometimes when it autofires at creation so wait for role policy to apply.
	depends_on = [aws_iam_role_policy.codepipeline]

	artifact_store {
		location = aws_s3_bucket.codepipeline.bucket
		type     = "S3"
	}

	# This loads the code from the open source github project. Note that local changes to the lambda@edge function
	# or SAM template will not be reflected because the project is pulled directly from GitHub by codepipeline.
	# If you wish to fork for customization purposes, host the code elsewhere and change this source to your new
	# forked repo. Be forewarned that at this time codepipeline cannot pull from cross region codecommit repos,
	# so if you host on codecommit it should be in us-east-1 or else you are in for a world of fun and God help you.
	stage {
		name = "source"

		action {
			name     = "source"
			category = "Source"
			owner    = "ThirdParty"
			provider = "GitHub"
			version  = "1"

			output_artifacts = ["source"]

			configuration = {
				Owner      = "holy-order-of-the-lambda-cube"
				Repo       = "CognitoOauth2S3Website"
				Branch     = "master"
				OAuthToken = var.github_oauth_token
			}
		}
	}

	stage {
		name = "build"

		action {
			name     = "build"
			category = "Build"
			owner    = "AWS"
			provider = "CodeBuild"
			version  = "1"

			input_artifacts = ["source"]

			output_artifacts = ["build"]

			configuration = {
				ProjectName = aws_codebuild_project.secure-site.arn
			}
		}
	}

	stage {
		name = "deploy"

		action {
			name     = "plan-deployment"
			category = "Deploy"
			owner    = "AWS"
			provider = "CloudFormation"
			version  = "1"
			input_artifacts = ["build"]

			configuration = {
				ActionMode         = "CHANGE_SET_REPLACE"
				StackName          = "c-pipe-secure-site-${var.stage}"
				ChangeSetName      = "c-secure-site-${var.stage}"
				RoleArn            = aws_iam_role.codepipeline-cloudformation-deploy.arn
				TemplatePath       = "build::output.yaml"
				ParameterOverrides = "{\"Alias\":\"${aws_s3_bucket.secure-site.bucket}\",\"CertificateArn\":\"${var.acm_certificate_arn}\",\"HostedZoneId\":\"${var.hosted_zone_id}\",\"OriginAccessIdentity\":\"${aws_cloudfront_origin_access_identity.secure-site.cloudfront_access_identity_path}\",\"OriginDomain\":\"${aws_s3_bucket.secure-site.bucket_regional_domain_name}\",\"WebAuthFunctionRoleArn\":\"${aws_iam_role.lambda-cloudfront-auth.arn}\"}"
			}
		}

		action {
			name      = "deploy"
			category  = "Deploy"
			owner     = "AWS"
			provider  = "CloudFormation"
			version   = "1"
			run_order = 2

			configuration = {
				ActionMode    = "CHANGE_SET_EXECUTE"
				StackName     = "c-pipe-secure-site-${var.stage}"
				ChangeSetName = "c-secure-site-${var.stage}"
			}
		}
	}
}

resource "aws_codebuild_project" "secure-site" {
	provider     = aws.us-east-1
	name         = "c-secure-site-${var.stage}"
	description  = "Secure site builder"
	service_role = "${aws_iam_role.codebuild.arn}"

	artifacts {
		type = "CODEPIPELINE"
	}

	environment {
		compute_type = "BUILD_GENERAL1_SMALL"
		image = "aws/codebuild/nodejs:10.14.1"
		type = "LINUX_CONTAINER"

		environment_variable {
			name = "c_s3_target_bucket"
			value = "${aws_s3_bucket.build-artifacts.bucket}"
		}

		environment_variable {
			name = "c_cognito_user_pool"
			value = "${var.cognito_user_pool}"
		}

		environment_variable {
			name = "c_cognito_client_id"
			value = "${aws_cognito_user_pool_client.secure-site.id}"
		}

		environment_variable {
			name = "c_site_domain"
			value = "${var.domain}"
		}

		environment_variable {
			name = "c_auth_domain"
			value = "${var.auth_domain}"
		}

		environment_variable {
			name = "c_client_secret"
			value = "${aws_cognito_user_pool_client.secure-site.client_secret}"
		}
	}

	source {
		type = "CODEPIPELINE"
	}
}

# I put all my IAM stuff in the same region as the resources accessing it. I have no idea if this makes a difference
# but I figure replication might be slightly faster this way
resource "aws_cloudwatch_log_group" "codebuild" {
	provider          = aws.us-east-1
	name              = "/aws/codebuild/c-secure-site-${var.stage}"
	retention_in_days = 7
}

resource "aws_iam_role" "codebuild" {
	provider           = aws.us-east-1
	name_prefix        = "c-codebuild-${var.stage}"
	assume_role_policy = data.aws_iam_policy_document.codebuild-assume-role.json
}

resource "aws_iam_role" "codepipeline" {
	provider           = aws.us-east-1
	name_prefix        = "c-pipe-secure-site-${var.stage}"
	assume_role_policy = data.aws_iam_policy_document.codepipeline-assume-role.json
}

resource "aws_iam_role" "codepipeline-cloudformation-deploy" {
	provider           = aws.us-east-1
	name_prefix        = "c-pipe-cfn-deploy-${var.stage}"
	assume_role_policy = data.aws_iam_policy_document.codepipeline-assume-role-cloudformation.json
}

resource "aws_iam_role" "lambda-cloudfront-auth" {
	provider           = aws.us-east-1
	name_prefix        = "c-lambda-cloudfront-auth-${var.stage}"
	assume_role_policy = data.aws_iam_policy_document.edgelambda-assume-role.json
}

resource "aws_iam_role_policy" "codebuild" {
	provider    = aws.us-east-1
	name_prefix = "c-codebuild-primary-${var.stage}"
	role        = aws_iam_role.codebuild.id
	policy      = data.aws_iam_policy_document.codebuild.json
}

resource "aws_iam_role_policy" "codepipeline" {
	provider    = aws.us-east-1
	name_prefix = "c-pipe-secure-site-${var.stage}"
	role        = aws_iam_role.codepipeline.id
	policy      = data.aws_iam_policy_document.codepipeline.json
}

resource "aws_iam_role_policy" "codepipeline-cloudformation-deploy" {
	provider    = aws.us-east-1
	name_prefix = "c-pipe-cfn-deploy-${var.stage}"
	role        = aws_iam_role.codepipeline-cloudformation-deploy.id
	policy      = data.aws_iam_policy_document.codepipeline-cloudformation-deploy.json
}

resource "aws_iam_role_policy" "lambda-cloudfront-auth" {
	provider    = aws.us-east-1
	name_prefix = "c-lambda-cloudfront-auth-${var.stage}"
	role        = aws_iam_role.lambda-cloudfront-auth.id
	policy      = data.aws_iam_policy_document.lambda-cloudfront-auth.json
}

data "aws_iam_policy_document" "codebuild-assume-role" {
	provider = aws.us-east-1

	statement {
		principals {
			type        = "Service"
			identifiers = ["codebuild.us-east-1.amazonaws.com"]
		}

		actions = ["sts:AssumeRole"]
	}
}

data "aws_iam_policy_document" "codebuild" {
	provider = aws.us-east-1

	statement {
		actions = [
			"logs:CreateLogStream",
			"logs:PutLogEvents",
		]

		resources = ["arn:aws:logs:us-east-1:${var.aws_account_id}:log-group:/aws/codebuild/*"]
	}

	statement {
		actions = [
			"s3:GetObject",
			"s3:PutObject",
		]

		resources = ["${aws_s3_bucket.codepipeline.arn}/*"]
	}

	statement {
		actions   = ["s3:PutObject"]
		resources = ["${aws_s3_bucket.build-artifacts.arn}/*"]
	}
}

data "aws_iam_policy_document" "codepipeline" {
	provider = aws.us-east-1

	statement {
		actions = [
			"codebuild:BatchGetBuilds",
			"codebuild:StartBuild",
		]

		resources = [aws_codebuild_project.secure-site.arn]
	}

	statement {
		actions = [
			"s3:GetObject",
			"s3:GetObjectVersion",
			"s3:PutObject",
		]

		resources = ["${aws_s3_bucket.codepipeline.arn}/*"]
	}

	statement {
		actions = [
			"cloudformation:CreateChangeSet",
			"cloudformation:DeleteChangeSet",
			"cloudformation:DescribeChangeSet",
			"cloudformation:DescribeStacks",
			"cloudformation:ExecuteChangeSet",
		]

		resources = ["arn:aws:cloudformation:us-east-1:${var.aws_account_id}:stack/c-pipe-secure-site-${var.stage}/*"]
	}

	statement {
		actions   = ["iam:PassRole"]
		resources = [aws_iam_role.codepipeline-cloudformation-deploy.arn]
	}
}

data "aws_iam_policy_document" "codepipeline-assume-role" {
	provider = aws.us-east-1

	statement {
		principals {
			type        = "Service"
			identifiers = ["codepipeline.us-east-1.amazonaws.com"]
		}

		actions = ["sts:AssumeRole"]
	}
}

data "aws_iam_policy_document" "codepipeline-assume-role-cloudformation" {
	provider = aws.us-east-1

	statement {
		principals {
			type        = "Service"
			identifiers = ["cloudformation.amazonaws.com"]
		}

		actions = ["sts:AssumeRole"]
	}
}

data "aws_iam_policy_document" "codepipeline-cloudformation-deploy" {
	provider = aws.us-east-1

	statement {
		actions   = ["cloudformation:CreateChangeSet"]
		resources = ["arn:aws:cloudformation:us-east-1:aws:transform/Serverless-2016-10-31"]
	}

	statement {
		actions = [
			"lambda:CreateAlias",
			"lambda:CreateFunction",
			"lambda:DeleteAlias",
			"lambda:DeleteFunction",
			"lambda:EnableReplication",
			"lambda:GetFunction",
			"lambda:GetFunctionConfiguration",
			"lambda:ListTags",
			"lambda:ListVersionsByFunction",
			"lambda:PublishVersion",
			"lambda:TagResource",
			"lambda:UntagResource",
			"lambda:UpdateAlias",
			"lambda:UpdateFunctionCode",
		]

		resources = ["arn:aws:lambda:us-east-1:${var.aws_account_id}:function:${aws_codepipeline.secure-site.name}-WebAuthFunction-*"]
	}

	statement {
		actions   = ["iam:PassRole"]
		resources = [aws_iam_role.lambda-cloudfront-auth.arn]
	}

	statement {
		actions   = ["s3:GetObject"]
		resources = ["${aws_s3_bucket.build-artifacts.arn}/SAM/*"]
	}

	statement {
		actions = [
			"cloudfront:CreateDistribution",
			"cloudfront:DeleteDistribution",
			"cloudfront:GetDistribution",
			"cloudfront:TagResource",
			"cloudfront:UpdateDistribution",
		]

		resources = ["*"]
	}

	statement {
		actions = [
			"route53:ChangeResourceRecordSets",
			"route53:GetHostedZone",
			"route53:ListResourceRecordSets",
		]

		resources = ["arn:aws:route53:::hostedzone/${var.hosted_zone_id}"]
	}

	statement {
		actions   = ["route53:GetChange"]
		resources = ["arn:aws:route53:::change/*"]
	}
}

data "aws_iam_policy_document" "edgelambda-assume-role" {
	provider = aws.us-east-1

	statement {
		principals {
			type = "Service"
			identifiers = [
				"edgelambda.amazonaws.com",
				"lambda.amazonaws.com"
			]
		}

		actions = ["sts:AssumeRole"]
	}
}

data "aws_iam_policy_document" "lambda-cloudfront-auth" {
	provider = aws.us-east-1

	statement {
		actions = [
			"logs:CreateLogGroup",
			"logs:CreateLogStream",
			"logs:PutLogEvents",
		]

		resources = ["arn:aws:logs:*:*:*"]
	}

	statement {
		actions = ["s3:GetObject"]
		resources = ["${aws_s3_bucket.secure-site.arn}/*"]
	}
}

data "aws_iam_policy_document" "s3-secure-site" {
	provider = aws.site

	# Allow access from cloudfront
	statement {
		principals {
			type        = "AWS"
			identifiers = [aws_cloudfront_origin_access_identity.secure-site.iam_arn]
		}

		actions   = ["s3:GetObject"]
		resources = ["${aws_s3_bucket.secure-site.arn}/*"]
	}
}