# CognitoOauth2S3Website

#### A cognito authenticated static site hosted in S3.

This Open Source project defines a function that can be used to authenticate a user that is accessing a website hosted on S3 via cloudfront against a cognito user pool using Oauth2. The authentication processes uses full Oauth2 security measures including the use of a client secret and stores the authentication token for the user in a cookie.

The project is split up into different segments for different purposes. The root of the project is for the lambda function itself. The lambda function is designed to be built as part of an AWS codepipeline and recieves, during the codebuild stage, a set of environment variables indicating other AWS resources it is meant to interact with. The lambda function is, as part of the build process, packed and minimized using webpack in order to minimize overhead at runtime.

The 'terraform' directory contains at its root a terraform script intended to be used as a standalone installation of a secure website. This script will need some parameters defined, typically in a file called 'terraform.tfvars' to indicate some user configuration that is not included in the terraform script.

Finally, under the terraform directory there is a module directory which contains the module intended to be included in larger AWS configurations to build a secure website. The included standalone terraform project uses this module itself.

## The Lambda@edge Authentication Function

The build process for this function assumes some environment variables are set.

- c_s3_target_bucket. The name of an S3 bucket where the cloudformation template will be placed.
- c_cognito_user_pool. The identifier for the cognito user pool to be used for authentication.
- c_cognito_client_id. The client Id of the secure website authenticating against the user pool.
- c_site_domain. The fully qualified domain name of the secure website.
- c_auth_domain. The fully qualified domain name for cognito.
- c_client_secret. The client secret that the website shares with cognito.

## The Terraform Module

The terraform module creates the stack of AWS resources needed to host a full secure website, aside from a few prerequisites. Notably, the module creates a codepipeline to build and deploy the function via SAM using cloudformation templates. As part of this codepipeline the source code for the function will be pulled from the github repository it is hosted in. As a result, even though you might execute the terraform module locally, the code will be pulled from the github repository on each pipeline invocation, so local changes to the function will not be reflected. In order to change the function and have those changes be reflected you should fork the repository and use the module input variables to point to your fork.

The prerequisites needed for the module are:

- A Cognito user pool to authenticate against.
- A route53 hosted domain for the secure website.
- An SSL certificate from AWS certificate manager for the domain.

The module accepts some input variables to customize the secure website.

- acm_certificate_arn. The ARN of the SSL certificate on AWS Certificate Manager.
- auth_domain. The full domain name used to access cognito.
- aws_account_id. The AWS account id of the account hosting the website.
- cognito_region. The AWS region hosting the cognito user pool. Defaults to 'us-east-1'.
- cognito_user_pool. The identifier of the cognito user pool being authenticated against.
- domain. The fully qualified domain name of the secure website.
- github_branch. The branch that hosts the version of this codebase. Defaults to 'master'.
- github_oauth_token. The name of a Secrets Manager secret in us-east-1 that contains an Oauth token to access github. This need only public access to pull the open source project into the codepipeline, so having no scopes defined will suffice and should be preferred. You can aquire such a token from github under Settings -> Developer Settings -> Personal Access Tokens. In Secrets Manager the token should be inserted in the form '{"token":"<Oauth Token>"}'. Defaults to 'github_token'.
- github_owner. The owner of the version of this codebase that you are using. Defaults to 'holy-order-of-the-lambda-cube'. If you fork the code base you should change this to point to your fork.
- github_repo. The repository name hosting this codebase. Defaults to 'CognitoOauth2S3Website'.
- hosted_zone_id. The route53 zone id for your domain.
- name_prefix. AWS resources will be prefixed by this to distinguish them from other module invocations. For instance, you might use 'test-' and 'prod-' to distinguish different stages of deployment. Defaults to blank.
- populate_site. Used to indicate whether or not to include the placeholder 'index.html' file for the website. Defaults to true.
- site_region. The AWS region that is hosting the website. Defaults to 'us-east-1'.

## The Standalone Terraform Project

The terraform directory contains a standalone terraform project in order to get a proof of concept secure website running quickly. The same prerequisites are needed as for the module, namely:

- A Cognito user pool to authenticate against.
- A route53 hosted domain for the secure website.
- An SSL certificate from AWS certificate manager for the domain.

The project takes the followining input variables:

- acm_certificate_arn. The ARN of the SSL certificate on AWS Certificate Manager.
- auth_prefix. The domain prefix for the domain which points to the Cognito authentication. Defaults to 'auth.'
- aws_account_id. The account id of the AWS account hosting the site.
- cognito_aws_region. The region which hosts the Cognito user pool. Defaults to 'us-east-1'.
- cognito_user_pool. The identifier for the Cognito user pool.
- github_oauth_token. The name of a Secrets Manager secret in us-east-1 that contains an Oauth token to access github. This need only public access to pull the open source project into the codepipeline, so having no scopes defined will suffice and should be preferred. You can aquire such a token from github under Settings -> Developer Settings -> Personal Access Tokens. In Secrets Manager the token should be inserted in the form '{"token":"<Oauth Token>"}'. Defaults to 'github_token'.
- hosted_zone_id. The route53 zone id for your domain.
- secure_prefix. The domain prefix for your secure site. Defaults to 'private.'.
- site_aws_region. The AWS region that will host the secure site. Defaults to 'us-east-1'.
- tld. The tld of your domain.

These variables can be set in a terraform.tfvars file like so:

```
aws_account_id = "<Your AWS Account Id>"
tld = "example.com"
cognito_user_pool = "us-east-1_xxxxxxxxx"
acm_certificate_arn = "arn:aws:acm:us-east-1:xxxxxxxxx:certificate/<Your Cert Id>"
hosted_zone_id = "xxxxxxxxxxx"

```

To execute the terraform project, first download the terraform executable and place it in your path. Then perform a 'terraform init' to create the terraform state files. Finally, perform 'terraform apply' to create the site. After the apply completes you can visit the codepipeline created by terraform in the AWS console to monitor for completion of the deployment. Once the deployment completes successfully you should be able to access the website at the url for the domain you provided.

You can delete the site and all resources associated with it by performing a 'terraform destroy'. Some resources may fail to destroy until propegation of certain resources, such as lambda replication or DNS updates has completed. If a destroy fails, allow time for propegation and try again. The same is possible when redeploying after a destroy.

Be aware that AWS charges will accrue for deploying this site, however these are minimal as this project uses very little AWS resources.

### Licensing

Copyright 2019, The Holy Order of the Lambda Cube

This project is licensed under your choice of the AGPL version 3 or the Monastic License 0.1 or any greater version.