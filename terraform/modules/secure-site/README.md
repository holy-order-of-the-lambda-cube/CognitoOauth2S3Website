# The Secure Site Module

The terraform module creates the stack of AWS resources needed to host a full secure website, aside from a few prerequisites. Notably, the module creates a codepipeline to build and deploy the function via SAM using cloudformation templates. As part of this codepipeline the source code for the function will be pulled from the github repository it is hosted in. As a result, even though you might execute the terraform module locally, the code will be pulled from the github repository on each pipeline invocation, so local changes to the function will not be reflected. In order to change the function and have those changes be reflected you should fork the repository and use the module input variables to point to your fork.

The prerequisites needed for the module are:

- A Cognito user pool to authenticate against.
- A route53 hosted domain for the secure website.
- An SSL certificate from AWS certificate manager for the domain.