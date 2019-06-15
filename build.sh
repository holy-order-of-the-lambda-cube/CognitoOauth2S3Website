#!/bin/bash -x

# Put the cognito pool and keys into variables
echo exports.USERPOOLID = \"${c_cognito_user_pool}\"\; > src/cognitoVars.js

echo exports.JWKS = $(curl -s https://cognito-idp.`echo ${c_cognito_user_pool} | cut -f 1 -d _`.amazonaws.com/${c_cognito_user_pool}/.well-known/jwks.json)\; >> src/cognitoVars.js

echo exports.REGION = \"`echo ${c_cognito_user_pool} | cut -f 1 -d _`\"\; >> src/cognitoVars.js

echo exports.CLIENTID = \"${c_cognito_client_id}\"\; >> src/cognitoVars.js

echo exports.SITE_DOMAIN = \"${c_site_domain}\"\; >> src/cognitoVars.js

echo exports.AUTH_DOMAIN = \"${c_auth_domain}\"\; >> src/cognitoVars.js

echo exports.CLIENT_SECRET = \"${c_client_secret}\"\; >> src/cognitoVars.js

webpack --mode $1
