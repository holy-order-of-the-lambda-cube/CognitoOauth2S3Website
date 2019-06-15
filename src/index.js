'use strict';

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const cognitoVars = require('./cognitoVars');
const https = require('https');
const querystring = require('querystring');
const keys = cognitoVars.JWKS.keys;

// This is who should have issued us an auth token
const issuer = 'https://cognito-idp.' + cognitoVars.REGION + '.amazonaws.com/' + cognitoVars.USERPOOLID;

// A cryptographically random string of bits used to generate random numbers
const seed = require('util').promisify(crypto.randomBytes)(32);

// The URI the auth server should redirect the browser to
const redirectUri = 'https://'.concat(cognitoVars.SITE_DOMAIN, '/index.html');

// The URI of the login server
const loginURI = 'https://'.concat(cognitoVars.AUTH_DOMAIN,
																	 '/authorize?code_challenge_method=S256&response_type=code&scope=openid&client_id=',
																	 cognitoVars.CLIENTID,
																	 '&redirect_uri=',
																	 redirectUri,
																	 '&state=');

// A buffer to hold random values
var stateBuffer = null;
var pems = {};

// The option for posting to the auth server. Headers are replaced with each request.
var authPostOptions = {
	hostname: cognitoVars.AUTH_DOMAIN,
	port: 443,
	path: '/token',
	method: 'POST',
	cache: 'no-cache'
}

for(var i = 0; i < keys.length; ++i) {
	// Convert each key to PEM
	var key_id = keys[i].kid;
	var modulus = keys[i].n;
	var exponent = keys[i].e;
	var key_type = keys[i].kty;
	var jwk = {kty: key_type, n: modulus, e: exponent};
	var pem = jwkToPem(jwk);
	pems[key_id] = pem;
}

// Unauthorized. We will reuse so cache it.
const response401 = {
	status: '401'
};

// Log before returning.
function response(struct) {
	console.log("Response: ", JSON.stringify(struct));
	return struct;
}

// Determine if there has been authentication yet.
const noAuthCookie = async (cookies, queryString) => {
	console.log("No auth cookie: ", cookies);

	if (queryString.code) {
		console.log("We have code");

		if (queryString.state && queryString.state === cookies['AuthState']) {
			console.log("We have matching state");
			return authorize(queryString.code, cookies);
		} else {
			console.log("State strings do not match: ", queryString.state, " ", cookies['AuthState'], " ", queryString.state === cookies['AuthState']);
			return response401;
		}
	}

	return authenticate();
}

// Redirect to the login page. Store a random token in state param and cookie. When client returns ensure state is the same to mitigate
// some impersonation and replay attacks.
const authorize = async (code, cookies) => {
	console.log("Authorizing. code: ", code, " cookies: ", cookies);

	const data = querystring.stringify({
		grant_type: 'authorization_code',
		code: code,
		redirect_uri: redirectUri,
		code_verifier: cookies['CodeVerifier']
	});

	authPostOptions.headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Content-Length': data.length,
		'Authorization' : 'Basic ' + new Buffer.from(cognitoVars.CLIENTID.concat(':', cognitoVars.CLIENT_SECRET)).toString('base64')
	}

	console.log("Posting to auth server. options: ", authPostOptions, " data: ", data);

	var tokenResponse = new Promise((resolve, reject) => {
		const req = https.request(authPostOptions, (res) => {
			console.log('response: ', res);
			console.log('code: ', res.statusCode);
			console.log('HEADERS: ', JSON.stringify(res.headers));

			// reject on bad status
			if (res.statusCode < 200 || res.statusCode >= 300) {
				return reject(new Error('statusCode=' + res.statusCode));
			}

			var body = [];

			res.on('data', (chunk) => {
				console.log("Data: ", chunk);
				body.push(chunk);
			});

			res.on('end', () => {
				console.log('No more data in response.');

				try {
					body = JSON.parse(Buffer.concat(body).toString());
				} catch(e) {
					reject(e);
				}

				console.log("recieved: ", body);
				resolve(body);
			});
		});

		// reject on request error
		req.on('error', (err) => {
			// This is not a "Second reject", just a different sort of failure
			console.log("Error: ", error);
			reject(err);
		});

		req.write(data);
		req.end();
	}).then((body) => {
		return {
			status: '303',
			headers: {
				'location': [{
					value: redirectUri
				}],
				'set-cookie': [{
					value: 'AuthState=;Max-Age=0;Secure;HttpOnly;SameSite=Strict;Domain='.concat(cognitoVars.SITE_DOMAIN)
				},{
					value: 'CodeVerifier=;Max-Age=0;Secure;HttpOnly;SameSite=Strict;Domain='.concat(cognitoVars.SITE_DOMAIN)
				},{
					value: 'AccessToken='.concat(body.access_token,
																			 ';Max-Age=',
																			 body.expires_in,
																			 ';Secure;HttpOnly;SameSite=Strict;Domain=',
																			 cognitoVars.SITE_DOMAIN)
				}]
			}
		};
	});

	console.log(tokenResponse);
	return tokenResponse;
}

const authenticate = async () => {
	console.log("Authenticating");

	// Make sure we have a buffer of entropy. Increment if we do. We will hash this constantly incrementing bucket for nonces.
	if (stateBuffer == null) {
		stateBuffer = await seed;
	} else {
		incrementBE(stateBuffer);
	}

	// The State is passed in on the URL. We set a cookie in the browser to this value. The server will return this
	// value back to us so we can check it against the cookie to make sure they match. This avoids
	// someone sending us a response that impersonates the server, as they will not have the correct
	// state value. Encoded as hex because AWS doesn't encode the + sign properly on return which is
	// used in base64, which causes us pain to try to get decodings to match, so we just do hex to keep
	// things alphanumeric.
	const stateVal = crypto.createHash('sha256').update(stateBuffer).digest('hex');
	incrementBE(stateBuffer);

	// We pass a hash of the code verifier to the server and store the verifier in a cookie.
	// The server will retain this. When we request our auth token we will pass the verifier to the server.
	// The server makes sure the hashes match before giving us the token to avoid a man in the middle attack
	// by a malicious client.
	const codeVerifier = base64URLEncode(stateBuffer);

	// Redirect them to the login page.
	return {
		status: '303',
		headers: {
			'location': [{
				value: loginURI.concat(stateVal,
															 "&code_challenge=",
															 base64URLEncode(crypto.createHash('sha256').update(codeVerifier).digest()))

			}],
			'set-cookie': [{
				value: 'AuthState='.concat(stateVal,
																	 ';Max-Age=3600;Secure;HttpOnly;SameSite=Strict;Domain=',
																	 cognitoVars.SITE_DOMAIN)
			},{
				value: 'CodeVerifier='.concat(codeVerifier,
																			';Max-Age=3600;Secure;HttpOnly;SameSite=Strict;Domain=',
																			cognitoVars.SITE_DOMAIN)
			}]
		}
	};
}

exports.handler = async (event, context, callback) => {
	const cfrequest = event.Records[0].cf.request;
	const cookies = getCookies(cfrequest.headers);
	console.log('Recieved: ' + JSON.stringify(event));

	if(!cookies['AccessToken']) {
		// TODO: Try removing await
		return response(await noAuthCookie(cookies, querystring.parse(cfrequest.querystring)));
	}

	// strip out "Bearer " to extract JWT token only
	var jwtToken = cookies['AccessToken'];
	console.log('jwtToken=' + jwtToken);

	// Fail if the token is not jwt
	var decodedJwt = jwt.decode(jwtToken, {complete: true});

	console.log("Decoded: ", decodedJwt);

	if (!decodedJwt) {
		console.log("Not a valid JWT token");
		return response401;
	}

	// Fail if token is not from your UserPool
	if (decodedJwt.payload.iss != issuer) {
		console.log("invalid issuer");
		return response401;
	}

	// Reject the jwt if it's not an 'Access Token'
	if (decodedJwt.payload.token_use != 'access') {
		console.log("Not an access token");
		return response401;
	}

	// Get the kid from the token and retrieve corresponding PEM
	var pem = pems[decodedJwt.header.kid];

	if (!pem) {
		console.log('Invalid access token');
		return response401;
	}

	// Verify the signature of the JWT token to ensure it's really coming from your User Pool
	jwt.verify(jwtToken, pem, { issuer: issuer }, function(err, payload) {
		if (err) {
			console.log('Token failed verification');
			return response401;
		} else {
			// Valid token. CloudFront can proceed to fetch the content from origin.
			console.log('Successful verification');
			callback(null, cfrequest);
			return true;
		}
	});
};

// increment a buffer in big endian
function incrementBE(buffer) {
	for (var i = buffer.length - 1; i >= 0; --i) {
		if (buffer[i]++ !== 255) break;
	}
}

// Parses the cookies from the headers
function getCookies(headers) {
	var cookies = {};

	if (headers && headers.cookie) {
		headers.cookie.forEach((cookieArray) => {
			cookieArray.value.split(';').forEach((cookie) => {
				var parts = cookie.match(/(.*?)=(.*)$/);
				cookies[parts[1].trim()] = (parts[2] || '').trim();
			});
		});
	}

	return cookies;
};

function base64URLEncode(str) {
	return str.toString('base64')
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=/g, '');
}
