var fs = require('fs');
var https = require('https');
var express = require("express");
var bodyParser = require('body-parser');
var session = require('express-session');
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var jose = require('jsrsasign');
var base64url = require('base64url');
var __ = require('underscore');
__.string = require('underscore.string');

var argv = require('yargs/yargs')(process.argv.slice(2)).argv;

var ip = '10.0.0.10';
var port = 9000;

if (argv.ip) {
	ip = argv.ip;
}

if (argv.port) {
	port = argv.port;
}

const options = {
	key: fs.readFileSync('files/certs/client-key.pem'),
	cert: fs.readFileSync('files/certs/client-cert.pem')
};
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

var base_url = 'https://' + ip + ':' + port;
console.log('base_url: ' + base_url);

var app = express();

app.use(session({
	secret: 'client secret',
	resave: true,
	saveUninitialized: true
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// client information

var client = {
	// "client_id": "oauth-client-1",
	// "client_secret": "oauth-client-secret-1",
	// "redirect_uris": [base_url + "/callback"],
	// "scope": "openid profile email phone address"
};

// authorization server information
var authServer = {
	// authorizationEndpoint: 'https://20.0.0.25:9001/authorize',
	// tokenEndpoint: 'https://20.0.0.25:9001/token',
	// userInfoEndpoint: 'https://30.0.0.30:9002/userinfo',
	// logoutEndpoint: 'https://20.0.0.25:9001/logout',
	// registrationEndpoint: 'https://20.0.0.25:9001/register'
	// jwksEndpoint: 'https://20.0.0.25:9001/jwks'
	openid_configuration: 'https://20.0.0.25:9001/.well-known/openid-configuration'
};

var rsaKey = {
	// "alg": "RS256",
	// "e": "AQAB",
	// "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
	// "kty": "RSA",
	// "kid": "authserver"
};

var protectedResource = 'https://30.0.0.30:9002/resource';

// helper functions

var isLoggedIn = function (req, res, next) {
	if (!req.session.loggedin) {
		res.redirect('/');
		return;
	}
	next();
	return;
}

var registerClient = function () {

	var template = {
		client_name: 'OAuth in Action Dynamic Test Client',
		client_uri: base_url + '/',
		redirect_uris: [base_url + '/callback'],
		post_logout_redirect_uri: base_url + '/post_logout_redirect_uri',
		backchannel_logout_uri: base_url + '/backchannel_logout_uri',
		grant_types: ['authorization_code'],
		response_types: ['code'],
		token_endpoint_auth_method: 'client_secret_basic',
		scope: 'openid profile email phone address'
	};

	var headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json'
	};

	var regRes = request('POST', authServer.registrationEndpoint, {
		body: JSON.stringify(template),
		headers: headers
	});

	if (regRes.statusCode == 201) {
		var body = JSON.parse(regRes.getBody());
		console.log("Got registered client", body);
		if (body.client_id) {
			client = body;
		}
	}
};

var fetchAuthServerConfiguration = function () {
	var configurationRes = request('GET', authServer.openid_configuration);

	if (configurationRes.statusCode == 200) {
		var body = JSON.parse(configurationRes.getBody());
		console.log("Got authorizationServer configuration", body);
		body.openid_configuration = authServer.openid_configuration;
		authServer = body;
	}

	var jwksRes = request('GET', authServer.jwksEndpoint);

	if (jwksRes.statusCode == 200) {
		var body = JSON.parse(jwksRes.getBody());
		console.log("Got jwks", body);
		rsaKey = body;
	}
}

var destroySession = function (req, iss, sub) {
	console.log("destroy session for iss:" + iss + ", sub:" + sub);

	var sessions = req.sessionStore.sessions;
	for (var sid in sessions) {
		var session = JSON.parse(sessions[sid]);
		if (session.id_token && session.id_token.iss && session.id_token.sub) {
			console.log("sid:" + sid + ", iss:" + session.id_token.iss + ", sub:" + session.id_token.sub);
			if (iss == session.id_token.iss && sub == session.id_token.sub) {
				console.log("destroy session sid:" + sid);
				req.sessionStore.destroy(sid, function (err) { });
			}
		}
	}
}

var buildUrl = function (base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function (value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}

	return url.format(newUrl);
};

var encodeClientCredentials = function (clientId, clientSecret) {
	return new Buffer(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
};

var validateIdToken = function (rsaKey, body, payload, client_id) {
	var pubKey = jose.KEYUTIL.getKey(rsaKey);
	if (jose.jws.JWS.verify(body.id_token, pubKey, [rsaKey.alg])) {
		console.log('Signature validated.');
		if (payload.iss == authServer.issuer) {
			console.log('issuer OK');
			if ((Array.isArray(payload.aud) && __.contains(payload.aud, client_id)) ||
				payload.aud == client_id) {
				console.log('Audience OK');

				var now = Math.floor(Date.now() / 1000);

				if (payload.iat <= now) {
					console.log('issued-at OK');
					if (payload.exp >= now) {
						console.log('expiration OK');
						console.log('Token valid!');
						return true;
					}
				}
			}
		}
	}
	return false;
}

// Routes

app.get('/', function (req, res) {
	res.render('login', { access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope });
});

app.get('/login', function (req, res) {
	res.redirect('/authorize');
});

app.get('/authorize', function (req, res) {

	// render 'userinfo' if already logged in
	if (req.session.loggedin) {
		res.render('userinfo', { userInfo: req.session.userInfo, id_token: req.session.id_token });
		return;
	}

	// if not authenticated, start oidc procedure
	if (!authServer.authorizationEndpoint) {
		fetchAuthServerConfiguration();
	}

	if (!client.client_id) {
		registerClient();
		if (!client.client_id) {
			res.render('error', { error: 'Unable to register client.' });
			return;
		}
	}

	req.session.access_token = null;
	req.session.refresh_token = null;
	req.session.scope = null;
	req.session.loggedin = false;
	req.session.state = randomstring.generate();

	var authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
		response_type: 'code',
		scope: client.scope,
		client_id: client.client_id,
		redirect_uri: client.redirect_uris[0],
		state: req.session.state
	});

	console.log("redirect", authorizeUrl);
	res.redirect(authorizeUrl);
});

app.get("/callback", function (req, res) {

	if (req.query.error) {
		// it's an error response, act accordingly
		res.render('error', { error: req.query.error });
		return;
	}

	var resState = req.query.state;

	if (resState == req.session.state) {
		console.log('State value matches: expected %s got %s', session.state, resState);
	} else {
		console.log('State DOES NOT MATCH: got %s', resState);
		res.render('error', { error: 'State value did not match' });
		return;
	}

	var code = req.query.code;

	var form_data = qs.stringify({
		grant_type: 'authorization_code',
		code: code,
		redirect_uri: client.redirect_uris[0]
	});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
	};

	var tokRes = request('POST', authServer.tokenEndpoint,
		{
			body: form_data,
			headers: headers
		}
	);

	console.log('Requesting access token for code %s', code);

	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());

		req.session.access_token = body.access_token;
		console.log('Got access token: %s', req.session.access_token);
		if (body.refresh_token) {
			req.session.refresh_token = body.refresh_token;
			console.log('Got refresh token: %s', req.session.refresh_token);
		}

		scope = body.scope;
		console.log('Got scope: %s', scope);

		if (body.id_token) {
			req.session.userInfo = null;
			req.session.id_token = null;

			console.log('Got ID token: %s', body.id_token);

			// validate the id token
			var tokenParts = body.id_token.split('.');
			var payload = JSON.parse(base64url.decode(tokenParts[1]));
			console.log('Payload', payload);
			if (validateIdToken(rsaKey, body, payload, client.client_id)) {
				// save just the payload, not the container (which has been validated)
				req.session.id_token = payload;
				req.session.id_token_hint = body.id_token;
				req.session.loggedin = true;
			}
			res.render('userinfo', { userInfo: req.session.userInfo, id_token: req.session.id_token });
			return;
		}
		res.render('index', { access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope });
		return;
	} else {
		res.render('error', { error: 'Unable to fetch access token, server response: ' + tokRes.statusCode })
		return;
	}
});

app.get('/fetch_resource', function (req, res) {

	if (!req.session.access_token) {
		res.render('error', { error: 'Missing access token.' });
		return;
	}

	console.log('Making request with access token %s', req.session.access_token);

	var headers = {
		'Authorization': 'Bearer ' + req.session.access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};

	var resource = request('POST', protectedResource,
		{ headers: headers }
	);

	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		res.render('data', { resource: body });
		return;
	} else {
		req.session.access_token = null;
		res.render('error', { error: 'Server returned response code: ' + resource.statusCode });
		return;
	}

});

app.get('/userinfo', isLoggedIn, function (req, res) {
	var headers = {
		'Authorization': 'Bearer ' + req.session.access_token
	};

	var resource = request('GET', authServer.userInfoEndpoint,
		{ headers: headers }
	);
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		console.log('Got data: ', body);

		req.session.userInfo = body;

		res.render('userinfo', { userInfo: req.session.userInfo, id_token: req.session.id_token });
		return;
	} else {
		res.render('error', { error: 'Unable to fetch user information' });
		return;
	}

});

app.get('/logout', isLoggedIn, function (req, res) {
	var logout = buildUrl(authServer.logoutEndpoint, {
		client_id: client.client_id,
		id_token_hint: req.session.id_token_hint,
	});

	req.session.destroy();
	res.redirect(logout);
});

app.get('/post_logout_redirect_uri', function (req, res) {
	res.redirect('/');
})

app.post('/backchannel_logout_uri', function (req, res) {
	if (req.body.logout_token) {
		console.log('Got Logout token: %s', req.body.logout_token);

		// check the id token
		var pubKey = jose.KEYUTIL.getKey(rsaKey);
		var tokenParts = req.body.logout_token.split('.');
		var payload = JSON.parse(base64url.decode(tokenParts[1]));
		console.log('Payload', payload);
		if (jose.jws.JWS.verify(req.body.logout_token, pubKey, [rsaKey.alg])) {
			console.log('Signature validated.');
			if (payload.iss == authServer.issuer) {
				console.log('issuer OK');
				if ((Array.isArray(payload.aud) && __.contains(payload.aud, client.client_id)) ||
					payload.aud == client.client_id) {
					console.log('Audience OK');

					var now = Math.floor(Date.now() / 1000);

					if (payload.iat <= now) {
						console.log('issued-at OK');

						destroySession(req, payload.iss, payload.sub);

						res.status(200).json();
						return;
					}
				}
			}
		}
	}

	res.status(400).json();
	return;
});

app.use('/', express.static('files/client'));

var server = https.createServer(options, app);

server.listen(port, ip, function () {
	var host = server.address().address;
	var port = server.address().port;
	console.log('OIDC Client is listening at https://%s:%s', host, port);
});

exports.encodeClientCredentials = encodeClientCredentials;
exports.validateIdToken = validateIdToken;