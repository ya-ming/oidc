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
const { Stats } = require("fs");
__.string = require('underscore.string');


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
	"client_id": "oauth-client-1",
	"client_secret": "oauth-client-secret-1",
	"redirect_uris": ["http://10.0.0.10:9000/callback"],
	"scope": "openid profile email phone address"
};

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://20.0.0.25:9001/authorize',
	tokenEndpoint: 'http://20.0.0.25:9001/token',
	userInfoEndpoint: 'http://30.0.0.30:9002/userinfo',
	logoutEndpoint: 'http://20.0.0.25:9001/logout'
};

var rsaKey = {
	"alg": "RS256",
	"e": "AQAB",
	"n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
	"kty": "RSA",
	"kid": "authserver"
};

var protectedResource = 'http://30.0.0.30:9002/resource';

app.get('/', function (req, res) {
	res.render('login', { access_token: req.session.access_token, refresh_token: req.session.refresh_token, scope: req.session.scope });
});

app.get('/login', function (req, res) {
	res.redirect('/authorize');
});

app.get('/authorize', function (req, res) {

	req.session.access_token = null;
	req.session.refresh_token = null;
	req.session.scope = null;
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

			// check the id token
			var pubKey = jose.KEYUTIL.getKey(rsaKey);
			var tokenParts = body.id_token.split('.');
			var payload = JSON.parse(base64url.decode(tokenParts[1]));
			console.log('Payload', payload);
			if (jose.jws.JWS.verify(body.id_token, pubKey, [rsaKey.alg])) {
				console.log('Signature validated.');
				if (payload.iss == 'http://localhost:9001/') {
					console.log('issuer OK');
					if ((Array.isArray(payload.aud) && __.contains(payload.aud, client.client_id)) ||
						payload.aud == client.client_id) {
						console.log('Audience OK');

						var now = Math.floor(Date.now() / 1000);

						if (payload.iat <= now) {
							console.log('issued-at OK');
							if (payload.exp >= now) {
								console.log('expiration OK');

								console.log('Token valid!');

								// save just the payload, not the container (which has been validated)
								req.session.id_token = payload;
							}
						}
					}
				}
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

app.get('/userinfo', function (req, res) {

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

app.get('/logout', function (req, res) {
	req.session.destroy();

	var logout = buildUrl(authServer.logoutEndpoint, {
		client_id: client.client_id,
	});
	res.redirect(logout);
});

app.get('/post_logout_redirect_uri', function (req, res) {
	res.redirect('/');
})

app.use('/', express.static('files/client'));

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

var server = app.listen(9000, '10.0.0.10', function () {
	var host = server.address().address;
	var port = server.address().port;
	console.log('OAuth Client is listening at http://%s:%s', host, port);
});

