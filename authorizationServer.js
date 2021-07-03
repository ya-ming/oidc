var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var session = require('express-session');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var qs = require("qs");
var __ = require('underscore');
__.string = require('underscore.string');
var base64url = require('base64url');
var jose = require('jsrsasign');
const { request } = require("http");

var app = express();

app.use(session({
	secret: 'my secret',
	resave: true,
	saveUninitialized: true
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://20.0.0.25:9001/authorize',
	tokenEndpoint: 'http://20.0.0.25:9001/token'
};

// client information
var clients = [
	{
		"client_id": "oauth-client-1",
		"client_secret": "oauth-client-secret-1",
		"redirect_uris": ["http://10.0.0.10:9000/callback"],
		"post_logout_redirect_uri": "http://10.0.0.10:9000/post_logout_redirect_uri",
		"scope": "openid profile email phone address"
	}
];

var rsaKey = {
	"alg": "RS256",
	"d": "ZXFizvaQ0RzWRbMExStaS_-yVnjtSQ9YslYQF1kkuIoTwFuiEQ2OywBfuyXhTvVQxIiJqPNnUyZR6kXAhyj__wS_Px1EH8zv7BHVt1N5TjJGlubt1dhAFCZQmgz0D-PfmATdf6KLL4HIijGrE8iYOPYIPF_FL8ddaxx5rsziRRnkRMX_fIHxuSQVCe401hSS3QBZOgwVdWEb1JuODT7KUk7xPpMTw5RYCeUoCYTRQ_KO8_NQMURi3GLvbgQGQgk7fmDcug3MwutmWbpe58GoSCkmExUS0U-KEkHtFiC8L6fN2jXh1whPeRCa9eoIK8nsIY05gnLKxXTn5-aPQzSy6Q",
	"e": "AQAB",
	"n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
	"kty": "RSA",
	"kid": "authserver"
};

var accounts = [
	{
		"username": "alice",
		"password": "alice"
	},
	{
		"username": "bob",
		"password": "bob"
	}
]

var userInfo = {
	"alice": {
		"sub": "9XE3-JI34-00132A",
		"preferred_username": "alice",
		"name": "Alice",
		"email": "alice.wonderland@example.com",
		"email_verified": true
	},

	"bob": {
		"sub": "1ZT5-OE63-57383B",
		"preferred_username": "bob",
		"name": "Bob",
		"email": "bob.loblob@example.net",
		"email_verified": false
	}
};

var getUser = function (username) {
	return userInfo[username];
};

var codes = {};

var requests = {};

var getAccount = function (username) {
	return __.find(accounts, function (account) { return account.username == username; });
};

var getClient = function (clientId) {
	return __.find(clients, function (client) { return client.client_id == clientId; });
};

var getProtectedResource = function (resourceId) {
	return __.find(protectedResources, function (resource) { return resource.resource_id == resourceId; });
};

app.get('/', function (req, res) {
	res.render('index', { clients: clients, authServer: authServer });
});

app.get('/login', function (req, res) {
	if (!req.session.loggedin) {
		res.render('login');
	} else {
		res.redirect('/authorize');
	}
})

app.post('/login', function (req, res) {
	username = req.body.username;
	password = req.body.password;
	if (!username || !password) {
		res.render('error', { error: 'invalid username or password' });
		return;
	}

	var account = getAccount(username);
	if (!account || account.password != password) {
		res.render('error', { error: 'invalid username or password' });
		return;
	}

	// user authentication passed, update the session and redirect user to authorize
	req.session.loggedin = true;
	req.session.username = username;
	console.log('logged in successfully, redirect to /authorize');
	var newUrl = buildUrl('/authorize', req.query);
	res.redirect(newUrl);
})

app.get("/authorize", function (req, res) {

	if (!req.session.loggedin) {
		// not logged in
		console.log('not logged in, redirect to /login');
		var newUrl = buildUrl('/login', req.query);
		res.render('login', { login_url: newUrl });
	} else {
		var client = getClient(req.query.client_id);

		if (!client) {
			console.log('Unknown client %s', req.query.client_id);
			res.render('error', { error: 'Unknown client' });
			return;
		} else if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
			console.log('Mismatched redirect URI, expected %s got %s', client.redirect_uris, req.query.redirect_uri);
			res.render('error', { error: 'Invalid redirect URI' });
			return;
		} else {

			var rscope = req.query.scope ? req.query.scope.split(' ') : undefined;
			var cscope = client.scope ? client.scope.split(' ') : undefined;
			if (__.difference(rscope, cscope).length > 0) {
				// client asked for a scope it couldn't have
				var urlParsed = buildUrl(req.query.redirect_uri, {
					error: 'invalid_scope'
				});
				res.redirect(urlParsed);
				return;
			}

			var reqid = randomstring.generate(8);

			requests[reqid] = req.query;

			res.render('approve', { username: req.session.username, client: client, reqid: reqid, scope: rscope });
			return;
		}

	}

});

app.post('/approve', function (req, res) {

	var reqid = req.body.reqid;
	var query = requests[reqid];
	delete requests[reqid];

	if (!query) {
		// there was no matching saved request, this is an error
		res.render('error', { error: 'No matching authorization request' });
		return;
	}

	if (req.body.approve) {
		if (query.response_type == 'code') {
			// user approved access
			var code = randomstring.generate(8);
			var user = getUser(req.session.username);
			var scope = getScopesFromForm(req.body);
			var client = getClient(query.client_id);
			var cscope = client.scope ? client.scope.split(' ') : undefined;
			if (__.difference(scope, cscope).length > 0) {
				// client asked for a scope it couldn't have
				var urlParsed = buildUrl(query.redirect_uri, {
					error: 'invalid_scope'
				});
				res.redirect(urlParsed);
				return;
			}

			// save the code and request for later
			codes[code] = { request: query, scope: scope, user: user };

			var urlParsed = buildUrl(query.redirect_uri, {
				code: code,
				state: query.state
			});
			res.redirect(urlParsed);
			return;
		} else {
			// we got a response type we don't understand
			var urlParsed = buildUrl(query.redirect_uri, {
				error: 'unsupported_response_type'
			});
			res.redirect(urlParsed);
			return;
		}
	} else {
		// user denied access
		var urlParsed = buildUrl(query.redirect_uri, {
			error: 'access_denied'
		});
		res.redirect(urlParsed);
		return;
	}

});

app.post("/token", function (req, res) {

	var auth = req.headers['authorization'];
	if (auth) {
		// check the auth header
		var clientCredentials = decodeClientCredentials(auth);
		var clientId = clientCredentials.id;
		var clientSecret = clientCredentials.secret;
	}

	// otherwise, check the post body
	if (req.body.client_id) {
		if (clientId) {
			// if we've already seen the client's credentials in the authorization header, this is an error
			console.log('Client attempted to authenticate with multiple methods');
			res.status(401).json({ error: 'invalid_client' });
			return;
		}

		var clientId = req.body.client_id;
		var clientSecret = req.body.client_secret;
	}

	var client = getClient(clientId);
	if (!client) {
		console.log('Unknown client %s', clientId);
		res.status(401).json({ error: 'invalid_client' });
		return;
	}

	if (client.client_secret != clientSecret) {
		console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
		res.status(401).json({ error: 'invalid_client' });
		return;
	}

	if (req.body.grant_type == 'authorization_code') {

		var code = codes[req.body.code];

		if (code) {
			delete codes[req.body.code]; // burn our code, it's been used
			if (code.request.client_id == clientId) {

				var access_token = randomstring.generate();

				console.log('Issuing access token %s', access_token);
				console.log('with scope %s', code.scope);

				var cscope = null;
				if (code.scope) {
					cscope = code.scope.join(' ');
				}

				var token_response = { access_token: access_token, token_type: 'Bearer', scope: cscope };

				if (__.contains(code.scope, 'openid') && code.user) {
					var header = { 'typ': 'JWT', 'alg': rsaKey.alg, 'kid': rsaKey.kid };

					var ipayload = {
						iss: 'http://localhost:9001/',
						sub: code.user.sub,
						aud: client.client_id,
						iat: Math.floor(Date.now() / 1000),
						exp: Math.floor(Date.now() / 1000) + (5 * 60)
					};
					if (code.request.nonce) {
						ipayload.nonce = code.request.nonce;
					}

					var privateKey = jose.KEYUTIL.getKey(rsaKey);
					var id_token = jose.jws.JWS.sign(header.alg, JSON.stringify(header), JSON.stringify(ipayload), privateKey);

					console.log('Issuing ID token %s', id_token);

					token_response.id_token = id_token;
				}

				// save data into the database
				nosql.insert({
					access_token: access_token, client_id: clientId,
					scope: code.scope, user: code.user,
					id_token: id_token
				});

				res.status(200).json(token_response);
				console.log('Issued tokens for code %s', req.body.code);

				return;
			} else {
				console.log('Client mismatch, expected %s got %s', code.request.client_id, clientId);
				res.status(400).json({ error: 'invalid_grant' });
				return;
			}
		} else {
			console.log('Unknown code, %s', req.body.code);
			res.status(400).json({ error: 'invalid_grant' });
			return;
		}
	} else {
		console.log('Unknown grant type %s', req.body.grant_type);
		res.status(400).json({ error: 'unsupported_grant_type' });
	}
});

app.get('/logout', function (req, res) {
	req.session.destroy();
	var client = getClient(req.query.client_id);
	if (!client) {
		console.log('Unknown client %s', req.query.client_id);
		res.render('error', { error: 'Unknown client' });
	}

	// delete tokens generated for the user
	var inToken = req.query.id_token_hint;
	console.log('Removing record for client_id:' + client.client_id);
	console.log('Removing record for id_token:' + inToken);

	nosql.remove().make(function (builder) {
		builder.and();
		builder.where('id_token', inToken);
		builder.where('client_id', client.client_id);
		builder.callback(function (err, count) {
			console.log("Removed %s tokens", count);
		});
	});

	res.redirect(client.post_logout_redirect_uri);
});

app.post('/register', function (req, res) {
	var reg = {};

	// First, we’ll see what the client has asked for as an authentication method. If
	// it hasn’t specified one, we’re going to default to using a client secret over HTTP Basic.
	if (!req.body.token_endpoint_auth_method) {
		reg.token_endpoint_auth_method = 'secret_basic';
	} else {
		reg.token_endpoint_auth_method = req.body.token_endpoint_auth_method;
	}

	if (!__.contains(['secret_basic', 'secret_post', 'none'],
		reg.token_endpoint_auth_method)) {
		res.status(400).json({ error: 'invalid_client_metadata' });
		return;
	}

	// Next, we’ll read in the grant_type and response_type values and ensure that
	// they are consistent.

	// no grant type
	if (!req.body.grant_types) {
		// no response type
		if (!req.body.response_types) {
			reg.grant_types = ['authorization_code'];
			reg.response_type = ['code'];
		} else {
			// has response type, check if it is 'code'
			if (__.contains(req.body.response_types, 'code')) {
				reg.grant_types = ['authorization_code'];
				reg.response_types = ['code'];
			} else {
				reg.grant_type = [];
			}
		}
	} else { // has grant type
		// no response type
		if (!req.body.response_types) {
			reg.grant_types = req.body.grant_types;
			// check if grant type is 'authorization_code'
			if (__.contains(req.body.grant_types, 'authorization_code')) {
				reg.response_types = ['code'];
			} else {
				reg.response_types = [];
			}
		} else {
			// has response type
			reg.grant_types = req.body.grant_types;
			reg.response_types = req.body.response_types;
			if (__.contains(req.body.grant_types, 'authorization_code') &&
				!__.contains(req.body.response_types, 'code')) {
				reg.response_types.push('code');
			}
			if (!__.contains(req.body.grant_types, 'authorization_code') &&
				__.contains(req.body.response_types, 'code')) {
				reg.grant_types.push('authorization_code');
			}
		}
	}

	if (!__.isEmpty(__.without(reg.grant_types, 'authorization_code', 'refresh_token')) ||
		!__.isEmpty(__.without(reg.response_types, 'code'))) {
		res.status(400).json({ error: 'invalid_client_metadata' });
		return;
	}

	// Next, we’ll make sure that the client has registered at least one redirect URI.
	if (!req.body.redirect_uris || !__.isArray(req.body.redirect_uris) ||
		__.isEmpty(req.body.redirect_uris)) {
		res.status(400).json({ error: 'invalid_redirect_uri' });
		return;
	} else {
		reg.redirect_uris = req.body.redirect_uris;
	}

	// Next, we’ll copy over the other fields that we care about, checking their data types on
	// the way.
	if (typeof (req.body.client_name) == 'string') {
		reg.client_name = req.body.client_name;
	}

	if (typeof (req.body.client_uri) == 'string') {
		reg.client_uri = req.body.client_uri;
	}

	if (typeof (req.body.post_logout_redirect_uri) == 'string') {
		reg.post_logout_redirect_uri = req.body.post_logout_redirect_uri;
	}

	if (typeof (req.body.logo_uri) == 'string') {
		reg.logo_uri = req.body.logo_uri;
	}

	if (typeof (req.body.scope) == 'string') {
		reg.scope = req.body.scope;
	}

	// Finally, we’ll generate a client ID and, if the client is using an appropriate token endpoint
	// authentication method, a client secret.
	reg.client_id = randomstring.generate();
	if (__.contains(['client_secret_basic', 'client_secret_post']), reg.token_endpoint_auth_method) {
		reg.client_secret = randomstring.generate();
	}

	reg.client_id_created_at = Math.floor(Date.now() / 1000);
	reg.client_secret_expires_at = 0;

	clients.push(reg);

	res.status(201).json(reg);
	return;
});

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

var getScopesFromForm = function (body) {
	return __.filter(__.keys(body), function (s) { return __.string.startsWith(s, 'scope_'); })
		.map(function (s) { return s.slice('scope_'.length); });
};

var decodeClientCredentials = function (auth) {
	var clientCredentials = new Buffer(auth.slice('basic '.length), 'base64').toString().split(':');
	var clientId = querystring.unescape(clientCredentials[0]);
	var clientSecret = querystring.unescape(clientCredentials[1]);
	return { id: clientId, secret: clientSecret };
};

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

var server = app.listen(9001, '20.0.0.25', function () {
	var host = server.address().address;
	var port = server.address().port;

	console.log('OIDC Authorization Server is listening at http://%s:%s', host, port);
});

