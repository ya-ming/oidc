var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var session = require('express-session');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var nosql_logout = require('nosql').load('logout.nosql');
var nosql_accounts = require('nosql').load('accounts.nosql');
var querystring = require('querystring');
var qs = require("qs");
var __ = require('underscore');
__.string = require('underscore.string');
var base64url = require('base64url');
var jose = require('jsrsasign');
var request = require("sync-request");

var app = express();

app.use(session({
	secret: 'my secret',
	resave: true,
	saveUninitialized: true
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)
app.use(bodyParser.text());
app.use(bodyParser.json({ type: 'application/json' }));

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://20.0.0.25:9001/authorize',
	tokenEndpoint: 'http://20.0.0.25:9001/token',
	userInfoEndpoint: 'http://30.0.0.30:9002/userinfo',
	logoutEndpoint: 'http://20.0.0.25:9001/logout',
	registrationEndpoint: 'http://20.0.0.25:9001/register',
	jwksEndpoint: 'http://20.0.0.25:9001/jwks',
	backchannel_logout_supported: true
};

// client information
var clients = [
	{
		"client_id": "oauth-client-1",
		"client_secret": "oauth-client-secret-1",
		"redirect_uris": ["http://10.0.0.10:9000/callback"],
		"post_logout_redirect_uri": "http://10.0.0.10:9000/post_logout_redirect_uri",
		"backchannel_logout_uri": "http://10.0.0.10:9000/backchannel_logout_uri",
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

// Helper functions

var getAccount = function (username) {
	return __.find(accounts, function (account) { return account.username == username; });
};

var checkIfAccountExists = function (req, res, callback) {
	username = req.body.username;
	nosql_accounts.find().make(function (builder) {
		builder.where('username', username);
		builder.callback(function (err, response) {
			if (response[0]) {
				console.log("We found the account: ", response[0]);
				res.render('user-register', { error: 'username not available' });
				return;
			} else {
				callback(req, res);
			}
		});
	});
};

var updatePassword = function (req, res) {
	username = req.session.username;
	password = req.body.password;
	password_new = req.body.password_new;

	nosql_accounts.update({ username: username, password: password_new }).make(function (builder) {
		builder.where('username', username);
		builder.where('password', password);
		builder.callback(function (err, count) {
			console.log('updated documents:', count);
			if (count == 0) {
				res.render('change-password', { error: 'password change failed' });
				return;
			}
			res.render('index', { info: 'password updated successfully', clients: clients, authServer: authServer });
			return;
		});
	});
};

var user_register = function (req, res) {
	nosql_accounts.insert({
		username: req.body.username,
		password: req.body.password
	});

	res.render('index', { info: 'user registered successfully', clients: clients, authServer: authServer });
	return;
}

var getAccountFromDB = function (req, res, next) {
	username = req.body.username;
	password = req.body.password;
	if (!username || !password) {
		res.render('error', { error: 'invalid username or password' });
		return;
	}

	nosql_accounts.find().make(function (builder) {
		builder.where('username', username);
		builder.callback(function (err, response) {
			if (response[0]) {
				console.log("We found the account: ", response[0]);
				var account = response[0];
				if (account.password != password) {
					res.render('error', { error: 'invalid username or password' });
					return;
				}
			} else {
				console.log('No matching account was found.');
				res.render('error', { error: 'invalid username or password' });
			}
			next();
			return;
		});
	});
};

var getClient = function (clientId) {
	return __.find(clients, function (client) { return client.client_id == clientId; });
};

var getProtectedResource = function (resourceId) {
	return __.find(protectedResources, function (resource) { return resource.resource_id == resourceId; });
};

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
	return __.filter(__.keys(body), function (s) {
		return __.string.startsWith(s, 'scope_');
	})
		.map(function (s) { return s.slice('scope_'.length); });
};

var decodeClientCredentials = function (auth) {
	var clientCredentials = new Buffer(auth.slice('basic '.length), 'base64').toString().split(':');
	var clientId = querystring.unescape(clientCredentials[0]);
	var clientSecret = querystring.unescape(clientCredentials[1]);
	return { id: clientId, secret: clientSecret };
};

var findSubFromDB = function (xxx) {
	nosql_logout.find().make(function (builder) {
		builder.where('xxx', xxx);
		builder.callback(function (err, response) {
			console.log('Found sub:', response[0].sub);

			logoutFromAllRPs(response[0].sub);

			// remove the remaining records in the database for this user
			nosql.remove().make(function (builder) {
				builder.and();
				builder.where('sub', response[0].sub);
				builder.callback(function (err, count) {
					console.log("Removed %s tokens", count);
				});
			});
		});
	});

	// clean up nosql_logout
	nosql_logout.remove().make(function (builder) {
		builder.and();
		builder.where('xxx', xxx);
		builder.callback(function (err, count) {
			console.log("Removed %s logout records", count);
		});
	});


}

var logoutFromAllRPs = function (sub) {
	nosql.find().make(function (builder) {
		builder.callback(function (err, response) {
			console.log('found client:', response);
			for (var c = 0; c < response.length; c++) {
				if (response[c].user.sub == sub) {
					console.log('send back-channel log out token to client:' + response[c].client_id);

					var client = getClient(response[c].client_id);

					var header = { 'typ': 'JWT', 'alg': rsaKey.alg, 'kid': rsaKey.kid };

					var ipayload = {
						iss: 'http://localhost:9001/',
						sub: sub,
						aud: client.client_id,
						iat: Math.floor(Date.now() / 1000),
						jti: randomstring.generate(4),
						events: { "http://schemas.openid.net/event/backchannel-logout": null }
					};

					var privateKey = jose.KEYUTIL.getKey(rsaKey);
					var logout_token = jose.jws.JWS.sign(header.alg, JSON.stringify(header), JSON.stringify(ipayload), privateKey);

					console.log('Issuing Logout token %s', logout_token);

					var headers = {
						'Content-Type': 'application/json',
						'Accept': 'application/json'
					};

					var postLogoutTokenRes = request('POST', client.backchannel_logout_uri, {
						body: JSON.stringify({ logout_token: logout_token }),
						headers: headers
					});

					if (postLogoutTokenRes.statusCode == 200) {
						console.log("Got postLogoutToken response");
					}
				}
			}
		});
	});
}

// Routes

app.get('/', function (req, res) {
	res.render('index', { info: '', clients: clients, authServer: authServer });
});

app.get('/user-register', function (req, res) {
	res.render('user-register', { error: '' });
});

app.post('/user-register', function (req, res) {
	var username = req.body.username;
	var password = req.body.password;
	var password_repeat = req.body.password_repeat;

	if (!username || !password || !password_repeat) {
		res.render('user-register', { error: 'Please fill in all required fileds' });
		return;
	}

	if (password != password_repeat) {
		res.render('user-register', { error: 'passwords do not match' });
		return;
	}

	checkIfAccountExists(req, res, user_register);
});

app.get('/change-password', function (req, res) {
	if (!req.session.loggedin) {
		res.render('index', { info: 'not allowed', clients: clients, authServer: authServer });
		return;
	}
	res.render('change-password', { error: '' });
});

app.post('/change-password', function (req, res) {
	if (!req.session.loggedin) {
		res.render('index', { info: 'not allowed', clients: clients, authServer: authServer });
		return;
	}
	var username = req.session.username;
	var password = req.body.password;
	var password_new = req.body.password_new;
	var password_repeat = req.body.password_repeat;

	if (!password || !password_new || !password_repeat) {
		res.render('change-password', { error: 'Please fill in all required fileds' });
		return;
	}

	if (password_new != password_repeat) {
		res.render('change-password', { error: 'passwords do not match' });
		return;
	}

	updatePassword(req, res);
});

app.get('/login', function (req, res) {
	if (!req.session.loggedin) {
		// access to /login without redirect from /athorize is not allowed
		res.status(400).render('error', { error: 'not allowed' });
		return;
	} else {
		res.redirect('/authorize');
	}
})

app.post('/login', getAccountFromDB, function (req, res) {
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
		return;
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
					sub: code.user.sub,
					id_token: id_token,
					logout: false
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
	console.log('Before removing record for client_id:' + client.client_id);
	console.log('       removing record for id_token:' + inToken);
	nosql.remove().make(function (builder) {
		builder.and();
		builder.where('client_id', client.client_id);
		builder.where('id_token', inToken);
		builder.callback(function (err, count) {
			console.log("Removed %s tokens", count);
		});
	});

	// save the sub and ask user if they want to logout from all RPs logged in
	rsaKeyTemp = Object.assign({}, rsaKey);
	delete rsaKeyTemp["d"];
	var pubKey = jose.KEYUTIL.getKey(rsaKeyTemp);
	var tokenParts = inToken.split('.');
	var payload = JSON.parse(base64url.decode(tokenParts[1]));
	console.log('Payload', payload);
	if (jose.jws.JWS.verify(inToken, pubKey, [rsaKey.alg])) {
		console.log('Signature validated.');
		sub = payload.sub;
		console.log('/logout sub=' + sub);

		// nosql.modify({ logout: true }).make(function (builder) {
		// 	builder.where('id_token', inToken);
		// 	builder.callback(function (err, count) {
		// 		console.log('updated documents:', count);
		// 	});
		// });

		// nosql_logout generated when redirecting the user to confirm if he/she
		// wants to logout from all RPs
		// random string 'xxx' is used to hide the sub of this user
		var xxx = randomstring.generate();
		nosql_logout.insert({ sub: sub, xxx: xxx });

		var newUrl = buildUrl('/logout/confirm', {
			xxx: xxx,
			client_id: client.client_id
		});
		res.redirect(newUrl);
	} else {
		res.status('400').json({ error: 'invalid_token_hint' });
	}

});

app.get('/logout/confirm', function (req, res) {
	var newUrl = buildUrl('/logout/confirm', req.query);
	res.render('logout', { logout_url: newUrl });
	return;
});

app.post('/logout/confirm', function (req, res) {
	// retrive xxx from the query, convert xxx back to sub in findSubFromDB()
	var xxx = req.query.xxx;
	var client_id = req.query.client_id;
	var client = getClient(client_id);

	// log out from all RPs for this user
	if (req.body.Yes) {
		findSubFromDB(xxx);
	} else {
		// do not logout from all RPs
	}

	res.redirect(client.post_logout_redirect_uri);
});

app.post('/register', function (req, res) {
	var reg = {};

	// First, we’ll see what the client has asked for as an authentication method. If
	// it hasn’t specified one, we’re going to default to using a client secret over HTTP Basic.
	if (!req.body.token_endpoint_auth_method) {
		reg.token_endpoint_auth_method = 'client_secret_basic';
	} else {
		reg.token_endpoint_auth_method = req.body.token_endpoint_auth_method;
	}

	if (!__.contains(['client_secret_basic', 'secret_post', 'none'],
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

	if (typeof (req.body.backchannel_logout_uri) == 'string') {
		reg.backchannel_logout_uri = req.body.backchannel_logout_uri;
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

app.get('/.well-known/openid-configuration', function (req, res) {
	res.status(200).json(authServer);
	return;
});

app.get('/jwks', function (req, res) {
	rsaKeyTemp = Object.assign({}, rsaKey);
	delete rsaKeyTemp["d"];
	res.status(200).json(rsaKeyTemp);
	return;
});

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();
nosql_logout.clear();

var server = app.listen(9001, '20.0.0.25', function () {
	var host = server.address().address;
	var port = server.address().port;

	console.log('OIDC Authorization Server is listening at http://%s:%s', host, port);
});

module.exports = app; // for testing

