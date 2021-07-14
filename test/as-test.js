process.env.NOD_EVN = 'test';

let server = require('../authorizationServer');
const request = require('supertest');
const { expect } = require('chai');
var base64url = require('base64url');

const client = require('../client');
var agent = request(server);

function delay(interval) {
    return it('delay', done => {
        setTimeout(() => done(), interval)

    }).timeout(interval + 100) // The extra 100ms should guarantee the test will not fail due to exceeded timeout
}

let rsaKey = null;
let Cookies = null;
let client_id = null;
let client_secret = null;
let issuer = null;
let reqid = null;
let _csrfInbody = null;
let code = null;
let access_token = null;
let id_token = null;
const delays = 200;

describe('config', () => {
    beforeEach((done) => {
        // console.log('before each test');
        done();
    });

    // Client to Authorization Server
    describe('GET /invalid_url', () => {
        it('it should return 404', (done) => {
            request(server)
                .get('/invalid_url')
                .expect(404, done);
        });
    });

    describe('GET /.well-known/openid-configuration', () => {
        it('Get the oidc configurations', (done) => {
            request(server)
                .get('/.well-known/openid-configuration')
                .expect((res) => {
                    issuer = res.body.issuer;
                })
                .expect(200, done);
        });
    });

    describe('GET /jwks', () => {
        it('Get the public key', (done) => {
            request(server)
                .get('/jwks')
                .expect((res) => {
                    rsaKey = res.body;
                })
                .expect(200, done);
        });
    });

    describe('POST /register', () => {
        it('Client registeres to the server', (done) => {
            base_url = 'http://client.example.com'
            var template = {
                client_name: 'OAuth in Action Dynamic Test Client',
                client_uri: base_url + '/',
                redirect_uris: [base_url + '/cb'],
                post_logout_redirect_uri: base_url + '/post_logout_redirect_uri',
                backchannel_logout_uri: base_url + '/backchannel_logout_uri',
                grant_types: ['authorization_code'],
                response_types: ['code'],
                token_endpoint_auth_method: 'client_secret_basic',
                scope: 'openid profile email phone address'
            };

            request(server)
                .post('/register')
                .send(
                    template
                )
                .expect((res) => {
                    expect((res.body)).contain.keys('client_id', 'client_secret');
                    expect((res.body)).have.property('token_endpoint_auth_method', 'client_secret_basic');
                    expect((res.body)).have.property('grant_types').and.eql(['authorization_code']);
                    expect((res.body)).property('response_types').and.eql(['code']);
                    client_id = res.body.client_id;
                    client_secret = res.body.client_secret;
                })
                .expect(201, done);
        });

        delay(delays);
    });

    // User to Authorization Server
    describe('GET /login', () => {
        it('user tries to login', () => {
            agent
                .get('/login')
                .expect(400)
                .then((res) => {
                    // Save the cookie to use it later to retrieve the session
                    Cookies = res.headers['set-cookie'].pop().split(';')[0];
                });
        });

        delay(delays);
    });

    describe('User login, authorize, client fetch the id_token', () => {
        it('GET /authorize: User tries to authorize', (done) => {
            agent
                .get('/authorize')
                .set('Cookie', Cookies)
                .query({
                    response_type: 'code',
                    scope: 'openid',
                    client_id: client_id,
                    redirect_uri: 'http://client.example.com/cb',
                    state: 'state'
                })
                .expect((res) => {
                    // save the csrf token from cookie                 
                    var tempString = res.headers['set-cookie'].pop().split(';')[0];
                    Cookies = Cookies + '; ' + tempString;
                    // save the csrf token from body
                    index = res.text.indexOf('name="_csrf" value="');
                    end = res.text.indexOf('"', index + 20);
                    _csrfInbody = res.text.substring(index + 20, end);
                })
                .expect(200, done);
        });

        delay(delays);

        it('POST /login: User authenticates to the server', (done) => {
            agent
                .post('/login')
                .set('Cookie', Cookies)
                .send({ username: 'bob', password: 'bob', _csrf: _csrfInbody })
                .query({
                    response_type: 'code',
                    scope: 'openid',
                    client_id: client_id,
                    redirect_uri: 'http://client.example.com/cb',
                    state: 'state'
                })
                .expect('Location', '/authorize?response_type=code&scope=openid&client_id=' +
                    client_id + '&redirect_uri=http%3A%2F%2Fclient.example.com%2Fcb&state=state')
                .expect(302, done);
        });
        delay(delays);

        it('GET /authorize: User authorize on the server', (done) => {
            agent
                .get('/authorize')
                .set('Cookie', Cookies)
                .query({
                    response_type: 'code',
                    scope: 'openid',
                    client_id: client_id,
                    redirect_uri: 'http://client.example.com/cb',
                    state: 'state'
                })
                .expect((res) => {
                    // save the reqid
                    let index = res.text.indexOf('name="reqid" value="');
                    let end = res.text.indexOf('"', index + 20);
                    reqid = res.text.substring(index + 20, end);

                    // save the csrf token from body
                    index = res.text.indexOf('name="_csrf" value="');
                    end = res.text.indexOf('"', index + 20);
                    _csrfInbody = res.text.substring(index + 20, end);
                })
                .expect(200, done);
        });

        delay(delays);

        it('POST /approve: User approve on the server', (done) => {
            agent
                .post('/approve')
                .set('Cookie', Cookies)
                .query({
                    response_type: 'code',
                    scope: 'openid',
                    client_id: client_id,
                    redirect_uri: 'http://client.example.com/cb',
                    state: 'state'
                })
                .send({ approve: 'approve', reqid: reqid, scope_openid: 'scope_openid', _csrf: _csrfInbody })
                .expect((res) => {
                    expect(res.headers).have.property('location');
                    // save the code
                    location = res.headers['location'];
                    code = location.substring(location.indexOf('code=') + 5, location.indexOf('&state='));
                    expect(code.length, 8);
                })
                .expect(302, done);
        });

        it('POST /token: Client fetch tokens', (done) => {
            agent
                .post('/token')
                .set('Content-Type', 'application/x-www-form-urlencoded')
                .set('Authorization', 'Basic ' + client.encodeClientCredentials(client_id, client_secret))
                .send({
                    grant_type: 'authorization_code',
                    code: code,
                    redirect_uri: 'http://client.example.com/cb',
                    state: 'state'
                })
                .expect((res) => {
                    expect((res.body)).contain.keys('access_token', 'id_token');
                    access_token = res.body.access_token;
                    id_token = res.body.id_token;
                    var tokenParts = res.body.id_token.split('.');
                    var payload = JSON.parse(base64url.decode(tokenParts[1]));
                    expect(client.validateIdToken(rsaKey, res.body, payload, client_id, issuer)).to.be.true;
                })
                .expect(200, done);
        });

        delay(delays);
    });
});