process.env.NOD_EVN = 'test';

let server = require('../authorizationServer');
const request = require('supertest');
const { expect } = require('chai');
var agent = request(server);

describe('config', () => {
    beforeEach((done) => {
        console.log('before each test');
        done();
    });

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
                .expect(200, done);
        });
    });

    describe('GET /jwks', () => {
        it('Get the public key', (done) => {
            request(server)
                .get('/jwks')
                .expect(200, done);
        });
    });

    describe('POST /register', () => {
        it('Client registeres to the server', (done) => {
            base_url = 'http://10.0.0.10:9000'
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
                })
                .expect(201, done);
        });

    });

    describe('GET /login', () => {
        it('user tries to login', (done) => {
            request(server)
                .get('/login')
                .expect(400, done);
        });
    });

    describe('GET /authorize', () => {
        it('user tries to authorize', (done) => {
            request(server)
                .get('/authorize')
                .query({
                    response_type: 'code',
                    scope: 'openid',
                    client_id: 'client_id',
                    redirect_uri: 'https://client.example.com/cb',
                    state: 'state'
                })
                .expect(200, done);
        });
    });

    describe('POST /login', () => {
        

        it('User authenticates to the server', (done) => {
            agent
                .post('/login')
                .send({ username: 'bob', password: 'bob' })
                .query({
                    response_type: 'code',
                    scope: 'openid',
                    client_id: 'client_id',
                    redirect_uri: 'https://client.example.com/cb',
                    state: 'state'
                })
                .expect('Location', '/authorize?response_type=code&scope=openid&client_id=client_id&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&state=state')
                .expect(302, done);
        });

        it('User authorize on the server', (done) => {
            agent
                .get('/authorize')
                .query({
                    response_type: 'code',
                    scope: 'openid',
                    client_id: 'client_id',
                    redirect_uri: 'https://client.example.com/cb',
                    state: 'state'
                })
                .expect((res) => {
                    
                })
                .expect(200, done);
        });
    });
});