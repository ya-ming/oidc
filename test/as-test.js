process.env.NOD_EVN = 'test';

let server = require('../authorizationServer');
let chai = require('chai');
let chaiHttp = require('chai-http');
let should = chai.should();

chai.use(chaiHttp);
describe('config', () => {
    beforeEach((done) => {
        console.log('before each test');
        done();
    });

    describe('/GET invalid_url', () => {
        it('it should return 404', (done) => {
            chai.request(server)
                .get('/invalid_url')
                .end((err, res) => {
                    res.should.have.status(404);
                    done();
                });
        });
    });

    describe('/GET .well-known/openid-configuration', () => {
        it('it should GET the oidc configurations', (done) => {
            chai.request(server)
                .get('/.well-known/openid-configuration')
                .end((err, res) => {
                    res.should.have.status(200);
                    res.body.should.be.a('Object');
                    done();
                });
        });
    });

    describe('/GET jwks', () => {
        it('it should GET the public key', (done) => {
            chai.request(server)
                .get('/jwks')
                .end((err, res) => {
                    res.should.have.status(200);
                    res.body.should.be.a('Object');
                    done();
                });
        });
    });

    describe('/POST register', () => {
        it('it should POST a client registration', (done) => {
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

            chai.request(server)
                .post('/register')
                .send(
                    template
                )
                .end((err, res) => {
                    res.should.have.status(201);
                    res.body.should.contain.keys('client_id', 'client_secret');
                    res.body.should.have.property('token_endpoint_auth_method', 'client_secret_basic');
                    res.body.should.have.property('grant_types').and.eql(['authorization_code']);
                    res.body.should.have.property('response_types').and.eql(['code']);
                    done();
                });
        });

    });
});