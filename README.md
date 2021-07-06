# oidc - openid-connect

* authorizationServer, protectedResource, and client node.js webservers.

Base on OAuth in action (https://github.com/oauthinaction/oauth-in-action-code)

## Environment configuration

Create 4 loop back interfaces on the Windows machine.

* 10.0.0.10 for the client 1.
* 10.0.0.11 for the client 2, to test back-channel logout, 2 clients are needed.
* 20.0.0.25 for the authorizationServer.
* 30.0.0.30 for the protectedResource.

## Start the programs

```sh

npm install

node authorizationServer.js
# OIDC Authorization Server is listening at http://20.0.0.25:9001
# http://20.0.0.25:9001/.well-known/openid-configuration

node protectedResource.js
# OIDC Resource Server is listening at http://30.0.0.30:9002

node client.js
# OIDC Client is listening at http://10.0.0.10:9000

node client.js --ip=10.0.0.11 --port=9000
# OIDC Client is listening at http://10.0.0.11:9000

```

## Functionalities

* User authentication
* User approval
* Authorization code flow
* Session management
  * RP initiated logout - pass id_token_hint to authorizationServer when user logs out.
  * Back-channel log out
* Dynamic client registration
* authorizationServer publishes its configuration at /.well-known/openid-configuration
* client fetches authorizationServer configuration before registering to the authorizationServer
* authorizationServer publishes its jwks at /jwks
* client verifies the signature of the token via the key from address-of-authorizationServer/jwks
* Add test cases ([mocha](https://github.com/mochajs/mocha), [supertest](https://github.com/visionmedia/supertest), [chai](https://github.com/chaijs/chai))
  * authorization server
    * `node node_modules\mocha\bin\mocha test\as-test.js`

## Functionalities to add

* Add test cases
  * authorization server
  * client
  * protected resource server
* re-register to the authorization server if access from client to it failed due to `unknown-client`
* protect and error handling for all client APIs
* protect and error handling for all authorization server APIs
* protect and error handling for all protectedResource server APIs
* https
* store session data into database
