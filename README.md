# oidc

Base on OAuth in action (https://github.com/oauthinaction/oauth-in-action-code)

```sh
npm install
```

## Environment configuration

Create 3 loop back interfaces on the Windows machine.

* 10.0.0.10 for the client.
* 20.0.0.25 for the authorizationServer.
* 30.0.0.30 for the protectedResource.

## Start the programs

```sh
node authorizationServer.js
# OIDC Authorization Server is listening at http://20.0.0.25:9001

node protectedResource.js
# OIDC Resource Server is listening at http://30.0.0.30:9002

node client.js
# OIDC Client is listening at http://10.0.0.10:9000
```

## Functionalities

* User authentication
* User approval
* Authorization code flow
* Session management
  * RP initiated logout - pass id_token_hint to authorizationServer when user logs out.

## Functionalities to add

* authorizationServer publishes its configuration at /.well-known/openid-configuration
* authorizationServer publishes its jwks at /jwks
* dynamic client registration
* client verify the signature of the token via the key from address-of-authorizationServer/jwks
* back-channel log out
