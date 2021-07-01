# oidc

Base on OAuth in action

```sh
npm install
```

node_modules/nosql/index.js needs to be updated

```js
// line 2388 change to
fs.close(fd, function(err, result) {});
```

Start the programs

```sh
node authorizationServer.js
node protectedResource.js
node client.js
```
