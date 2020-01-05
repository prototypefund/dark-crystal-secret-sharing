
Secret sharing using [sss-node](https://github.com/dsprenkels/sss-node) (node bindings to [dsprenkles/sss](https://github.com/dsprenkels/sss))

## API
```js
const secrets = require('.')
```
```js
const key = secrets.encryptionKey()
```
const cipherText = secrets.encrypt(message, key)
const result = secrets.decrypt(cipherText, key)

secrets.share(message, 5, 4).then((shares) => {
secrets.combine(shares).then((result) => {
```
