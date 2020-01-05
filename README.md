# sss-wrapper

Secret sharing using [sss-node](https://github.com/dsprenkels/sss-node) (node bindings to [dsprenkles/sss](https://github.com/dsprenkels/sss))

## API
```js
const secrets = require('.')
```
```js
secrets.share(secret, amount, threshold)
```
takes:
- `secret` - a string or buffer
- `amount` - the number of custodians (eg: 5)
- `threshold` - the threshold (eg: 3)

returns a promise which resolves to an array of shares

```js
secrets.combine(shares)
```
takes:
- `shares` - an array of shares

returns a promise which resolves to the recovered secret, if successful

```js
secrets.shareFixedLength, secrets.combineFixedLength
```

Functions which behave similarly to `share`, `combine`, but take a 64 byte fixed length secret.

```js
const key = secrets.encryptionKey()
```
generate an encryption key

```js
const cipherText = secrets.encrypt(message, key)
```
encrypt a message

```js
const result = secrets.decrypt(cipherText, key)
```
decrypt a message
