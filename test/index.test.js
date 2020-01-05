const { describe } = require('tape-plus')
const secrets = require('..')

const message = 'its nice to be important but its more important to be nice'

describe('basic', (context) => {
  context('encrypt and decrypt', (assert, next) => {
    const key = secrets.encryptionKey()
    const cipherText = secrets.encrypt(message, key)
    assert.ok(cipherText.length, 'ciphertext exists')
    const result = secrets.decrypt(cipherText, key)
    assert.equal(result.toString(), message, 'decryption successful')
    next()
  })

  context('share a secret', (assert, next) => {
    secrets.share(message, 5, 4).then((shares) => {
      assert.equal(shares.length, 5, 'correct number of shares')
      secrets.combine(shares).then((result) => {
        assert.equal(result.toString(), message, 'decryption successful')
        next()
      })
    })
  })
})
