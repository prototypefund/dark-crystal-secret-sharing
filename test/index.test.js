const { describe } = require('tape-plus')
const sodium = require('sodium-native')
const secrets = require('..')

const message = 'its nice to be important but its more important to be nice'

describe('encrypt and decrypt', (context) => {
  context('basic', (assert, next) => {
    const key = secrets.encryptionKey()
    const cipherText = secrets.encrypt(message, key)
    assert.ok(cipherText.length, 'ciphertext exists')
    assert.true(cipherText.toString() !== Buffer.from(message), 'ciphertext !== message')
    const result = secrets.decrypt(cipherText, key)
    assert.equal(result.toString(), message, 'decryption successful')
    next()
  })

  context('fails on bad key', (assert, next) => {
    const key = secrets.encryptionKey()
    const cipherText = secrets.encrypt(message, key)
    assert.ok(cipherText.length, 'ciphertext exists')
    assert.true(cipherText.toString() !== Buffer.from(message), 'ciphertext !== message')
    let result
    try {
      result = secrets.decrypt(cipherText, secrets.encryptionKey())
    } catch (err) {
      assert.ok(err, 'throws error')
      next()
    }
    assert.notOk(result, 'no result given')
  })

  context('fails on bad cipherText', (assert, next) => {
    const key = secrets.encryptionKey()
    let cipherText = secrets.encrypt(message, key)
    assert.ok(cipherText.length, 'ciphertext exists')
    assert.true(cipherText.toString() !== Buffer.from(message), 'ciphertext !== message')
    sodium.randombytes_buf(cipherText)
    let result
    try {
      result = secrets.decrypt(cipherText, secrets.encryptionKey())
    } catch (err) {
      assert.ok(err, 'throws error')
      next()
    }
    assert.notOk(result, 'no result given')
  })
})

describe('secret sharing', (context) => {
  context('share a secret', (assert, next) => {
    secrets.share(message, 5, 4).then((shares) => {
      assert.equal(shares.length, 5, 'correct number of shares')
      shares.pop()
      secrets.combine(shares).then((result) => {
        assert.equal(result.toString(), message, 'decryption successful')
        next()
      })
    })
  })

  context('fails on bad share', (assert, next) => {
    secrets.share(message, 5, 4).then((shares) => {
      assert.equal(shares.length, 5, 'correct number of shares')
      shares.pop()
      sodium.randombytes_buf(shares[0])
      secrets.combine(shares).then((result) => {
        assert.notOk(result, 'decryption not successful')
      }).catch((err) => {
        assert.ok(err, 'throws error')
        next()
      })
    })
  })

  context('fails on not enough shares', (assert, next) => {
    secrets.share(message, 5, 4).then((shares) => {
      assert.equal(shares.length, 5, 'correct number of shares')
      shares.pop()
      shares.pop()
      secrets.combine(shares).then((result) => {
        assert.notOk(result, 'decryption not successful')
      }).catch((err) => {
        assert.ok(err, 'throws error')
        next()
      })
    })
  })

  context('combine key only', (assert, next) => {
    const key = secrets.encryptionKey()
    secrets.shareFixedLength(key, 5, 4).then((shares) => {
      assert.equal(shares.length, 5, 'correct number of shares')
      secrets.combineFixedLength(shares).then((result) => {
        assert.equal(result.toString('hex'), key.toString('hex'), 'decryption successful')
        next()
      }).catch((err) => {
        assert.error(err, 'no error')
      })
    })
  })
  context('fails on bad share on combine key only', (assert, next) => {
    const key = secrets.encryptionKey()
    secrets.shareFixedLength(key, 5, 4).then((shares) => {
      assert.equal(shares.length, 5, 'correct number of shares')
      shares.pop()
      shares.pop()
      // sodium.randombytes_buf(shares[0])
      secrets.combineFixedLength(shares).then((result) => {
        assert.notOk(result, 'decryption not successful')
        console.log(result.toString('hex'))
        console.log(key.toString('hex'))
      }).catch((err) => {
        assert.ok(err, 'throws error')
        console.log(err)
        next()
      })
    })
  })
})
