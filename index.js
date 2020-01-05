const sss = require('shamirsecretsharing')
const sodium = require('sodium-native')
const zero = sodium.sodium_memzero
const assert = require('assert')
const SHARELENGTH = 33

module.exports = {
  encryptionKey () {
    const key = sodium.sodium_malloc(sodium.crypto_secretbox_KEYBYTES)
    sodium.randombytes_buf(key)
    return key
  },

  encrypt (message, key) {
    if (!Buffer.isBuffer(message)) message = Buffer.from(message)
    const ciphertext = Buffer.alloc(message.length + sodium.crypto_secretbox_MACBYTES)
    const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
    sodium.randombytes_buf(nonce)
    sodium.crypto_secretbox_easy(ciphertext, message, nonce, key)
    zero(message)
    return Buffer.concat([nonce, ciphertext])
  },

  decrypt (cipherText, key) {
    const nonce = cipherText.slice(0, sodium.crypto_secretbox_NONCEBYTES)
    const cipherTextWithMAC = cipherText.slice(sodium.crypto_secretbox_NONCEBYTES)
    const message = Buffer.alloc(cipherTextWithMAC.length - sodium.crypto_secretbox_MACBYTES)
    assert(
      sodium.crypto_secretbox_open_easy(message, cipherTextWithMAC, nonce, key),
      'Decryption failed!'
    )
    return message
  },

  async shareFixedLength (secret, amount, threshold) {
    assert(amount < 256, 'amount must be less than 256')
    assert(amount > 1, 'amount must be greater than 1')
    assert(Buffer.isBuffer(secret), 'secret must be a buffer')
    assert(secret.length === 32, 'secret must be 32 bytes')
    const allShares = await sss.createKeyshares(secret, 255, threshold)
    const indexes = []
    const shares = []
    do {
      const randomIndex = sodium.randombytes_uniform(256)
      if (!indexes.includes(randomIndex)) {
        indexes.push(randomIndex)
        shares.push(allShares[randomIndex])
      }
    } while (shares.length < amount)
    return shares
  },

  combineFixedLength (sharesArray) {
    return sss.combineKeyshares(sharesArray)
  },

  async share (secret, amount, threshold) {
    if (!Buffer.isBuffer(secret)) secret = Buffer.from(secret)
    if (secret.length === 64) return this.shareFixedLength(secret, amount, threshold)
    // TODO handle length < 64
    const key = this.encryptionKey()
    const encryptedMessage = this.encrypt(secret, key)
    // const paddedKey = Buffer.concat([Buffer.alloc(32), key])

    const shares = await this.shareFixedLength(key, amount, threshold)
    const packedShares = shares.map((share) => {
      const s = Buffer.concat([share, encryptedMessage])
      return s
    })

    return packedShares
  },

  async combine (packedShares) {
    const messages = []
    const shares = packedShares.map((share) => {
      messages.push(share.slice(SHARELENGTH))
      return share.slice(0, SHARELENGTH)
    })
    const key = await this.combineFixedLength(shares)
    // const key = paddedKey.slice(32)
    const message = this.decrypt(messages[0], key)
    return message
  }
}
