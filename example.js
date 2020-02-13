const secrets = require('.')

const message = 'its nice to be important but its more important to be nice'

console.log('Secret to share:', message)

console.log('Creating 5 shares, 3 needed to recover')
secrets.share(message, 5, 3).then((shares) => {
  console.log(shares.map(s => s.toString('hex')))
  secrets.combine(shares.slice(2)).then((result) => {
    console.log('Result of recombining 3 shares:', result.toString())
  })
})
