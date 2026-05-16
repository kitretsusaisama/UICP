const { generateKeyPairSync, randomBytes } = require('crypto');

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 4096,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem',
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
  },
});

console.log('JWT_PRIVATE_KEY_ENC=');
console.log(JSON.stringify(privateKey));

console.log('\nJWT_PUBLIC_KEY=');
console.log(JSON.stringify(publicKey));

console.log('\nJWT_SECRET=');
console.log(randomBytes(32).toString('hex'));