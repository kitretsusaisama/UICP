const fs = require('fs');
const path = require('path');
const file = path.join(__dirname, '../src/application/services/otp.service.ts');

let code = fs.readFileSync(file, 'utf8');

// Fix OTP 300 hardcoded TTL to dynamic TTL based on this.ttlS
code = code.replace(
  /local current = redis\.call\('GET', KEYS\[2\]\)\n\s*if current then return -1 end\n\s*local exists = redis\.call\('GET', KEYS\[1\]\)\n\s*if not exists then return -2 end\n\s*redis\.call\('SET', KEYS\[2\], '1', 'EX', 300\)/,
  `local current = redis.call('GET', KEYS[2])
      if current then return -1 end
      local exists = redis.call('GET', KEYS[1])
      if not exists then return -2 end
      redis.call('SET', KEYS[2], '1', 'EX', ARGV[1])`
);

// Update eval args to pass this.ttlS
code = code.replace(
  /resultCode = await client\.eval\(luaScript, 2, key, consumedKey\);/,
  `resultCode = await client.eval(luaScript, 2, key, consumedKey, this.ttlS);`
);

// Update fallback path
code = code.replace(
  /await this\.cache\.set\(consumedKey, '1', 300\);/,
  `await this.cache.set(consumedKey, '1', this.ttlS);`
);

fs.writeFileSync(file, code);
