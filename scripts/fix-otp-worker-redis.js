const fs = require('fs');
const path = require('path');
const file = path.join(__dirname, '../src/infrastructure/queue/workers/otp-send.worker.ts');

let code = fs.readFileSync(file, 'utf8');

// Replace dynamic ioredis instantiation with the provided redisClient logic
code = code.replace(
  /const Redis = require\('ioredis'\);\n\s*const redisClient = new Redis\(this\.connection\);/g,
  `const redisClient = this.connection as any;`
);

// Ensure finally block for quit is removed since we share the client now
code = code.replace(
  /await redisClient\.quit\(\);/g,
  `// Shared connection, do not quit`
);

fs.writeFileSync(file, code);
