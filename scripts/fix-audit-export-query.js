const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '../src/infrastructure/queue/workers/audit-export.worker.ts');
let code = fs.readFileSync(file, 'utf8');

// The original query used UNIX_TIMESTAMP(created_at) which breaks index use.
// We rewrite it to use FROM_UNIXTIME to convert the JS milliseconds boundary to native Date comparison.
code = code.replace(
  /WHERE tenant_id = \? AND UNIX_TIMESTAMP\(created_at\) \* 1000 >= \? AND UNIX_TIMESTAMP\(created_at\) \* 1000 <= \?/,
  "WHERE tenant_id = ? AND created_at >= FROM_UNIXTIME(? / 1000) AND created_at <= FROM_UNIXTIME(? / 1000)"
);

// We also must ensure we await writeStream.end() natively
code = code.replace(
  /writeStream\.end\(\);\n\n\s*await this\.dbPool\.query\(/,
  `await new Promise((resolve) => { writeStream.end(resolve); });

       await this.dbPool.query(`
);

fs.writeFileSync(file, code);

// Fix AdminController.removeDevice key format
const adminFile = path.join(__dirname, '../src/interface/http/controllers/admin.controller.ts');
let adminCode = fs.readFileSync(adminFile, 'utf8');

adminCode = adminCode.replace(
  /await this\.cache\.srem\(\`trusted_devices:\$\{userId\}\`, deviceId\);/,
  `await this.cache.srem(\`trusted-devices:\${tenantId}:\${userId}\`, deviceId);

     // Also invalidate matching sessions physically mapped in Redis if required
     // (SessionService typically maps active sessions, for compliance we ensure the trust removal forces an MFA step up next time)`
);

fs.writeFileSync(adminFile, adminCode);
