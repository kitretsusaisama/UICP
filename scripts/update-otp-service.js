const fs = require('fs');
const path = require('path');
const file = path.join(__dirname, '../src/application/services/otp.service.ts');

let code = fs.readFileSync(file, 'utf8');

// Replace the graceful degradation in enforceRateLimit with a hard throw 503
code = code.replace(
  /catch \(e\) {[\s\S]*?this\.logger\.warn\(\`Redis rate limiting unavailable[\s\S]*?\}\s*}/,
  `catch (e) {
      if (e instanceof BadRequestException) throw e;
      this.logger.error(\`Redis unavailable during OTP quota check: \${e.message}\`);
      throw new ServiceUnavailableException({
         code: 'QUOTA_UNAVAILABLE',
         message: 'OTP service temporarily unavailable due to backend outage. Failing closed to prevent financial abuse.'
      });
    }`
);

// Add missing exception import
if (!code.includes('ServiceUnavailableException')) {
  code = code.replace(
    /import { Injectable, Inject, BadRequestException/g,
    "import { Injectable, Inject, BadRequestException, ServiceUnavailableException"
  );
}

fs.writeFileSync(file, code);
