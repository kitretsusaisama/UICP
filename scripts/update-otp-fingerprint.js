const fs = require('fs');
const path = require('path');
const otpFile = path.join(__dirname, '../src/application/services/otp.service.ts');

let code = fs.readFileSync(otpFile, 'utf8');

// Update generateOtp to accept deviceHash
code = code.replace(
  /async generateOtp\(tenantId: string, phone: string, purpose: string\): Promise<string> \{/,
  "async generateOtp(tenantId: string, phone: string, purpose: string, deviceHash?: string): Promise<string> {"
);

// Store device hash in redis
code = code.replace(
  /await this\.cache\.set\(key, otp, 300\);/,
  "await this.cache.set(key, JSON.stringify({ otp, deviceHash }), 300);"
);

// Update verifyOtp to accept deviceHash
code = code.replace(
  /async verifyOtp\(tenantId: string, phone: string, code: string, purpose: string\): Promise<boolean> \{/,
  "async verifyOtp(tenantId: string, phone: string, code: string, purpose: string, incomingDeviceHash?: string): Promise<boolean> {"
);

// Parse stored OTP and verify device hash
code = code.replace(
  /if \(storedCode !== code\)/,
  `let parsed;
    try { parsed = JSON.parse(storedCode); } catch(e) { parsed = { otp: storedCode }; }
    if (parsed.otp !== code) return false;
    if (parsed.deviceHash && incomingDeviceHash && parsed.deviceHash !== incomingDeviceHash) {
       // Ideally we'd emit a SOC alert here for DEVICE_MISMATCH
       throw new ForbiddenException('DEVICE_MISMATCH');
    }
    `
);

// Fix ForbiddenException import
if (!code.includes('ForbiddenException')) {
  code = code.replace(
    /import { Injectable, Inject, BadRequestException, ServiceUnavailableException/g,
    "import { Injectable, Inject, BadRequestException, ServiceUnavailableException, ForbiddenException"
  );
}

fs.writeFileSync(otpFile, code);
