const fs = require('fs');
const path = require('path');
const file = path.join(__dirname, '../src/interface/http/controllers/auth.controller.ts');

let code = fs.readFileSync(file, 'utf8');

// POST /v1/auth/signup/phone
code = code.replace(
  /async signupPhone\(@Body\(\) body: any, @Req\(\) req: any\) \{/,
  "async signupPhone(@Body() body: any, @Req() req: any, @Headers('x-device-fingerprint') deviceHash?: string) {"
);

code = code.replace(
  /await this\.otpService\.generateOtp\(tenantId, phone, 'signup'\);/,
  "await this.otpService.generateOtp(tenantId, phone, 'signup', deviceHash);"
);

// POST /v1/auth/signup/phone/verify
code = code.replace(
  /async signupPhoneVerify\(@Body\(\) body: any, @Req\(\) req: any\) \{/,
  "async signupPhoneVerify(@Body() body: any, @Req() req: any, @Headers('x-device-fingerprint') deviceHash?: string) {"
);

code = code.replace(
  /await this\.otpService\.verifyOtp\(tenantId, phone, code, 'signup'\);/,
  "await this.otpService.verifyOtp(tenantId, phone, code, 'signup', deviceHash);"
);

fs.writeFileSync(file, code);
