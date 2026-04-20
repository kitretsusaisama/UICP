const fs = require('fs');
const path = require('path');
const file = path.join(__dirname, '../src/application/services/extensions/extension.executor.ts');

let code = fs.readFileSync(file, 'utf8');

// Inject KmsService
code = code.replace(
  /private readonly metrics: MetricsService/,
  `private readonly metrics: MetricsService,
    private readonly kmsService: KmsService`
);

// Import KmsService
if (!code.includes('import { KmsService }')) {
  code = `import { KmsService } from '../platform/kms.service';\n` + code;
}

// Fix Signature Verification
code = code.replace(
  /\/\/ In Phase 3, secrets are hashed using SHA-256[\s\S]*?if \(!isValid\) \{/g,
  `// In a secure architecture, we retrieve the raw secret from an internal KMS to compute HMAC
    const rawSecret = await this.kmsService.getRawSecret(appId);
    if (!rawSecret) throw new UnauthorizedException('KMS Error: Unable to resolve signing material');

    const expectedSignature = crypto.createHmac('sha256', rawSecret).update(signatureBase).digest('hex');

    if (signature !== expectedSignature) {`
);

fs.writeFileSync(file, code);
