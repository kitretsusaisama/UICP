const fs = require('fs');
const path = require('path');

// 1. Fix ClientBasicAuthGuard
const authGuardFile = path.join(__dirname, '../src/interface/http/guards/client-basic-auth.guard.ts');
let authGuardCode = fs.readFileSync(authGuardFile, 'utf8');

// Fix colon split logic (RFC 7617)
authGuardCode = authGuardCode.replace(
  /const parts = decoded\.split\(':'\);\n\s*if \(parts\.length !== 2\) throw new Error\('Invalid format'\);\n\s*clientId = parts\[0\];\n\s*clientSecret = parts\[1\];/,
  `const colonIdx = decoded.indexOf(':');
      if (colonIdx === -1) throw new Error('Invalid format');
      clientId = decoded.substring(0, colonIdx);
      clientSecret = decoded.substring(colonIdx + 1);`
);

fs.writeFileSync(authGuardFile, authGuardCode);

// 2. Fix InternalServiceGuard
const internalGuardFile = path.join(__dirname, '../src/interface/http/guards/internal-service.guard.ts');
let internalGuardCode = fs.readFileSync(internalGuardFile, 'utf8');

// Remove x-service-id bypass and hardcoded fallback
internalGuardCode = internalGuardCode.replace(
  /const internalToken = process\.env\.INTERNAL_TOKEN \|\| 'local-internal-secret-token';/,
  `const internalToken = process.env.INTERNAL_TOKEN;
    if (!internalToken && process.env.RELEASE_MODE === 'production') {
        throw new InternalServerErrorException('INTERNAL_TOKEN is strictly required in production');
    }`
);

internalGuardCode = internalGuardCode.replace(
  /const isServiceMesh = !!req\.headers\['x-service-id'\];[\s\S]*?if \(!hasValidToken && !isServiceMesh\) {/,
  `if (!hasValidToken) {`
);

// Fix missing exception import
if (!internalGuardCode.includes('InternalServerErrorException')) {
    internalGuardCode = internalGuardCode.replace(
        /import { Injectable, CanActivate, ExecutionContext, ForbiddenException }/,
        "import { Injectable, CanActivate, ExecutionContext, ForbiddenException, InternalServerErrorException }"
    );
}

fs.writeFileSync(internalGuardFile, internalGuardCode);
