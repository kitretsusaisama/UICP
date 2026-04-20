const fs = require('fs');
const path = require('path');

// 1. Remove SessionService from http.module.ts controllers array
const httpModuleFile = path.join(__dirname, '../src/interface/http/http.module.ts');
let httpCode = fs.readFileSync(httpModuleFile, 'utf8');

httpCode = httpCode.replace(
  /controllers: \[IamController, SessionService, CoreController\]/,
  `controllers: [IamController, CoreController]`
);

// SessionService is an injectable service and should ideally be in providers,
// but it's likely exported by an application module so we just remove it from controllers here.
if (httpCode.includes('providers: [')) {
  if (!httpCode.includes('SessionService,')) {
      httpCode = httpCode.replace(/providers: \[/, "providers: [SessionService, ");
  }
} else {
  // If no providers array exists, we can inject one
  httpCode = httpCode.replace(/controllers: \[/, "providers: [SessionService],\n  controllers: [");
}

fs.writeFileSync(httpModuleFile, httpCode);

// 2. Fix AuthController unprotected introspect
const authCtrlFile = path.join(__dirname, '../src/interface/http/controllers/auth.controller.ts');
let authCode = fs.readFileSync(authCtrlFile, 'utf8');

// Find and delete the unprotected introspect route
const introspectRegex = /@Post\('introspect'\)[\s\S]*?async introspect\(@Body\(\) body: any\) \{[\s\S]*?return \{ active: true \};\n\s*\}/g;
authCode = authCode.replace(introspectRegex, '// DELETED: Unprotected introspect migrated to OAuthController');

fs.writeFileSync(authCtrlFile, authCode);

console.log('✅ Resolved http.module.ts and auth.controller.ts bugs.');
