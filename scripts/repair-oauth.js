const fs = require('fs');
const path = require('path');
const file = path.join(__dirname, '../src/interface/http/controllers/platform/oauth.controller.ts');

let code = fs.readFileSync(file, 'utf8');

// Fix validateRedirectUri which does not exist on OAuthService, use getClientApp instead
code = code.replace(
  /await this\.oauthService\.validateRedirectUri\(clientId, redirectUri\);/,
  `const appEntity = await this.oauthService.getClientApp(clientId);
    if (!appEntity || !appEntity.redirectUris.includes(redirectUri)) {
        throw new BadRequestException('Invalid redirect_uri');
    }`
);

// Fix exchangeCodeForTokens -> exchangeToken
code = code.replace(
  /const { tokens, user, tenantId } = await this\.oauthService\.exchangeCodeForTokens\(\{/,
  `const { tokens, user, tenantId } = await this.oauthService.exchangeToken({`
);

// Mock the @Governance decorators for OAuth endpoints missing them from the Phase 9 refactor
code = code.replace(/@Get\('authorize'\)/, "@Get('authorize')\n  @Governance({ owner: 'auth-team', risk: 'critical', auth: 'public' })");
code = code.replace(/@Post\('token'\)/, "@Post('token')\n  @Governance({ owner: 'auth-team', risk: 'critical', auth: 'public' })");
code = code.replace(/@Post\('introspect'\)/, "@Post('introspect')\n  @Governance({ owner: 'auth-team', risk: 'high', auth: 'client' })");
code = code.replace(/@Post\('revoke'\)/, "@Post('revoke')\n  @Governance({ owner: 'auth-team', risk: 'high', auth: 'client' })");

if (!code.includes('import { Governance }')) {
  code = `import { Governance } from '../../../../src/infrastructure/governance/decorators/governance.decorator';\n` + code;
}

fs.writeFileSync(file, code);
