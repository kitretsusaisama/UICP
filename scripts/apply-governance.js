const fs = require('fs');
const path = require('path');

const applyDecorator = (filePath, content, defaultOwner, authLevel) => {
  if (content.includes('@Governance(')) return content;

  let newContent = content.replace(
    /import { ([^}]+) } from '@nestjs\/common';/,
    "import { $1, UseGuards } from '@nestjs/common';"
  );

  if (!newContent.includes('Governance(')) {
     newContent = `import { Governance } from '../../../../src/infrastructure/governance/decorators/governance.decorator';\nimport { GovernanceGuard } from '../../../../src/infrastructure/governance/guards/governance.guard';\n` + newContent;
  }

  newContent = newContent.replace(
     /(@ApiOperation\(\{.*\}\))/g,
     `@UseGuards(GovernanceGuard)\n  @Governance({ owner: '${defaultOwner}', risk: '${authLevel === 'admin' ? 'critical' : 'medium'}', auth: '${authLevel}' })\n  $1`
  );

  fs.writeFileSync(filePath, newContent);
};

const dirs = [
  { dir: 'src/interface/http/controllers/platform', owner: 'platform-team@uicp.com', auth: 'client' },
  { dir: 'src/interface/http/controllers/platform-ops', owner: 'sre-team@uicp.com', auth: 'internal' },
  { dir: 'src/interface/http/controllers/governance', owner: 'iam-team@uicp.com', auth: 'admin' },
  { dir: 'src/interface/http/controllers/extensions', owner: 'extensions-team@uicp.com', auth: 'client' }
];

dirs.forEach(d => {
   const files = fs.readdirSync(d.dir);
   files.forEach(f => {
      if (f.endsWith('.ts')) {
         const p = path.join(d.dir, f);
         applyDecorator(p, fs.readFileSync(p, 'utf8'), d.owner, d.auth);
      }
   });
});

const adminCtrl = 'src/interface/http/controllers/admin.controller.ts';
applyDecorator(adminCtrl, fs.readFileSync(adminCtrl, 'utf8'), 'iam-admin-team@uicp.com', 'admin');

const iamCtrl = 'src/interface/http/controllers/iam.controller.ts';
applyDecorator(iamCtrl, fs.readFileSync(iamCtrl, 'utf8'), 'iam-team@uicp.com', 'user');

const authCtrl = 'src/interface/http/controllers/auth.controller.ts';
applyDecorator(authCtrl, fs.readFileSync(authCtrl, 'utf8'), 'auth-team@uicp.com', 'public');
