const fs = require('fs');
const path = require('path');
const file = path.join(__dirname, '../src/infrastructure/governance/bootstrap/governance.bootstrap.ts');

let code = fs.readFileSync(file, 'utf8');

code = code.replace(
  /console\.warn\(\`\[GOVERNANCE LEAK DETECTED\].*\`\);[\s\S]*?\/\/ throw new Error/,
  `if (process.env.RELEASE_MODE === 'production') {
            throw new Error(\`[PRODUCTION BOOT ERROR] Missing governance metadata: \${instance.constructor.name}.\${method}\`);
          } else {
            console.warn(\`[GOVERNANCE LEAK DETECTED]: \${instance.constructor.name}.\${method} lacks @Governance() metadata.\`);
          }`
);

fs.writeFileSync(file, code);
