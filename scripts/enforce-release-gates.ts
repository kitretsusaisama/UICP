import * as fs from 'fs';
import * as path from 'path';

console.log('🚀 [Layer 1] Running Static Governance Enforcement (Regex/AST Analyzer)...');

const srcDir = path.join(__dirname, '../src');
let hasErrors = false;

function walkDir(dir: string, callback: (filepath: string) => void) {
  fs.readdirSync(dir).forEach(f => {
    const dirPath = path.join(dir, f);
    const isDirectory = fs.statSync(dirPath).isDirectory();
    if (isDirectory) walkDir(dirPath, callback);
    else if (f.endsWith('.ts') && !f.endsWith('.spec.ts')) callback(dirPath);
  });
}

walkDir(srcDir, (filepath) => {
  const content = fs.readFileSync(filepath, 'utf8');
  const filename = path.basename(filepath);

  // 1. Controller Governance Validation
  if (filename.endsWith('.controller.ts')) {
    // Only verify non-abstract controllers with @Controller
    if (content.includes('@Controller')) {
       // Check if there are un-governed endpoints (very simple regex check for missing @Governance)
       // Advanced AST logic is preferred, but simple string detection flags gross violations.
       const endpointRegex = /@(Get|Post|Put|Delete|Patch)\([^)]*\)/g;
       let match;
       let lastIndex = 0;

       while ((match = endpointRegex.exec(content)) !== null) {
          const substring = content.slice(Math.max(0, match.index - 300), match.index);
          // If @Governance is nowhere near the route definition, it's highly suspect
          if (!substring.includes('@Governance(')) {
             console.error(`❌ [Governance Violation] Missing @Governance metadata near route in ${filename} at index ${match.index}`);
             hasErrors = true;
          }
       }
    }
  }

  // 2. Dangerous Redis Anti-Patterns (INCR + EXPIRE sequentially without Lua)
  if (content.includes('.incr(') && content.includes('.expire(')) {
     // Look for non-atomic operations in close proximity
     if (/await\s+this\.cache\.incr[^\n]*\n.*await\s+this\.cache\.expire/g.test(content)) {
        console.error(`❌ [Redis Anti-Pattern] Non-atomic INCR + EXPIRE detected in ${filename}. Must use Lua scripts or pipeline.`);
        hasErrors = true;
     }
  }

  // 3. Dynamic Execution Blocking
  if (content.includes('eval(') || content.includes('new Function(')) {
     console.error(`❌ [Security Violation] Dynamic code execution (eval / new Function) detected in ${filename}.`);
     hasErrors = true;
  }

  // 4. External Provider direct usage without resilience (mock check for firebase example)
  if (content.includes('firebase.auth()') && !content.includes('resilientProvider.execute')) {
     if (filepath.includes('otp.adapter') || filepath.includes('otp.service')) {
        console.error(`❌ [Resilience Violation] Direct external provider call without CircuitBreaker/ResilientProvider detected in ${filename}.`);
        hasErrors = true;
     }
  }
});

if (hasErrors) {
  console.error('\n🚨 STATIC ENFORCEMENT FAILED. Fix violations before release.');
  process.exit(1);
} else {
  console.log('✅ Static Governance Checks Passed.');
}
