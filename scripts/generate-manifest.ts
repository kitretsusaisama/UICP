import * as fs from 'fs';
import * as path from 'path';
import { ulid } from 'ulid';

console.log('📦 Auto-generating Route Manifest for Dual-Lock Governance...');

const srcDir = path.join(__dirname, '../src');
const manifestFile = path.join(__dirname, '../src/infrastructure/governance/route-manifest.ts');

const routes: any = {};

function walkDir(dir: string, callback: (filepath: string) => void) {
  fs.readdirSync(dir).forEach(f => {
    const dirPath = path.join(dir, f);
    const isDirectory = fs.statSync(dirPath).isDirectory();
    if (isDirectory) walkDir(dirPath, callback);
    else if (f.endsWith('.controller.ts') && !f.endsWith('.spec.ts')) callback(dirPath);
  });
}

walkDir(srcDir, (filepath) => {
  const content = fs.readFileSync(filepath, 'utf8');

  // Extract controller base path
  const ctrlMatch = /@Controller\(['"]([^'"]+)['"]\)/.exec(content);
  if (!ctrlMatch) return;
  let basePath = ctrlMatch[1];
  if (basePath.startsWith('/')) basePath = basePath.substring(1);

  const endpointRegex = /@(Get|Post|Put|Delete|Patch)\(['"]([^'"]*)['"]\)?[\s\S]*?@Governance\(\{([^}]+)\}\)[\s\S]*?async\s+(\w+)\(/g;
  let match;

  while ((match = endpointRegex.exec(content)) !== null) {
     const method = match[1].toUpperCase();
     const subPath = match[2] ? (match[2].startsWith('/') ? match[2] : `/${match[2]}`) : '';
     let fullPath = `/${basePath}${subPath}`;
     // Clean double slashes
     fullPath = fullPath.replace(/\/\//g, '/');

     const routeKey = `${method} ${fullPath}`;
     const govMetaStr = match[3];

     // Primitive parser for governance object fields
     const ownerMatch = /owner:\s*['"]([^'"]+)['"]/.exec(govMetaStr);
     const authMatch = /auth:\s*['"]([^'"]+)['"]/.exec(govMetaStr);
     const riskMatch = /risk:\s*['"]([^'"]+)['"]/.exec(govMetaStr);
     const costMatch = /cost:\s*['"]([^'"]+)['"]/.exec(govMetaStr);

     const isMutation = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);

     routes[routeKey] = {
        id: ulid(),
        owner: ownerMatch ? ownerMatch[1] : 'unknown-team',
        auth: authMatch ? authMatch[1] : 'public',
        risk: riskMatch ? riskMatch[1] : 'medium',
        cost: costMatch ? costMatch[1] : 'normal',
        ratePolicy: 'default',
        audit: isMutation ? 'MANDATORY' : 'OPTIONAL',
        idempotency: isMutation,
        edgeCases: {
           retry: isMutation ? 'idempotent' : 'manual',
           redis: costMatch && costMatch[1] === 'cost-critical' ? 'fail_closed' : 'degrade',
           db: isMutation ? 'force_primary' : 'eventual',
           queue: 'reject_if_backlog',
           provider: 'timeout_fallback',
           replay: 'block',
           deviceSwitch: 'step_up_auth',
           tenantBudget: 'hard_stop'
        },
        failure: {
           timeoutMs: 2000,
           retry: false,
           circuitBreaker: true,
           fallback: 'none',
           alert: true
        },
        deprecation: {
           status: fullPath.includes('/core/') ? 'deprecated' : 'active',
           sunsetAt: fullPath.includes('/core/') ? '2026-08-01T00:00:00Z' : null,
           replacement: null
        }
     };
  }
});

let manifestContent = `import { GovernanceMetadata } from './decorators/governance.decorator';

export interface RouteEdgeCases {
  retry: 'idempotent' | 'not_supported' | 'manual';
  redis: 'fail_closed' | 'degrade' | 'fail_open';
  db: 'force_primary' | 'eventual' | 'none';
  queue: 'reject_if_backlog' | 'degrade' | 'none';
  provider: 'timeout_fallback' | 'circuit_breaker' | 'none';
  replay: 'block' | 'none';
  deviceSwitch: 'step_up_auth' | 'reject' | 'allow';
  tenantBudget: 'hard_stop' | 'soft_limit' | 'none';
}

export interface RouteFailureModel {
  timeoutMs: number;
  retry: boolean;
  circuitBreaker: boolean;
  fallback: string;
  alert: boolean;
}

export interface RouteManifestEntry extends GovernanceMetadata {
  id: string;
  ratePolicy: string;
  audit: 'MANDATORY' | 'OPTIONAL' | 'NONE';
  idempotency: boolean;
  edgeCases: RouteEdgeCases;
  failure: RouteFailureModel;
  deprecation: {
    status: 'active' | 'deprecated' | 'sunset';
    sunsetAt: string | null;
    replacement: string | null;
  };
}

export const ROUTE_MANIFEST: Record<string, RouteManifestEntry> = ${JSON.stringify(routes, null, 2)};
`;

fs.writeFileSync(manifestFile, manifestContent);
console.log('✅ Route Manifest written to src/infrastructure/governance/route-manifest.ts');
