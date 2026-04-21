import { GovernanceMetadata } from './decorators/governance.decorator';

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
  id: string; // ULID
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

export const ROUTE_MANIFEST: Record<string, RouteManifestEntry> = {
  // We will programmatically populate this or define the critical ones here
};
