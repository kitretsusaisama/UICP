import { SetMetadata } from '@nestjs/common';

export interface GovernanceMetadata {
  owner: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  cost?: 'normal' | 'cost-critical';
  auth?: 'public' | 'user' | 'admin' | 'internal' | 'client';
}

// In the dual-lock system, the runtime decorator must hold the exact same keys as the manifest checks
export const Governance = (meta: GovernanceMetadata) => SetMetadata('governance', meta);
