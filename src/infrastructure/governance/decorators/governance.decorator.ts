import { SetMetadata } from '@nestjs/common';

export interface GovernanceMetadata {
  owner: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  cost?: 'normal' | 'cost-critical';
  auth?: 'public' | 'user' | 'admin' | 'internal' | 'client';
}

export const Governance = (meta: GovernanceMetadata) => SetMetadata('governance', meta);
