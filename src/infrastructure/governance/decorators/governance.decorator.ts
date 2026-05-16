import { SetMetadata } from '@nestjs/common';

export const GOVERNANCE_METADATA_KEY = 'uicp:governance';

export interface GovernanceMetadata {
  owner: string;
  auth: 'public' | 'authenticated' | 'internal' | 'service';
  capabilities?: string[];
}

export function Governance(metadataOrOwner: GovernanceMetadata | string, ...capabilities: string[]) {
  const metadata: GovernanceMetadata =
    typeof metadataOrOwner === 'string'
      ? { owner: metadataOrOwner, auth: 'authenticated', capabilities }
      : metadataOrOwner;

  return SetMetadata('governance', metadata);
}
