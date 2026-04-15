export interface RuntimeAuthMethodSummary {
  id: string;
  type: string;
  verified: boolean;
  providerName?: string;
  providerSubject?: string;
}

export interface RuntimeActorSummary {
  id: string;
  membershipId: string;
  actorType: string;
  status: string;
  isDefault: boolean;
  displayName?: string;
}

export interface RuntimeMembershipSummary {
  id: string;
  tenantId: string;
  principalId: string;
  status: string;
  tenantType: string;
  isolationTier: string;
  runtimeStatus: string;
}

export interface RuntimeIdentityContext {
  principalId: string;
  principalStatus: string;
  tenantId: string;
  membershipId: string;
  membershipStatus: string;
  tenantType: string;
  isolationTier: string;
  runtimeStatus: string;
  actorId: string;
  actorType: string;
  actorStatus: string;
  actorDisplayName?: string;
  authMethodsSummary: RuntimeAuthMethodSummary[];
}

export interface EnsurePrincipalGraphInput {
  principalId: string;
  tenantId: string;
  principalStatus: string;
  authMethods: Array<{
    id: string;
    type: string;
    valueHash: string;
    providerSubject?: string;
    providerName?: string;
    verified: boolean;
    verifiedAt?: Date;
  }>;
  preferredActorType?: string;
}

export interface IRuntimeIdentityRepository {
  ensurePrincipalGraph(input: EnsurePrincipalGraphInput): Promise<RuntimeIdentityContext>;
  findContext(principalId: string, tenantId: string, actorId?: string): Promise<RuntimeIdentityContext | null>;
  listMemberships(principalId: string): Promise<RuntimeMembershipSummary[]>;
  listActors(membershipId: string): Promise<RuntimeActorSummary[]>;
  findActor(membershipId: string, actorId: string): Promise<RuntimeActorSummary | null>;
  listAuthMethods(principalId: string): Promise<RuntimeAuthMethodSummary[]>;
}
