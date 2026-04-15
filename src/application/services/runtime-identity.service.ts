import { Inject, Injectable } from '@nestjs/common';
import { User } from '../../domain/aggregates/user.aggregate';
import { INJECTION_TOKENS } from '../ports/injection-tokens';
import {
  IRuntimeIdentityRepository,
  RuntimeActorSummary,
  RuntimeIdentityContext,
  RuntimeMembershipSummary,
} from '../ports/driven/i-runtime-identity.repository';

@Injectable()
export class RuntimeIdentityService {
  constructor(
    @Inject(INJECTION_TOKENS.RUNTIME_IDENTITY_REPOSITORY)
    private readonly runtimeIdentityRepository: IRuntimeIdentityRepository,
  ) {}

  async ensureForLegacyUser(user: User, preferredActorType?: string): Promise<RuntimeIdentityContext> {
    return this.runtimeIdentityRepository.ensurePrincipalGraph({
      principalId: user.getId().toString(),
      tenantId: user.getTenantId().toString(),
      principalStatus: user.getStatus(),
      preferredActorType,
      authMethods: user.getIdentities().map((identity) => ({
        id: identity.id.toString(),
        type: identity.getType(),
        valueHash: identity.getValueHash(),
        providerSubject: identity.getProviderSub(),
        providerName: identity.getType().startsWith('OAUTH_') ? identity.getType().replace('OAUTH_', '').toLowerCase() : undefined,
        verified: identity.isVerified(),
        verifiedAt: identity.getVerifiedAt(),
      })),
    });
  }

  async getContext(principalId: string, tenantId: string, actorId?: string): Promise<RuntimeIdentityContext | null> {
    return this.runtimeIdentityRepository.findContext(principalId, tenantId, actorId);
  }

  async listMemberships(principalId: string): Promise<RuntimeMembershipSummary[]> {
    return this.runtimeIdentityRepository.listMemberships(principalId);
  }

  async listActors(membershipId: string): Promise<RuntimeActorSummary[]> {
    return this.runtimeIdentityRepository.listActors(membershipId);
  }

  async findActor(membershipId: string, actorId: string): Promise<RuntimeActorSummary | null> {
    return this.runtimeIdentityRepository.findActor(membershipId, actorId);
  }
}

