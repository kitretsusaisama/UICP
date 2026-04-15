import { ForbiddenException, Injectable } from '@nestjs/common';

export interface AuthorizationContext {
  principalId?: string;
  membershipId?: string;
  actorId?: string;
  capabilities?: string[];
  legacyPermissions?: string[];
  authAssuranceLevel?: string;
}

@Injectable()
export class RuntimeAuthorizationService {
  assertCapability(context: AuthorizationContext, capability?: string): void {
    if (!capability) {
      return;
    }

    const capabilities = new Set(context.capabilities ?? []);
    const permissions = new Set(context.legacyPermissions ?? []);

    if (capabilities.size === 0 && permissions.size === 0) {
      return;
    }

    if (capabilities.has(capability) || capabilities.has('*') || permissions.has(capability) || permissions.has('*:*')) {
      return;
    }

    throw new ForbiddenException({
      error: {
        code: 'CAPABILITY_DENIED',
        message: `Missing capability ${capability}`,
      },
    });
  }

  assertStepUp(context: AuthorizationContext, required?: boolean): void {
    if (!required) {
      return;
    }

    if (context.authAssuranceLevel === 'aal2' || context.authAssuranceLevel === 'high') {
      return;
    }

    throw new ForbiddenException({
      error: {
        code: 'STEP_UP_REQUIRED',
        message: 'Recent or stronger authentication is required for this operation',
      },
    });
  }
}
