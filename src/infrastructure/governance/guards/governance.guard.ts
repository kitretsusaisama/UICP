import { Injectable, CanActivate, ExecutionContext, InternalServerErrorException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { GovernanceMetadata } from '../decorators/governance.decorator';

@Injectable()
export class GovernanceGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(ctx: ExecutionContext): boolean {
    const handler = ctx.getHandler();
    const meta = this.reflector.get<GovernanceMetadata>('governance', handler);

    if (!meta) {
      throw new InternalServerErrorException('GOVERNANCE_METADATA_MISSING: Route lacks mandatory @Governance owner and risk profile');
    }

    return true;
  }
}
