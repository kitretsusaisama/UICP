import { BadRequestException, Injectable } from '@nestjs/common';
import { RuntimeIdentityService } from '../../services/runtime-identity.service';
import { RuntimeAuthorizationService } from '../../services/runtime-authorization.service';
import { SessionService } from '../../services/session.service';
import { TokenService } from '../../services/token.service';
import { VerifyOtpHandler } from '../../commands/verify-otp/verify-otp.handler';
import { VerifyOtpCommand } from '../../commands/verify-otp/verify-otp.command';
import { ProviderRoutingService } from '../../control-plane/services/provider-routing.service';
import { OtpService } from '../../services/otp.service';
import { IQueuePort } from '../../ports/driven/i-queue.port';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { Inject } from '@nestjs/common';
import { OtpDispatchPayload } from '../../contracts/otp-dispatch.contract';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { SessionId } from '../../../domain/value-objects/session-id.vo';

export interface DynamicRequestContext {
  tenantId: string;
  principalId?: string;
  membershipId?: string;
  actorId?: string;
  sessionId?: string;
  capabilities?: string[];
  perms?: string[];
}

@Injectable()
export class DynamicCommandRegistryService {
  constructor(
    private readonly runtimeIdentityService: RuntimeIdentityService,
    private readonly runtimeAuthorizationService: RuntimeAuthorizationService,
    private readonly sessionService: SessionService,
    private readonly tokenService: TokenService,
    private readonly verifyOtpHandler: VerifyOtpHandler,
    private readonly providerRoutingService: ProviderRoutingService,
    private readonly otpService: OtpService,
    @Inject(INJECTION_TOKENS.QUEUE_PORT)
    private readonly queue: IQueuePort,
  ) {}

  async execute(
    moduleKey: string,
    commandKey: string,
    capability: string | undefined,
    stepUpRequired: boolean | undefined,
    body: Record<string, unknown>,
    requestContext: DynamicRequestContext,
  ): Promise<Record<string, unknown>> {
    this.runtimeAuthorizationService.assertCapability(
      {
        principalId: requestContext.principalId,
        membershipId: requestContext.membershipId,
        actorId: requestContext.actorId,
        capabilities: requestContext.capabilities,
        legacyPermissions: requestContext.perms,
        authAssuranceLevel: 'aal1',
      },
      capability,
    );
    this.runtimeAuthorizationService.assertStepUp(
      {
        principalId: requestContext.principalId,
        membershipId: requestContext.membershipId,
        actorId: requestContext.actorId,
        capabilities: requestContext.capabilities,
        legacyPermissions: requestContext.perms,
        authAssuranceLevel: 'aal1',
      },
      stepUpRequired,
    );

    if (moduleKey === 'core' && commandKey === 'actor.switch') {
      if (!requestContext.principalId || !requestContext.membershipId || !requestContext.sessionId) {
        throw new BadRequestException({
          error: { code: 'MISSING_RUNTIME_CONTEXT', message: 'principalId, membershipId, and sessionId are required' },
        });
      }

      const requestedActorId = String(body['actorId'] ?? '');
      const runtimeContext = await this.runtimeIdentityService.getContext(
        requestContext.principalId,
        requestContext.tenantId,
        requestedActorId,
      );
      if (!runtimeContext || runtimeContext.membershipId !== requestContext.membershipId) {
        throw new BadRequestException({
          error: { code: 'ACTOR_NOT_AVAILABLE', message: `Actor ${requestedActorId} is not available` },
        });
      }

      const session = await this.sessionService.findById(
        SessionId.from(requestContext.sessionId),
        TenantId.from(requestContext.tenantId),
      );
      if (!session) {
        throw new BadRequestException({
          error: { code: 'SESSION_NOT_FOUND', message: 'Session not found for actor switch' },
        });
      }

      const accessToken = await this.tokenService.mintAccessToken({
        principalId: runtimeContext.principalId,
        tenantId: runtimeContext.tenantId,
        membershipId: runtimeContext.membershipId,
        actorId: runtimeContext.actorId,
        session,
        capabilities: requestContext.capabilities ?? [],
        roles: ['member'],
        perms: requestContext.perms ?? [],
        amr: ['pwd'],
        policyVersion: session.policyVersion ?? 'legacy-policy-v1',
        manifestVersion: session.manifestVersion ?? 'legacy-manifest-v1',
      });

      return {
        accessToken: accessToken.token,
        actor: {
          id: runtimeContext.actorId,
          type: runtimeContext.actorType,
          displayName: runtimeContext.actorDisplayName,
        },
      };
    }

    if (moduleKey === 'auth' && commandKey === 'otp.send') {
      const recipient = String(body['recipient'] ?? '');
      const purpose = String(body['purpose'] ?? 'IDENTITY_VERIFICATION') as 'IDENTITY_VERIFICATION' | 'MFA' | 'PASSWORD_RESET';
      const channel = (String(body['channel'] ?? (recipient.includes('@') ? 'EMAIL' : 'SMS')).toUpperCase()) as 'EMAIL' | 'SMS';
      if (!recipient) {
        throw new BadRequestException({
          error: { code: 'INVALID_DYNAMIC_COMMAND', message: 'recipient is required' },
        });
      }

      const code = this.otpService.generate();
      const subjectKey = String(body['subjectKey'] ?? requestContext.principalId ?? 'anonymous');
      await this.otpService.store(subjectKey, purpose, code);
      const route = await this.providerRoutingService.resolveRoute(requestContext.tenantId, channel, purpose);
      const payload: OtpDispatchPayload = {
        userId: subjectKey,
        tenantId: requestContext.tenantId,
        recipient,
        channel,
        purpose,
        code,
        tenantName: body['tenantName'] ? String(body['tenantName']) : undefined,
      };
      await this.queue.enqueue('otp-send', payload);

      return {
        challengeId: subjectKey,
        providerRouteSummary: route,
        sent: true,
      };
    }

    if (moduleKey === 'auth' && commandKey === 'otp.verify') {
      const result = await this.verifyOtpHandler.handle(
        new VerifyOtpCommand(
          requestContext.tenantId,
          String(body['userId'] ?? body['subjectKey'] ?? requestContext.principalId ?? ''),
          String(body['code'] ?? ''),
          String(body['purpose'] ?? 'IDENTITY_VERIFICATION') as 'IDENTITY_VERIFICATION' | 'MFA' | 'PASSWORD_RESET',
          body['identityId'] ? String(body['identityId']) : undefined,
          body['sessionId'] ? String(body['sessionId']) : undefined,
        ),
      );
      return result as Record<string, unknown>;
    }

    if (moduleKey === 'iam' && commandKey === 'policy.simulate') {
      return {
        simulated: true,
        requestedCapability: body['capability'] ?? capability,
        resourceContext: body['resourceContext'] ?? {},
        manifestVersion: body['manifestVersion'] ?? 'dynamic-runtime',
      };
    }

    throw new BadRequestException({
      error: {
        code: 'COMMAND_HANDLER_NOT_REGISTERED',
        message: `No runtime handler registered for ${moduleKey}.${commandKey}`,
      },
    });
  }
}
