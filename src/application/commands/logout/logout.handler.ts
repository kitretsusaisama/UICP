import { Injectable, Inject } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { LogoutCommand } from './logout.command';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { ITokenRepository } from '../../ports/driven/i-token.repository';
import { IOutboxRepository, OutboxEvent } from '../../ports/driven/i-outbox.repository';
import { SessionService } from '../../services/session.service';
import { SessionId } from '../../../domain/value-objects/session-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';

@Injectable()
export class LogoutHandler {
  constructor(
    private readonly sessionService: SessionService,
    @Inject(INJECTION_TOKENS.TOKEN_REPOSITORY)
    private readonly tokenRepo: ITokenRepository,
    @Inject(INJECTION_TOKENS.OUTBOX_REPOSITORY)
    private readonly outboxRepo: IOutboxRepository,
  ) {}

  async handle(cmd: LogoutCommand): Promise<{ success: boolean }> {
    const tenantId = TenantId.from(cmd.tenantId);

    // 1. Invalidate session
    await this.sessionService.invalidate(SessionId.from(cmd.sessionId), tenantId);

    // 2. Blocklist access token
    await this.tokenRepo.addToBlocklist(cmd.accessTokenJti, cmd.accessTokenExpiresAt);

    // 3. Insert outbox event
    const outboxEvent: OutboxEvent = {
      id: randomUUID(),
      eventType: 'SessionRevoked',
      aggregateId: cmd.sessionId,
      aggregateType: 'Session',
      tenantId: cmd.tenantId,
      payload: {
        sessionId: cmd.sessionId,
        userId: cmd.userId,
        reason: 'logout',
      },
      status: 'PENDING',
      attempts: 0,
      createdAt: new Date(),
    };
    await this.outboxRepo.insertWithinTransaction(outboxEvent, null);

    return { success: true };
  }
}
