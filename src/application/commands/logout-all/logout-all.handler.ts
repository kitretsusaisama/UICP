import { Injectable, Inject } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { LogoutAllCommand } from './logout-all.command';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { ITokenRepository } from '../../ports/driven/i-token.repository';
import { IOutboxRepository, OutboxEvent } from '../../ports/driven/i-outbox.repository';
import { SessionService } from '../../services/session.service';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';

@Injectable()
export class LogoutAllHandler {
  constructor(
    private readonly sessionService: SessionService,
    @Inject(INJECTION_TOKENS.TOKEN_REPOSITORY)
    private readonly tokenRepo: ITokenRepository,
    @Inject(INJECTION_TOKENS.OUTBOX_REPOSITORY)
    private readonly outboxRepo: IOutboxRepository,
  ) {}

  async handle(cmd: LogoutAllCommand): Promise<{ revokedSessions: number }> {
    const userId = UserId.from(cmd.userId);
    const tenantId = TenantId.from(cmd.tenantId);

    // 1. List active sessions
    const sessions = await this.sessionService.listByUser(userId, tenantId);

    // 2. Revoke all token families for user
    await this.tokenRepo.revokeAllFamiliesByUser(userId, tenantId);

    // 3. Bulk blocklist active JTIs
    const activeJtis = await this.tokenRepo.getActiveJtisByUser(userId, tenantId);
    const expiresAt = new Date(Date.now() + 900 * 1000); // 15 min fallback
    await Promise.all(activeJtis.map((jti) => this.tokenRepo.addToBlocklist(jti, expiresAt)));

    // 4. Invalidate all sessions
    await this.sessionService.invalidateAll(userId, tenantId);

    // 5. Insert outbox event
    const outboxEvent: OutboxEvent = {
      id: randomUUID(),
      eventType: 'AllSessionsRevoked',
      aggregateId: cmd.userId,
      aggregateType: 'User',
      tenantId: cmd.tenantId,
      payload: { userId: cmd.userId, revokedCount: sessions.length },
      status: 'PENDING',
      attempts: 0,
      createdAt: new Date(),
    };
    await this.outboxRepo.insertWithinTransaction(outboxEvent, null);

    return { revokedSessions: sessions.length };
  }
}
