import { Injectable, Inject } from '@nestjs/common';
import { GetThreatHistoryQuery } from './get-threat-history.query';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { IAlertRepository } from '../../ports/driven/i-alert.repository';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';

export interface ThreatHistoryDto {
  id: string;
  threatScore: number;
  killChainStage: string;
  signals: Array<{ signal: string; score: number; detail?: string }>;
  workflow: string;
  createdAt: string;
}

/**
 * Query handler — load SOC alert threat history for a user with signal breakdown.
 *
 * Implements: Req 12.5 (threat history with signal breakdown and kill-chain stage)
 */
@Injectable()
export class GetThreatHistoryHandler {
  constructor(
    @Inject(INJECTION_TOKENS.ALERT_REPOSITORY)
    private readonly alertRepo: IAlertRepository,
  ) {}

  async handle(query: GetThreatHistoryQuery): Promise<ThreatHistoryDto[]> {
    const userId = UserId.from(query.userId);
    const tenantId = TenantId.from(query.tenantId);

    const alerts = await this.alertRepo.findByUserId(userId, tenantId, query.since);

    return alerts.map((alert) => ({
      id: alert.id,
      threatScore: alert.threatScore,
      killChainStage: alert.killChainStage,
      signals: alert.signals.map((s) => ({
        signal: s.signal,
        score: s.score,
        detail: s.detail,
      })),
      workflow: alert.workflow,
      createdAt: alert.createdAt.toISOString(),
    }));
  }
}
