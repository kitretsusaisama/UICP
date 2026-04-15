import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';

export type AlertWorkflowState = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'FALSE_POSITIVE';

export type KillChainStage =
  | 'RECONNAISSANCE'
  | 'INITIAL_ACCESS'
  | 'CREDENTIAL_ACCESS'
  | 'LATERAL_MOVEMENT'
  | 'ACCOUNT_TAKEOVER';

export interface SignalResult {
  signal: string;
  score: number;
  detail?: string;
}

/** Immutable SOC alert record. */
export interface SocAlert {
  id: string;
  tenantId: string;
  userId?: string;
  ipHash: string;
  threatScore: number;
  killChainStage: KillChainStage;
  signals: SignalResult[];
  workflow: AlertWorkflowState;
  /** HMAC-SHA256 checksum of the immutable fields — verified on read (Req 12.10). */
  checksum: string;
  acknowledgedBy?: string;
  acknowledgedAt?: Date;
  resolvedBy?: string;
  resolvedAt?: Date;
  createdAt: Date;
}

export interface AlertWorkflow {
  state: AlertWorkflowState;
  updatedBy: string;
  updatedAt: Date;
}

export interface AlertQueryParams {
  workflowState?: AlertWorkflowState;
  minThreatScore?: number;
  maxThreatScore?: number;
  killChainStage?: KillChainStage;
  since?: Date;
  until?: Date;
  limit?: number;
  cursor?: string;
}

export interface PaginatedResult<T> {
  items: T[];
  nextCursor?: string;
  total: number;
}

/**
 * Driven port — SOC alert persistence (Section 4.4).
 *
 * Contract:
 * - `save` is INSERT only — alerts are immutable core records.
 * - `updateWorkflow` only updates the `workflow` column.
 * - HMAC checksum is verified on read; throws `IntegrityViolationException` if tampered (Req 12.10).
 */
export interface IAlertRepository {
  /**
   * Persist a new SOC alert (INSERT only).
   */
  save(alert: SocAlert): Promise<void>;

  /**
   * Query alerts for the SOC dashboard with filtering and cursor pagination.
   */
  findByTenantId(tenantId: TenantId, params: AlertQueryParams): Promise<PaginatedResult<SocAlert>>;

  /**
   * Update the workflow state of an alert.
   * Only the `workflow` column is modified — core alert fields remain immutable.
   */
  updateWorkflow(alertId: string, workflow: AlertWorkflow, tenantId: TenantId): Promise<void>;

  /**
   * Load threat history for a user (for UEBA baseline computation).
   */
  findByUserId(userId: UserId, tenantId: TenantId, since: Date): Promise<SocAlert[]>;
}
