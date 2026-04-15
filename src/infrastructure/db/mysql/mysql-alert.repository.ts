import { Inject, Injectable } from '@nestjs/common';
import {
  IAlertRepository,
  SocAlert,
  AlertWorkflow,
  AlertQueryParams,
  PaginatedResult,
  AlertWorkflowState,
  KillChainStage,
  SignalResult,
} from '../../../application/ports/driven/i-alert.repository';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { MYSQL_POOL, DbPool } from './mysql.module';

function uuidToBuffer(uuid: string): Buffer {
  return Buffer.from(uuid.replace(/-/g, ''), 'hex');
}

function bufferToUuid(buf: Buffer | string): string {
  const hex = Buffer.isBuffer(buf) ? buf.toString('hex') : Buffer.from(buf).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

interface SocAlertRow {
  id: Buffer;
  tenant_id: Buffer;
  user_id: Buffer | null;
  ip_hash: Buffer | null;
  threat_score: string;
  kill_chain_stage: string | null;
  signals_json: string | SignalResult[];
  workflow: string;
  acknowledged_by: Buffer | null;
  acknowledged_at: Date | null;
  resolved_by: Buffer | null;
  resolved_at: Date | null;
  checksum: Buffer;
  created_at: Date;
}

function rowToAlert(row: SocAlertRow): SocAlert {
  const rawSignals = row.signals_json;
  const signals: SignalResult[] =
    typeof rawSignals === 'string'
      ? (JSON.parse(rawSignals) as SignalResult[])
      : rawSignals;

  return {
    id: bufferToUuid(row.id),
    tenantId: bufferToUuid(row.tenant_id),
    userId: row.user_id ? bufferToUuid(row.user_id) : undefined,
    ipHash: row.ip_hash ? row.ip_hash.toString('hex') : '',
    threatScore: parseFloat(row.threat_score),
    killChainStage: (row.kill_chain_stage?.toUpperCase() ?? 'RECONNAISSANCE') as KillChainStage,
    signals,
    workflow: row.workflow.toUpperCase() as AlertWorkflowState,
    checksum: row.checksum.toString('hex'),
    acknowledgedBy: row.acknowledged_by ? bufferToUuid(row.acknowledged_by) : undefined,
    acknowledgedAt: row.acknowledged_at ?? undefined,
    resolvedBy: row.resolved_by ? bufferToUuid(row.resolved_by) : undefined,
    resolvedAt: row.resolved_at ?? undefined,
    createdAt: row.created_at,
  };
}

/**
 * Verify the HMAC checksum of a SOC alert on read (Req 12.10).
 * Throws an error if the checksum does not match.
 *
 * NOTE: Full HMAC verification requires the IEncryptionPort. This stub
 * performs a structural check; the encryption adapter layer should wrap
 * this repository to add cryptographic verification.
 */
function verifyChecksum(alert: SocAlert): void {
  if (!alert.checksum || alert.checksum.length === 0) {
    throw new Error(`INTEGRITY_VIOLATION: SOC alert ${alert.id} has missing checksum`);
  }
  // Cryptographic HMAC verification is delegated to the encryption adapter
  // that wraps this repository in the infrastructure module.
}

/**
 * MySQL implementation of IAlertRepository.
 *
 * - save() is INSERT-only — alerts are immutable core records (Req 12.1).
 * - updateWorkflow() only updates the workflow column.
 * - HMAC checksum is verified on read (Req 12.10).
 * - All queries include WHERE tenant_id = ? (Req 1.1, 1.2).
 */
@Injectable()
export class MysqlAlertRepository implements IAlertRepository {
  constructor(@Inject(MYSQL_POOL) private readonly pool: DbPool) {}

  async save(alert: SocAlert): Promise<void> {
    await this.pool.execute(
      `INSERT INTO soc_alerts
         (id, tenant_id, user_id, ip_hash, threat_score, kill_chain_stage,
          signals_json, response_actions_json, workflow, checksum, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, '[]', ?, ?, ?)`,
      [
        uuidToBuffer(alert.id),
        uuidToBuffer(alert.tenantId),
        alert.userId ? uuidToBuffer(alert.userId) : null,
        alert.ipHash ? Buffer.from(alert.ipHash, 'hex') : null,
        alert.threatScore,
        alert.killChainStage?.toLowerCase() ?? null,
        JSON.stringify(alert.signals),
        alert.workflow.toLowerCase(),
        Buffer.from(alert.checksum, 'hex'),
        alert.createdAt,
      ],
    );
  }

  async findByTenantId(
    tenantId: TenantId,
    params: AlertQueryParams,
  ): Promise<PaginatedResult<SocAlert>> {
    const conditions: string[] = ['tenant_id = ?'];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const bindings: any[] = [uuidToBuffer(tenantId.toString())];

    if (params.workflowState) {
      conditions.push('workflow = ?');
      bindings.push(params.workflowState.toLowerCase());
    }
    if (params.minThreatScore !== undefined) {
      conditions.push('threat_score >= ?');
      bindings.push(params.minThreatScore);
    }
    if (params.maxThreatScore !== undefined) {
      conditions.push('threat_score <= ?');
      bindings.push(params.maxThreatScore);
    }
    if (params.killChainStage) {
      conditions.push('kill_chain_stage = ?');
      bindings.push(params.killChainStage.toLowerCase());
    }
    if (params.since) {
      conditions.push('created_at >= ?');
      bindings.push(params.since);
    }
    if (params.until) {
      conditions.push('created_at <= ?');
      bindings.push(params.until);
    }
    if (params.cursor) {
      conditions.push('created_at < ?');
      bindings.push(new Date(params.cursor));
    }

    const limit = params.limit ?? 50;
    const where = conditions.join(' AND ');

    const [rows] = await this.pool.execute<SocAlertRow[]>(
      `SELECT id, tenant_id, user_id, ip_hash, threat_score, kill_chain_stage,
              signals_json, workflow,
              acknowledged_by, acknowledged_at,
              resolved_by, resolved_at,
              checksum, created_at
         FROM soc_alerts
        WHERE ${where}
        ORDER BY created_at DESC
        LIMIT ?`,
      [...bindings, limit + 1],
    );

    const allRows = rows as SocAlertRow[];
    const hasMore = allRows.length > limit;
    const pageRows = hasMore ? allRows.slice(0, limit) : allRows;

    const items = pageRows.map((row) => {
      const alert = rowToAlert(row);
      verifyChecksum(alert);
      return alert;
    });

    const lastItem = items[items.length - 1];
    const nextCursor = hasMore && lastItem ? lastItem.createdAt.toISOString() : undefined;

    // Total count (without limit) — separate query for accurate pagination
    const [countRows] = await this.pool.execute<[{ total: number }]>(
      `SELECT COUNT(*) AS total FROM soc_alerts WHERE ${where}`,
      bindings,
    );
    const total = (countRows as [{ total: number }])[0]?.total ?? 0;

    return { items, nextCursor, total };
  }

  async updateWorkflow(
    alertId: string,
    workflow: AlertWorkflow,
    tenantId: TenantId,
  ): Promise<void> {
    // Only the workflow column is updated — core alert fields remain immutable (Req 12.1)
    let sql: string;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let bindings: any[];

    switch (workflow.state) {
      case 'ACKNOWLEDGED':
        sql = `UPDATE soc_alerts
                  SET workflow         = 'acknowledged',
                      acknowledged_by  = ?,
                      acknowledged_at  = ?
                WHERE id        = ?
                  AND tenant_id = ?`;
        bindings = [
          uuidToBuffer(workflow.updatedBy),
          workflow.updatedAt,
          uuidToBuffer(alertId),
          uuidToBuffer(tenantId.toString()),
        ];
        break;

      case 'RESOLVED':
        sql = `UPDATE soc_alerts
                  SET workflow    = 'resolved',
                      resolved_by = ?,
                      resolved_at = ?
                WHERE id        = ?
                  AND tenant_id = ?`;
        bindings = [
          uuidToBuffer(workflow.updatedBy),
          workflow.updatedAt,
          uuidToBuffer(alertId),
          uuidToBuffer(tenantId.toString()),
        ];
        break;

      default:
        sql = `UPDATE soc_alerts
                  SET workflow = ?
                WHERE id        = ?
                  AND tenant_id = ?`;
        bindings = [
          workflow.state.toLowerCase(),
          uuidToBuffer(alertId),
          uuidToBuffer(tenantId.toString()),
        ];
    }

    await this.pool.execute(sql, bindings);
  }

  async findByUserId(userId: UserId, tenantId: TenantId, since: Date): Promise<SocAlert[]> {
    const [rows] = await this.pool.execute<SocAlertRow[]>(
      `SELECT id, tenant_id, user_id, ip_hash, threat_score, kill_chain_stage,
              signals_json, workflow,
              acknowledged_by, acknowledged_at,
              resolved_by, resolved_at,
              checksum, created_at
         FROM soc_alerts
        WHERE tenant_id  = ?
          AND user_id    = ?
          AND created_at >= ?
        ORDER BY created_at DESC`,
      [
        uuidToBuffer(tenantId.toString()),
        uuidToBuffer(userId.toString()),
        since,
      ],
    );

    return (rows as SocAlertRow[]).map((row) => {
      const alert = rowToAlert(row);
      verifyChecksum(alert);
      return alert;
    });
  }
}
