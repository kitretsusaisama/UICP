import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { Inject, Injectable, Logger } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
@Processor('audit-export', { concurrency: 2 })
export class AuditExportWorker extends WorkerHost {
  private readonly logger = new Logger(AuditExportWorker.name);

  constructor(@Inject('MYSQL_POOL') private readonly dbPool: Pool) {
    super();
  }

  async process(job: Job<any, any, string>): Promise<any> {
    const { exportId, tenantId, fromTimestamp, toTimestamp, actorId } = job.data;
    const tempDir = path.join('/tmp', 'uicp_exports', tenantId);
    fs.mkdirSync(tempDir, { recursive: true });

    const filePath = path.join(tempDir, `${exportId}.csv`);

    try {
       await this.dbPool.query('UPDATE audit_exports SET status = "processing" WHERE id = ?', [exportId]);

       const writeStream = fs.createWriteStream(filePath, { flags: 'w' });
       writeStream.write('audit_id,event,actor_id,timestamp,metadata\n');

       // Simulating streaming via batch pagination to avoid loading millions of rows into memory
       let offset = 0;
       const limit = 1000;
       let hasMore = true;

       while (hasMore) {
          const [rows]: any = await this.dbPool.query(
             `SELECT audit_id, event, actor_id, timestamp, metadata
              FROM audit_logs
              WHERE tenant_id = ? AND timestamp >= ? AND timestamp <= ?
              ORDER BY timestamp ASC LIMIT ? OFFSET ?`,
             [tenantId, fromTimestamp, toTimestamp, limit, offset]
          );

          if (rows.length === 0) {
             hasMore = false;
          } else {
             for (const row of rows) {
                const metadataStr = JSON.stringify(row.metadata).replace(/"/g, '""');
                writeStream.write(`"${row.audit_id}","${row.event}","${row.actor_id}",${row.timestamp},"${metadataStr}"\n`);
             }
             offset += limit;
          }
       }

       writeStream.end();

       await this.dbPool.query(
           'UPDATE audit_exports SET status = "completed", file_path = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?',
           [filePath, exportId]
       );

       this.logger.log(`Completed audit export ${exportId}`);
       return { filePath };

    } catch (err: any) {
       this.logger.error(`Failed audit export ${exportId}: ${err.message}`);
       await this.dbPool.query(
           'UPDATE audit_exports SET status = "failed", error_message = ? WHERE id = ?',
           [err.message, exportId]
       );
       throw err;
    }
  }
}
