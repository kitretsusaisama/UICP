import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class AuditExportWorker {
  private readonly logger = new Logger(AuditExportWorker.name);

  async process(job: { data: unknown }): Promise<void> {
    this.logger.debug({ job: job.data }, 'Audit export placeholder processed');
  }
}
