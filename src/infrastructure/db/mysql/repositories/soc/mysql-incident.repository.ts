import { Injectable, Logger } from '@nestjs/common';
import { IIncidentRepository } from '../../../../../domain/repositories/soc/incident.repository.interface';

@Injectable()
export class MysqlIncidentRepository implements IIncidentRepository {
  private readonly logger = new Logger(MysqlIncidentRepository.name);

  async create(input: Record<string, unknown>): Promise<void> {
    this.logger.debug({ input }, 'Incident persistence placeholder');
  }
}
