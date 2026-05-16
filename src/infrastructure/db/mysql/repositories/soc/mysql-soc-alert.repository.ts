import { Injectable, Logger } from '@nestjs/common';
import { SocAlert } from '../../../../../domain/entities/soc/soc-alert.entity';
import { ISocAlertRepository } from '../../../../../domain/repositories/soc/soc-alert.repository.interface';

@Injectable()
export class MysqlSocAlertRepository implements ISocAlertRepository {
  private readonly logger = new Logger(MysqlSocAlertRepository.name);

  async save(alert: SocAlert): Promise<void> {
    this.logger.debug({ tenantId: alert.tenantId, type: alert.type }, 'SOC alert persistence placeholder');
  }
}
