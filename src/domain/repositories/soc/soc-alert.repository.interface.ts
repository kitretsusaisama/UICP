import { SocAlert } from '../../entities/soc/soc-alert.entity';

export const SOC_ALERT_REPOSITORY = 'SOC_ALERT_REPOSITORY';

export interface ISocAlertRepository {
  save(alert: SocAlert): Promise<void>;
}
