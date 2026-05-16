export type SocAlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type SocAlertStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED';

export class SocAlert {
  readonly id: string;
  readonly tenantId: string;
  readonly type: string;
  readonly severity: SocAlertSeverity;
  readonly dedupeKey: string;
  readonly payload: Record<string, unknown>;
  readonly status: SocAlertStatus;

  constructor(input: {
    id: string;
    tenantId: string;
    type: string;
    severity: SocAlertSeverity;
    dedupeKey: string;
    payload: Record<string, unknown>;
    status: SocAlertStatus;
  }) {
    this.id = input.id;
    this.tenantId = input.tenantId;
    this.type = input.type;
    this.severity = input.severity;
    this.dedupeKey = input.dedupeKey;
    this.payload = input.payload;
    this.status = input.status;
  }
}
