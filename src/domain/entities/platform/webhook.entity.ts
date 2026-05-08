export type WebhookStatus = 'active' | 'suspended';

export interface WebhookProps {
  id: string;
  tenantId: string;
  appId: string;
  url: string;
  events: string[];
  secretKey: string;
  status: WebhookStatus;
  failureCount?: number;
  createdAt?: Date;
}

export class Webhook {
  readonly id: string;
  readonly tenantId: string;
  readonly appId: string;
  readonly url: string;
  readonly events: string[];
  readonly secretKey: string; // Used to sign payloads with HMAC-SHA256
  private _status: WebhookStatus;
  private _failureCount: number;
  readonly createdAt: Date;

  constructor(props: WebhookProps) {
    this.id = props.id;
    this.tenantId = props.tenantId;
    this.appId = props.appId;
    this.url = props.url;
    this.events = props.events;
    this.secretKey = props.secretKey;
    this._status = props.status;
    this._failureCount = props.failureCount ?? 0;
    this.createdAt = props.createdAt ?? new Date();
  }

  get status(): WebhookStatus {
    return this._status;
  }

  get failureCount(): number {
    return this._failureCount;
  }

  recordFailure(): void {
    this._failureCount++;
    if (this._failureCount >= 5) {
      this._status = 'suspended'; // Auto-suspend after 5 consecutive failures
    }
  }

  resetFailures(): void {
    this._failureCount = 0;
    this._status = 'active';
  }
}
