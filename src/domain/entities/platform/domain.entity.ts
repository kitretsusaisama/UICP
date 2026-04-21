export type DomainStatus = 'pending' | 'verified' | 'failed';

export interface DomainProps {
  id: string;
  tenantId: string;
  domainName: string;
  status: DomainStatus;
  dnsTxtRecord: string;
  createdAt?: Date;
  verifiedAt?: Date | null;
}

export class Domain {
  readonly id: string;
  readonly tenantId: string;
  readonly domainName: string;
  private _status: DomainStatus;
  readonly dnsTxtRecord: string;
  readonly createdAt: Date;
  private _verifiedAt: Date | null;

  constructor(props: DomainProps) {
    this.id = props.id;
    this.tenantId = props.tenantId;
    this.domainName = props.domainName;
    this._status = props.status;
    this.dnsTxtRecord = props.dnsTxtRecord;
    this.createdAt = props.createdAt ?? new Date();
    this._verifiedAt = props.verifiedAt ?? null;
  }

  get status(): DomainStatus {
    return this._status;
  }

  get verifiedAt(): Date | null {
    return this._verifiedAt;
  }

  verify(): void {
    this._status = 'verified';
    this._verifiedAt = new Date();
  }

  fail(): void {
    this._status = 'failed';
  }
}
