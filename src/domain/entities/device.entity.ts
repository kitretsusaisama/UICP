/**
 * Device entity — represents a known device associated with a user session.
 * Pure domain object; zero framework imports.
 */
export interface DeviceParams {
  fingerprint: string;
  trusted: boolean;
  trustedAt?: Date;
  createdAt?: Date;
}

export class Device {
  readonly fingerprint: string;
  private trusted: boolean;
  private trustedAt?: Date;
  readonly createdAt: Date;

  constructor(params: DeviceParams) {
    this.fingerprint = params.fingerprint;
    this.trusted = params.trusted;
    this.trustedAt = params.trustedAt;
    this.createdAt = params.createdAt ?? new Date();
  }

  /** Mark this device as trusted (e.g. after successful MFA verification). */
  trust(): void {
    this.trusted = true;
    this.trustedAt = new Date();
  }

  isTrusted(): boolean {
    return this.trusted;
  }

  getTrustedAt(): Date | undefined {
    return this.trustedAt;
  }
}
