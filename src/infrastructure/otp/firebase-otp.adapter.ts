import { Injectable } from '@nestjs/common';

export interface OtpDispatchParams {
  tenantId?: string;
  recipient: string;
  channel: 'SMS' | 'EMAIL';
  purpose: 'IDENTITY_VERIFICATION' | 'MFA' | 'PASSWORD_RESET';
  code: string;
  tenantName?: string;
}

@Injectable()
export class FirebaseOtpAdapter {
  isCircuitOpen(): boolean {
    return false;
  }

  async send(params: OtpDispatchParams): Promise<void> {
    if (params.channel !== 'SMS') {
      return;
    }
  }
}
