import { OtpPurpose } from './i-otp.port';

export interface SmsDispatchParams {
  recipient: string;
  message: string;
  code: string;
  purpose: OtpPurpose;
  tenantName?: string;
}

export interface ISmsProvider {
  readonly providerKey: string;
  readonly channel: 'SMS';
  isEnabled(): boolean;
  send(params: SmsDispatchParams): Promise<{ providerMessageId?: string }>;
}
