import { OtpPurpose } from './i-otp.port';

export interface EmailDispatchParams {
  recipient: string;
  subject: string;
  text: string;
  html: string;
  purpose: OtpPurpose;
  tenantName?: string;
}

export interface IEmailProvider {
  readonly providerKey: string;
  readonly channel: 'EMAIL';
  isEnabled(): boolean;
  send(params: EmailDispatchParams): Promise<{ providerMessageId?: string }>;
}
