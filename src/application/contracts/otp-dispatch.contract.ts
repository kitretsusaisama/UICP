import { OtpChannel, OtpPurpose } from '../ports/driven/i-otp.port';

export interface OtpDispatchPayload {
  [key: string]: unknown;
  userId: string;
  tenantId?: string;
  recipient: string;
  channel: OtpChannel;
  purpose: OtpPurpose;
  code: string;
  tenantName?: string;
}
