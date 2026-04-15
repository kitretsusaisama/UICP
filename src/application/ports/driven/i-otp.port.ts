/**
 * Delivery channel for OTP codes.
 */
export type OtpChannel = 'EMAIL' | 'SMS';

/**
 * Purpose of the OTP — determines the message template and TTL.
 */
export type OtpPurpose = 'IDENTITY_VERIFICATION' | 'MFA' | 'PASSWORD_RESET';

export interface SendOtpParams {
  tenantId: string;
  /** Recipient address — email address or E.164 phone number. */
  recipient: string;
  channel: OtpChannel;
  purpose: OtpPurpose;
  /** The 6-digit OTP code to deliver. */
  code: string;
  /** Tenant-specific display name shown in the message. */
  tenantName?: string;
}

/**
 * Driven port — OTP delivery routed through pluggable SMS and email providers.
 *
 * Contract:
 * - `send` dispatches the OTP via the specified channel.
 * - SMS and email providers are selected by the provider routing service.
 * - Throws `InfrastructureException(OTP_DELIVERY_FAILED)` when both channels fail.
 */
export interface IOtpPort {
  /**
   * Deliver a one-time password to the recipient via the specified channel.
   */
  send(params: SendOtpParams): Promise<void>;
}
