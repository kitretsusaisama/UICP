import { Injectable, Logger } from '@nestjs/common';
import { IOtpAdapter, OtpDispatchParams } from '../../application/ports/driven/i-otp.adapter';
import { ResilientProvider } from '../governance/resilience/resilient-provider';

@Injectable()
export class FirebaseOtpAdapter implements IOtpAdapter {
  private readonly logger = new Logger(FirebaseOtpAdapter.name);

  constructor(private readonly circuitBreaker: ResilientProvider) {}

  async dispatch(params: OtpDispatchParams): Promise<void> {
    if (params.channel !== 'sms') {
      throw new Error('FirebaseOtpAdapter only handles SMS channel');
    }

    const smsRecipientPattern =
      process.env.OTP_SMS_RECIPIENT_PATTERN
        ? new RegExp(process.env.OTP_SMS_RECIPIENT_PATTERN)
        : /^\+[1-9]\d{7,14}$/;

    if (!smsRecipientPattern.test(params.recipient)) {
      this.logger.warn(
        {
          pattern: smsRecipientPattern.toString(),
        },
        'SMS Dispatch Blocked: Phone number failed validation against configured pattern'
      );
      throw new Error('OTP_DELIVERY_FAILED: Invalid phone number format');
    }

    await this.circuitBreaker.executeWithResilience('firebase-otp', () => this.dispatchSms(params));
  }

  private async dispatchSms(params: OtpDispatchParams): Promise<void> {
    // Simulated outbound SMS integration logic
    this.logger.debug('Mock SMS sent securely.');
  }
}
