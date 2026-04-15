export class VerifyOtpCommand {
  constructor(
    public readonly tenantId: string,
    public readonly userId: string,
    public readonly code: string,
    public readonly purpose: 'IDENTITY_VERIFICATION' | 'MFA' | 'PASSWORD_RESET',
    public readonly identityId?: string,
    public readonly sessionId?: string,
  ) {}
}
