export class LoginCommand {
  constructor(
    public readonly tenantId: string,
    public readonly identity: string,
    public readonly password: string,
    public readonly ipHash: string,
    public readonly userAgent: string,
    public readonly deviceFingerprint?: string,
    public readonly identityType?: 'EMAIL' | 'PHONE',
  ) {}
}
