export class PasswordResetRequestCommand {
  constructor(
    public readonly tenantId: string,
    public readonly identity: string,
    public readonly identityType?: 'EMAIL' | 'PHONE',
  ) {}
}
