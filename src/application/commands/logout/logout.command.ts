export class LogoutCommand {
  constructor(
    public readonly tenantId: string,
    public readonly userId: string,
    public readonly sessionId: string,
    public readonly accessTokenJti: string,
    public readonly accessTokenExpiresAt: Date,
  ) {}
}
