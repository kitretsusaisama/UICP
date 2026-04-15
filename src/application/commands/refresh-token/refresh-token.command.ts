export class RefreshTokenCommand {
  constructor(
    public readonly tenantId: string,
    public readonly refreshToken: string,
  ) {}
}
