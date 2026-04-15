export class LogoutAllCommand {
  constructor(
    public readonly tenantId: string,
    public readonly userId: string,
  ) {}
}
