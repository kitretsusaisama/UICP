export class ChangePasswordCommand {
  constructor(
    public readonly tenantId: string,
    public readonly userId: string,
    public readonly currentPassword: string,
    public readonly newPassword: string,
    public readonly currentSessionId: string,
  ) {}
}
