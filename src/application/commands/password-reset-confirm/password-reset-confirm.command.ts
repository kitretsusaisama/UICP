export class PasswordResetConfirmCommand {
  constructor(
    public readonly tenantId: string,
    public readonly resetToken: string,
    public readonly newPassword: string,
  ) {}
}
