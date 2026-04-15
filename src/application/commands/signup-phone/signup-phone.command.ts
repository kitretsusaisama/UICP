export class SignupPhoneCommand {
  constructor(
    public readonly tenantId: string,
    public readonly phone: string,
    public readonly password: string,
    public readonly idempotencyKey?: string,
  ) {}
}
