export class SignupEmailCommand {
  constructor(
    public readonly tenantId: string,
    public readonly email: string,
    public readonly password: string,
    public readonly idempotencyKey?: string,
  ) {}
}
