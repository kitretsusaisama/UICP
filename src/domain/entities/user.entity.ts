export class User {
  constructor(
    public readonly id: string,
    public readonly tenantId: string,
    public readonly email?: string,
    public readonly phone?: string,
  ) {}
}
