export class RotateKeysCommand {
  constructor(
    public readonly requestedBy: string,
    public readonly tenantId: string,
  ) {}
}
