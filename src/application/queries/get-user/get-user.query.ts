/**
 * Query: load a user profile by ID with tenant isolation and PII decryption.
 * Implements: Req 1.1, Req 1.3, Req 13.1
 */
export class GetUserQuery {
  constructor(
    public readonly userId: string,
    public readonly tenantId: string,
    /** The requesting user — used for authorization checks. */
    public readonly requestingUserId: string,
  ) {}
}
