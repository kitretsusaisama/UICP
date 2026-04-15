/**
 * Query: list all active sessions for a user, enriched with device info.
 * Implements: Req 8.7
 */
export class GetUserSessionsQuery {
  constructor(
    public readonly userId: string,
    public readonly tenantId: string,
    /** Must match userId or be an admin — enforced by the handler. */
    public readonly requestingUserId: string,
  ) {}
}
