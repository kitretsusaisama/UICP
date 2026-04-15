/**
 * Query: load SOC alert threat history for a user with signal breakdown.
 * Implements: Req 12.5
 */
export class GetThreatHistoryQuery {
  constructor(
    public readonly userId: string,
    public readonly tenantId: string,
    /** Default: 30 days ago. */
    public readonly since: Date = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
  ) {}
}
