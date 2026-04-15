/**
 * Query: validate an access token — RS256 signature, exp/iss/aud claims,
 * and O(1) Redis blocklist check. Zero DB round trips.
 * Implements: Req 7.7
 */
export class ValidateTokenQuery {
  constructor(
    public readonly token: string,
    public readonly requiredType: 'access' | 'refresh' = 'access',
  ) {}
}
