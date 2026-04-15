export type OAuthProvider = 'google' | 'github' | 'apple' | 'microsoft';

export class OAuthCallbackCommand {
  constructor(
    public readonly tenantId: string,
    public readonly provider: OAuthProvider,
    public readonly code: string,
    public readonly state: string,
    public readonly expectedState: string,
    public readonly redirectUri: string,
    public readonly ipHash: string,
    public readonly userAgent: string,
    public readonly providerSub: string,
    public readonly providerEmail?: string,
  ) {}
}
