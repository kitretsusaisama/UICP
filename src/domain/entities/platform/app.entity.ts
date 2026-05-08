export type AppType = 'public' | 'confidential' | 'internal';

export interface AppProps {
  id: string;
  tenantId: string;
  clientId: string;
  name: string;
  type: AppType;
  redirectUris: string[];
  allowedOrigins: string[];
  createdAt?: Date;
  updatedAt?: Date;
}

export class App {
  readonly id: string;
  readonly tenantId: string;
  readonly clientId: string;
  readonly name: string;
  readonly type: AppType;
  private _redirectUris: string[];
  private _allowedOrigins: string[];
  readonly createdAt: Date;
  private _updatedAt: Date;

  constructor(props: AppProps) {
    this.id = props.id;
    this.tenantId = props.tenantId;
    this.clientId = props.clientId;
    this.name = props.name;
    this.type = props.type;
    this._redirectUris = this.normalizeUrls(props.redirectUris);
    this._allowedOrigins = this.normalizeUrls(props.allowedOrigins);
    this.createdAt = props.createdAt ?? new Date();
    this._updatedAt = props.updatedAt ?? new Date();
  }

  get redirectUris(): string[] {
    return [...this._redirectUris];
  }

  get allowedOrigins(): string[] {
    return [...this._allowedOrigins];
  }

  get updatedAt(): Date {
    return this._updatedAt;
  }

  private normalizeUrls(urls: string[]): string[] {
    // Exact match deduplication and basic normalization
    const unique = Array.from(new Set(urls.map(u => u.trim())));
    return unique.filter(u => {
      try {
        new URL(u);
        return true;
      } catch {
        return false; // drop invalid formats
      }
    });
  }

  updateMetadata(redirectUris: string[], allowedOrigins: string[]): void {
    this._redirectUris = this.normalizeUrls(redirectUris);
    this._allowedOrigins = this.normalizeUrls(allowedOrigins);
    this._updatedAt = new Date();
  }
}
