/**
 * @uicp/sdk - Core Client
 *
 * Fully dynamic, pluggable, enterprise-grade client
 * No hardcoded values - everything is configurable
 */

import type { UicpClientConfig, IStorageAdapter, TokenSet, RequestOptions } from '../types';
import { createErrorFromResponse, UicpError, UicpSessionExpiredError, isSessionExpiredError } from '../errors/UicpError';
import { TokenVault } from '../auth/token-vault';
import { createStorage } from '../storage/adapters';

// ═════════════════════════════════════════════════════════════════════════════
// PLUGIN SYSTEM
// ═════════════════════════════════════════════════════════════════════════════

export interface UicpPlugin {
  name: string;
  version?: string;
  onRequest?: (ctx: RequestContext) => Promise<RequestContext> | RequestContext;
  onResponse?: <T>(ctx: ResponseContext<T>) => Promise<ResponseContext<T>> | ResponseContext<T>;
  onError?: (error: UicpError, ctx: RequestContext) => void | Promise<void>;
}

export interface RequestContext {
  method: string;
  path: string;
  url: string;
  headers: Record<string, string>;
  body?: unknown;
  options?: RequestOptions;
  meta: { requiresAuth: boolean; isIdempotent: boolean };
}

export interface ResponseContext<T = unknown> {
  statusCode: number;
  data: T;
  headers: Record<string, string>;
  durationMs: number;
  request: RequestContext;
}

// ═════════════════════════════════════════════════════════════════════════════
// EVENT BUS
// ═════════════════════════════════════════════════════════════════════════════

export class EventBus {
  private handlers = new Map<string, Set<(payload: unknown) => void>>();

  on(event: string, handler: (payload: unknown) => void): () => void {
    if (!this.handlers.has(event)) this.handlers.set(event, new Set());
    this.handlers.get(event)!.add(handler);
    return () => this.off(event, handler);
  }

  off(event: string, handler: (payload: unknown) => void): void {
    this.handlers.get(event)?.delete(handler);
  }

  emit(event: string, payload: unknown): void {
    this.handlers.get(event)?.forEach((h) => { try { h(payload); } catch { } });
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// BUILT-IN PLUGINS
// ═════════════════════════════════════════════════════════════════════════════

export function createTenantPlugin(tenantId: string): UicpPlugin {
  return {
    name: 'tenant-header',
    onRequest: (ctx) => ({ ...ctx, headers: { ...ctx.headers, 'x-tenant-id': tenantId } }),
  };
}

export function createAuthPlugin(vault: TokenVault): UicpPlugin {
  return {
    name: 'auth-header',
    onRequest: async (ctx) => {
      if (!ctx.meta.requiresAuth) return ctx;
      const token = await vault.getAccessToken();
      if (!token) return ctx;
      return { ...ctx, headers: { ...ctx.headers, Authorization: `Bearer ${token}` } };
    },
  };
}

export function createIdempotencyPlugin(): UicpPlugin {
  const costCriticalPaths = ['/auth/signup', '/users/me/identities', '/auth/password/reset/request'];
  return {
    name: 'idempotency',
    onRequest: (ctx) => {
      if (ctx.method !== 'POST') return ctx;
      const isCostCritical = costCriticalPaths.some((p) => ctx.path.includes(p));
      if (!isCostCritical && !ctx.options?.idempotencyKey) return ctx;
      return { ...ctx, headers: { ...ctx.headers, 'x-idempotency-key': ctx.options?.idempotencyKey ?? crypto.randomUUID() } };
    },
  };
}

export function createRefreshPlugin(vault: TokenVault, refreshFn: () => Promise<TokenSet>): UicpPlugin {
  return {
    name: 'token-refresh',
    onError: async (error, ctx) => {
      if (error.statusCode !== 401 || !ctx.meta.requiresAuth) return;
      if (isSessionExpiredError(error)) return;
      try {
        const tokens = await refreshFn();
        await vault.setTokens(tokens);
      } catch { /* refresh failed */ }
    },
  };
}

// ═════════════════════════════════════════════════════════════════════════════
// HTTP TRANSPORT
// ═════════════════════════════════════════════════════════════════════════════

export class HttpTransport {
  private fetchFn: typeof fetch;
  private baseUrl: string;
  private plugins: UicpPlugin[] = [];
  private timeout: number;

  constructor(config: UicpClientConfig) {
    this.fetchFn = config.fetch ?? globalThis.fetch;
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    this.timeout = config.timeout ?? 30000;
  }

  addPlugin(plugin: UicpPlugin): void {
    this.plugins.push(plugin);
  }

  async request<T>(method: string, path: string, body?: unknown, options?: RequestOptions): Promise<T> {
    const startTime = Date.now();
    const url = `${this.baseUrl}${path}`;

    let ctx: RequestContext = {
      method, path, url,
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', ...options?.headers },
      body, options,
      meta: { requiresAuth: true, isIdempotent: false },
    };

    for (const plugin of this.plugins) {
      if (plugin.onRequest) ctx = await plugin.onRequest(ctx);
    }

    const response = await this.fetchFn(ctx.url, {
      method: ctx.method,
      headers: ctx.headers,
      body: ctx.body ? JSON.stringify(ctx.body) : undefined,
      signal: options?.signal ?? (this.timeout ? AbortSignal.timeout(this.timeout) : undefined),
    });

    const durationMs = Date.now() - startTime;
    let data: unknown;
    try { data = await response.json(); } catch { data = null; }

    const resCtx: ResponseContext = {
      statusCode: response.status,
      data: data as T,
      headers: Object.fromEntries([...response.headers].map(([k, v]) => [k, v])),
      durationMs,
      request: ctx,
    };

    for (const plugin of this.plugins) {
      if (plugin.onResponse) {
        const transformed = await plugin.onResponse(resCtx);
        resCtx.data = transformed.data as T;
      }
    }

    if (resCtx.statusCode >= 400) {
      const error = createErrorFromResponse(resCtx.statusCode, resCtx.data, resCtx.headers);
      for (const plugin of this.plugins) { if (plugin.onError) await plugin.onError(error, ctx); }
      if (isSessionExpiredError(error)) throw new UicpSessionExpiredError({ traceId: error.traceId });
      throw error;
    }

    return resCtx.data as T;
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// CLIENT INTERFACES - Hide internal implementation
// ═════════════════════════════════════════════════════════════════════════════

export interface IAuthClient {
  login(body: { identifier: string; credential: string }): Promise<TokenSet>;
  signup(body: { identity: string; credential: string; type: string }): Promise<unknown>;
  refresh(body?: { refreshToken?: string }): Promise<{ accessToken: string; refreshToken: string; expiresIn: number; sessionId?: string }>;
  logout(): Promise<void>;
  logoutAll(): Promise<void>;
  sendOtp(body: { purpose: string; channel: string; identity: string }): Promise<unknown>;
  verifyOtp(body: { userId: string; code: string; purpose: string }): Promise<unknown>;
  changePassword(body: { currentPassword: string; newPassword: string }): Promise<void>;
  getOAuthUrl(provider: string): string;
  handleOAuthCallback(provider: string, params: { code: string; state: string }): Promise<TokenSet>;
}

export interface IUserClient {
  getMe(): Promise<unknown>;
  updateMe(body: Record<string, unknown>): Promise<unknown>;
  deleteMe(): Promise<void>;
  getIdentities(): Promise<unknown>;
  addIdentity(body: Record<string, unknown>): Promise<unknown>;
}

export interface ISessionClient {
  listSessions(): Promise<unknown>;
  revokeSession(sessionId: string): Promise<unknown>;
}

export interface ICoreClient {
  getIdentityContext(): Promise<unknown>;
  listMemberships(): Promise<unknown>;
  listActors(): Promise<unknown>;
  getCurrentSession(): Promise<unknown>;
  getAuthMethods(): Promise<unknown>;
}

export interface IAdminClient {
  listRoles(): Promise<unknown>;
  createRole(body: Record<string, unknown>): Promise<unknown>;
  deleteRole(roleId: string): Promise<unknown>;
  listPermissions(): Promise<unknown>;
  getUserRoles(userId: string): Promise<unknown>;
  assignUserRole(userId: string, body: Record<string, unknown>): Promise<unknown>;
}

export interface IPlatformClient {
  getManifests(): Promise<unknown>;
  getOpenApiSpec(): Promise<unknown>;
  getSdkDescriptor(): Promise<unknown>;
}

export interface IDynamicModuleClient {
  getResource(moduleKey: string, resourceKey: string): Promise<unknown>;
  executeCommand(moduleKey: string, commandKey: string, body: Record<string, unknown>): Promise<unknown>;
}

export interface IExtensionClient {
  executeCommand(extensionKey: string, commandKey: string, body: Record<string, unknown>): Promise<unknown>;
  getBindings(extensionKey: string): Promise<unknown>;
}

// ═════════════════════════════════════════════════════════════════════════════
// MAIN CLIENT
// ═════════════════════════════════════════════════════════════════════════════

export class UicpClient {
  readonly transport: HttpTransport;
  readonly events: EventBus;
  readonly vault: TokenVault;
  readonly config: UicpClientConfig;

  private _auth?: AuthClient;
  private _user?: UserClient;
  private _session?: SessionClient;
  private _core?: CoreClient;
  private _admin?: AdminClient;
  private _platform?: PlatformClient;
  private _modules?: DynamicModuleClient;
  private _extensions?: ExtensionClient;

  constructor(config: UicpClientConfig) {
    if (!config.baseUrl) throw new Error('baseUrl is required');
    if (!config.tenantId) throw new Error('tenantId is required');

    this.config = config;
    this.events = new EventBus();
    const storage = config.storage ?? createStorage();
    this.vault = new TokenVault(storage, config.earlyRefreshBufferMs ?? 30000);
    this.transport = new HttpTransport(config);

    this.transport.addPlugin(createTenantPlugin(config.tenantId));
    this.transport.addPlugin(createAuthPlugin(this.vault));
    this.transport.addPlugin(createIdempotencyPlugin());
    // Refresh plugin deferred - registers after client is fully constructed

    if (config.debug) {
      this.events.on('request:before', (p: unknown) => { const { method, path } = p as { method: string; path: string }; console.log(`[UICP] → ${method} ${path}`); });
      this.events.on('request:after', (p: unknown) => { const { method, path, statusCode, durationMs } = p as { method: string; path: string; statusCode: number; durationMs: number }; console.log(`[UICP] ← ${method} ${path} ${statusCode} (${durationMs}ms)`); });
    }

    this.events.on('session:expired', () => {
      this.vault.clearTokens();
      config.onSessionExpired?.();
    });
  }

  get auth(): IAuthClient { this._auth ??= new AuthClient(this); return this._auth as IAuthClient; }
  get user(): IUserClient { this._user ??= new UserClient(this); return this._user as IUserClient; }
  get session(): ISessionClient { this._session ??= new SessionClient(this); return this._session as ISessionClient; }
  get core(): ICoreClient { this._core ??= new CoreClient(this); return this._core as ICoreClient; }
  get admin(): IAdminClient { this._admin ??= new AdminClient(this); return this._admin as IAdminClient; }
  get platform(): IPlatformClient { this._platform ??= new PlatformClient(this); return this._platform as IPlatformClient; }
  get modules(): IDynamicModuleClient { this._modules ??= new DynamicModuleClient(this); return this._modules as IDynamicModuleClient; }
  get extensions(): IExtensionClient { this._extensions ??= new ExtensionClient(this); return this._extensions as IExtensionClient; }

  use(plugin: UicpPlugin): void { this.transport.addPlugin(plugin); }
  async isAuthenticated(): Promise<boolean> { return this.vault.hasTokens(); }
  async getAccessToken(): Promise<string | null> { return this.vault.getAccessToken(); }

  async setTokens(tokens: TokenSet): Promise<void> {
    await this.vault.setTokens(tokens);
    this.events.emit('tokens:set', { accessToken: tokens.accessToken, sessionId: tokens.sessionId });
  }

  async clearTokens(): Promise<void> {
    await this.vault.clearTokens();
    this.events.emit('tokens:cleared', undefined);
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// SUB-CLIENTS
// ═════════════════════════════════════════════════════════════════════════════

class AuthClient {
  constructor(protected client: UicpClient) {}

  async login(body: { identifier: string; credential: string }) {
    const r = await this.client.transport.request<TokenSet>('POST', '/v1/auth/login', body);
    await this.client.vault.setTokens(r);
    this.client.events.emit('tokens:set', { accessToken: r.accessToken, sessionId: r.sessionId });
    return r;
  }

  async signup(body: { identity: string; credential: string; type: string }) {
    return this.client.transport.request('POST', '/v1/auth/signup', body, { idempotencyKey: crypto.randomUUID() });
  }

  async refresh(body?: { refreshToken?: string }) {
    const rt = body?.refreshToken ?? await this.client.vault.getRefreshToken();
    const r = await this.client.transport.request<{ accessToken: string; refreshToken: string; expiresIn: number; sessionId?: string }>('POST', '/v1/auth/refresh', { refreshToken: rt });
    const sessionId = r.sessionId ?? await this.client.vault.getSessionId() ?? '';
    const tokens: TokenSet = { accessToken: r.accessToken, refreshToken: r.refreshToken, expiresIn: r.expiresIn, sessionId: sessionId as any };
    await this.client.vault.setTokens(tokens);
    return r;
  }

  async logout() {
    await this.client.transport.request('POST', '/v1/auth/logout', {});
    await this.client.vault.clearTokens();
    this.client.events.emit('tokens:cleared', undefined);
  }

  async logoutAll() {
    await this.client.transport.request('POST', '/v1/auth/logout-all', {});
    await this.client.vault.clearTokens();
    this.client.events.emit('tokens:cleared', undefined);
  }

  async sendOtp(body: { purpose: string; channel: string; identity: string }) {
    return this.client.transport.request('POST', '/v1/auth/otp/send', body);
  }

  async verifyOtp(body: { userId: string; code: string; purpose: string }) {
    return this.client.transport.request('POST', '/v1/auth/otp/verify', body);
  }

  async changePassword(body: { currentPassword: string; newPassword: string }) {
    await this.client.transport.request('POST', '/v1/auth/password/change', body, { idempotencyKey: crypto.randomUUID() });
    await this.client.vault.clearTokens();
    this.client.events.emit('tokens:cleared', undefined);
  }

  getOAuthUrl(provider: string): string { return `${this.client.config.baseUrl}/v1/auth/oauth/${provider}`; }

  async handleOAuthCallback(provider: string, params: { code: string; state: string }) {
    const r = await this.client.transport.request<TokenSet>('GET', `/v1/auth/oauth/${provider}/callback`, undefined, params as any);
    await this.client.vault.setTokens(r);
    return r;
  }
}

class UserClient {
  constructor(protected client: UicpClient) {}
  async getMe() { return this.client.transport.request('GET', '/v1/users/me'); }
  async updateMe(body: Record<string, unknown>) { return this.client.transport.request('PATCH', '/v1/users/me', body); }
  async deleteMe() { await this.client.transport.request('DELETE', '/v1/users/me'); await this.client.vault.clearTokens(); this.client.events.emit('tokens:cleared', undefined); }
  async getIdentities() { return this.client.transport.request('GET', '/v1/users/me/identities'); }
  async addIdentity(body: Record<string, unknown>) { return this.client.transport.request('POST', '/v1/users/me/identities', body, { idempotencyKey: crypto.randomUUID() }); }
}

class SessionClient {
  constructor(protected client: UicpClient) {}
  async listSessions() { return this.client.transport.request('GET', '/v1/users/me/sessions'); }
  async revokeSession(sessionId: string) { return this.client.transport.request('DELETE', `/v1/users/me/sessions/${sessionId}`); }
}

class CoreClient {
  constructor(protected client: UicpClient) {}
  async getIdentityContext() { return this.client.transport.request('GET', '/v1/core/me'); }
  async listMemberships() { return this.client.transport.request('GET', '/v1/core/memberships'); }
  async listActors() { return this.client.transport.request('GET', '/v1/core/actors'); }
  async getCurrentSession() { return this.client.transport.request('GET', '/v1/core/session'); }
  async getAuthMethods() { return this.client.transport.request('GET', '/v1/core/auth-methods'); }
}

class AdminClient {
  constructor(protected client: UicpClient) {}
  async listRoles() { return this.client.transport.request('GET', '/v1/admin/iam/roles'); }
  async createRole(body: Record<string, unknown>) { return this.client.transport.request('POST', '/v1/admin/iam/roles', body); }
  async deleteRole(roleId: string) { return this.client.transport.request('DELETE', `/v1/admin/iam/roles/${roleId}`); }
  async listPermissions() { return this.client.transport.request('GET', '/v1/admin/iam/permissions'); }
  async getUserRoles(userId: string) { return this.client.transport.request('GET', `/v1/admin/iam/users/${userId}/roles`); }
  async assignUserRole(userId: string, body: Record<string, unknown>) { return this.client.transport.request('POST', `/v1/admin/iam/users/${userId}/roles`, body); }
}

class PlatformClient {
  constructor(protected client: UicpClient) {}
  async getManifests() { return this.client.transport.request('GET', '/v1/platform/manifests'); }
  async getOpenApiSpec() { return this.client.transport.request('GET', '/v1/platform/openapi'); }
  async getSdkDescriptor() { return this.client.transport.request('GET', '/v1/platform/sdk-descriptor'); }
}

class DynamicModuleClient {
  constructor(protected client: UicpClient) {}
  async getResource(moduleKey: string, resourceKey: string) { return this.client.transport.request('GET', `/v1/modules/${moduleKey}/resources/${resourceKey}`); }
  async executeCommand(moduleKey: string, commandKey: string, body: Record<string, unknown>) { return this.client.transport.request('POST', `/v1/modules/${moduleKey}/commands/${commandKey}`, body); }
}

class ExtensionClient {
  constructor(protected client: UicpClient) {}
  async executeCommand(extensionKey: string, commandKey: string, body: Record<string, unknown>) { return this.client.transport.request('POST', `/v1/extensions/${extensionKey}/commands/${commandKey}`, body); }
  async getBindings(extensionKey: string) { return this.client.transport.request('GET', `/v1/extensions/${extensionKey}/bindings`); }
}

// ═════════════════════════════════════════════════════════════════════════════
// FACTORY
// ═════════════════════════════════════════════════════════════════════════════

export function createUicpClient(config: UicpClientConfig): UicpClient {
  return new UicpClient(config);
}

export class UicpClientBuilder {
  private _config: Partial<UicpClientConfig> = {};

  baseUrl(url: string): this { this._config.baseUrl = url; return this; }
  tenantId(id: string): this { this._config.tenantId = id as any; return this; }
  storage(adapter: IStorageAdapter): this { this._config.storage = adapter; return this; }
  onSessionExpired(callback: () => void): this { this._config.onSessionExpired = callback; return this; }
  debug(enabled = true): this { this._config.debug = enabled; return this; }
  build(): UicpClient { return new UicpClient(this._config as UicpClientConfig); }
}