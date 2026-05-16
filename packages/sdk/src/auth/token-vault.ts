/**
 * @uicp/sdk - Token Vault
 *
 * Manages token lifecycle: storage, refresh, expiry detection
 */

import type { IStorageAdapter, TokenSet } from '../types';
import { StorageKeys } from '../storage/adapters';

export class TokenVault {
  private storage: IStorageAdapter;
  private earlyRefreshBufferMs: number;

  constructor(storage: IStorageAdapter, earlyRefreshBufferMs = 30_000) {
    this.storage = storage;
    this.earlyRefreshBufferMs = earlyRefreshBufferMs;
  }

  async setTokens(tokens: TokenSet): Promise<void> {
    await this.storage.set(StorageKeys.ACCESS_TOKEN, tokens.accessToken);
    await this.storage.set(StorageKeys.REFRESH_TOKEN, tokens.refreshToken);
    await this.storage.set(StorageKeys.SESSION_ID, tokens.sessionId);
    const expiresAt = Date.now() + tokens.expiresIn * 1000 - this.earlyRefreshBufferMs;
    await this.storage.set(StorageKeys.EXPIRES_AT, String(expiresAt));
  }

  async getAccessToken(): Promise<string | null> {
    return this.storage.get(StorageKeys.ACCESS_TOKEN);
  }

  async getRefreshToken(): Promise<string | null> {
    return this.storage.get(StorageKeys.REFRESH_TOKEN);
  }

  async getSessionId(): Promise<string | null> {
    return this.storage.get(StorageKeys.SESSION_ID);
  }

  async isAccessTokenExpired(): Promise<boolean> {
    const expiresAtStr = await this.storage.get(StorageKeys.EXPIRES_AT);
    if (!expiresAtStr) return false;
    const expiresAt = parseInt(expiresAtStr, 10);
    return Date.now() >= expiresAt;
  }

  async shouldRefresh(): Promise<boolean> {
    const expiresAtStr = await this.storage.get(StorageKeys.EXPIRES_AT);
    if (!expiresAtStr) return false;
    const expiresAt = parseInt(expiresAtStr, 10);
    return Date.now() >= expiresAt - this.earlyRefreshBufferMs;
  }

  async clearTokens(): Promise<void> {
    await this.storage.delete(StorageKeys.ACCESS_TOKEN);
    await this.storage.delete(StorageKeys.REFRESH_TOKEN);
    await this.storage.delete(StorageKeys.SESSION_ID);
    await this.storage.delete(StorageKeys.EXPIRES_AT);
  }

  async hasTokens(): Promise<boolean> {
    const accessToken = await this.storage.get(StorageKeys.ACCESS_TOKEN);
    return accessToken !== null;
  }
}