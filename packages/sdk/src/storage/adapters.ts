/**
 * @uicp/sdk - Storage Adapters
 *
 * Multiple storage implementations for different environments
 */

import type { IStorageAdapter } from '../types';

export const StorageKeys = {
  ACCESS_TOKEN: 'uicp.access_token',
  REFRESH_TOKEN: 'uicp.refresh_token',
  SESSION_ID: 'uicp.session_id',
  EXPIRES_AT: 'uicp.expires_at',
} as const;

export class MemoryStorageAdapter implements IStorageAdapter {
  private store = new Map<string, string>();

  get(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  set(key: string, value: string): void {
    this.store.set(key, value);
  }

  delete(key: string): void {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }
}

export class LocalStorageAdapter implements IStorageAdapter {
  private prefix: string;

  constructor(prefix = 'uicp.') {
    if (typeof window === 'undefined' || !window.localStorage) {
      throw new Error('LocalStorageAdapter requires browser environment');
    }
    this.prefix = prefix;
  }

  private getKey(key: string): string {
    return `${this.prefix}${key}`;
  }

  get(key: string): string | null {
    try {
      return window.localStorage.getItem(this.getKey(key));
    } catch {
      return null;
    }
  }

  set(key: string, value: string): void {
    try {
      window.localStorage.setItem(this.getKey(key), value);
    } catch {
      // Ignore quota errors
    }
  }

  delete(key: string): void {
    try {
      window.localStorage.removeItem(this.getKey(key));
    } catch {
      // Ignore
    }
  }

  clear(): void {
    try {
      const keys = Object.keys(window.localStorage).filter((k) => k.startsWith(this.prefix));
      keys.forEach((k) => window.localStorage.removeItem(k));
    } catch {
      // Ignore
    }
  }
}

export class SessionStorageAdapter implements IStorageAdapter {
  private prefix: string;

  constructor(prefix = 'uicp.') {
    if (typeof window === 'undefined' || !window.sessionStorage) {
      throw new Error('SessionStorageAdapter requires browser environment');
    }
    this.prefix = prefix;
  }

  private getKey(key: string): string {
    return `${this.prefix}${key}`;
  }

  get(key: string): string | null {
    try {
      return window.sessionStorage.getItem(this.getKey(key));
    } catch {
      return null;
    }
  }

  set(key: string, value: string): void {
    try {
      window.sessionStorage.setItem(this.getKey(key), value);
    } catch {
      // Ignore
    }
  }

  delete(key: string): void {
    try {
      window.sessionStorage.removeItem(this.getKey(key));
    } catch {
      // Ignore
    }
  }

  clear(): void {
    try {
      const keys = Object.keys(window.sessionStorage).filter((k) => k.startsWith(this.prefix));
      keys.forEach((k) => window.sessionStorage.removeItem(k));
    } catch {
      // Ignore
    }
  }
}

export interface CookieOptions {
  path?: string;
  domain?: string;
  secure?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  maxAge?: number;
}

export class CookieStorageAdapter implements IStorageAdapter {
  private prefix: string;
  private getCookie: (name: string) => string | null;
  private setCookie: (name: string, value: string, options?: CookieOptions) => void;
  private deleteCookie: (name: string) => void;

  constructor(options: {
    prefix?: string;
    getCookie: (name: string) => string | null;
    setCookie: (name: string, value: string, options?: CookieOptions) => void;
    deleteCookie: (name: string) => void;
  }) {
    this.prefix = options.prefix ?? 'uicp_';
    this.getCookie = options.getCookie;
    this.setCookie = options.setCookie;
    this.deleteCookie = options.deleteCookie;
  }

  private getKey(key: string): string {
    return `${this.prefix}${key}`;
  }

  get(key: string): string | null {
    return this.getCookie(this.getKey(key));
  }

  set(key: string, value: string): void {
    this.setCookie(this.getKey(key), value, { path: '/', secure: true, sameSite: 'lax' });
  }

  delete(key: string): void {
    this.deleteCookie(this.getKey(key));
  }

  clear(): void {
    // Handled by external
  }
}

export function createStorage(): IStorageAdapter {
  if (typeof window !== 'undefined' && window.localStorage) {
    return new LocalStorageAdapter();
  }
  return new MemoryStorageAdapter();
}