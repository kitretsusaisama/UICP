/**
 * Auth Store — Zustand state management for auth flow
 * Handles login state, tenant context, actor switching
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { UserProfile, TenantContext, LoginResponse } from '@/types';

interface AuthState {
  // Token state
  accessToken: string | null;
  refreshToken: string | null;

  // User state
  user: UserProfile | null;
  tenantContext: TenantContext | null;

  // Flow state
  pendingVerification: {
    userId: string;
    purpose: string;
    channel: string;
  } | null;

  // Actions
  setTokens: (accessToken: string, refreshToken?: string) => void;
  setUser: (user: UserProfile | null) => void;
  setTenantContext: (context: TenantContext | null) => void;
  setPendingVerification: (pending: AuthState['pendingVerification']) => void;
  logout: () => void;
  switchActor: (actorId: string, accessToken: string) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      accessToken: null,
      refreshToken: null,
      user: null,
      tenantContext: null,
      pendingVerification: null,

      setTokens: (accessToken, refreshToken) =>
        set({ accessToken, refreshToken: refreshToken ?? null }),

      setUser: (user) => set({ user }),

      setTenantContext: (context) => set({ tenantContext: context }),

      setPendingVerification: (pending) => set({ pendingVerification: pending }),

      logout: () =>
        set({
          accessToken: null,
          refreshToken: null,
          user: null,
          tenantContext: null,
          pendingVerification: null,
        }),

      switchActor: (actorId, accessToken) =>
        set((state) => ({
          accessToken,
          user: state.user ? { ...state.user } : null,
        })),
    }),
    {
      name: 'uicp-auth',
      partialize: (state) => ({
        tenantContext: state.tenantContext,
      }),
    }
  )
);

/**
 * Derive auth headers from store state
 */
export function getAuthHeaders(): Record<string, string> {
  const state = useAuthStore.getState();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (state.tenantContext) {
    headers['X-Tenant-ID'] = state.tenantContext.tenantId;
  }
  if (state.accessToken) {
    headers['Authorization'] = `Bearer ${state.accessToken}`;
  }
  return headers;
}
