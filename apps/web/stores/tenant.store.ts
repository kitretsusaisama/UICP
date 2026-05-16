/**
 * Tenant Store — Multi-tenant context management
 */

import { create } from 'zustand';
import type { Tenant } from '@/types';

interface TenantState {
  tenants: Tenant[];
  activeTenantId: string | null;
  loading: boolean;

  setTenants: (tenants: Tenant[]) => void;
  setActiveTenant: (tenantId: string) => void;
  setLoading: (loading: boolean) => void;
}

export const useTenantStore = create<TenantState>()((set) => ({
  tenants: [],
  activeTenantId: null,
  loading: false,

  setTenants: (tenants) => set({ tenants }),
  setActiveTenant: (activeTenantId) => set({ activeTenantId }),
  setLoading: (loading) => set({ loading }),
}));