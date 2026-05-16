'use client';

import { useState } from 'react';
import { Building2, Plus, Settings, MoreHorizontal, CheckCircle2, AlertTriangle, Clock, X } from 'lucide-react';

interface Tenant {
  id: string;
  name: string;
  type: 'DEDICATED' | 'ISOLATED' | 'SHARED';
  status: 'active' | 'suspended' | 'pending';
  isolationTier: string;
  plan: string;
  createdAt: string;
  userCount: number;
  monthlyRequests: number;
}

const MOCK_TENANTS: Tenant[] = [
  { id: 'alpha-corp', name: 'Acme Corporation', type: 'DEDICATED', status: 'active', isolationTier: 'strict', plan: 'enterprise', createdAt: '2023-01-15', userCount: 342, monthlyRequests: 1250000 },
  { id: 'startup-inc', name: 'Startup Inc', type: 'SHARED', status: 'active', isolationTier: 'standard', plan: 'pro', createdAt: '2023-06-20', userCount: 48, monthlyRequests: 85000 },
  { id: 'corp-global', name: 'Corp Global', type: 'ISOLATED', status: 'active', isolationTier: 'strict', plan: 'enterprise', createdAt: '2022-11-08', userCount: 890, monthlyRequests: 3400000 },
  { id: 'devshop', name: 'DevShop', type: 'SHARED', status: 'pending', isolationTier: 'standard', plan: 'starter', createdAt: '2024-05-01', userCount: 5, monthlyRequests: 2000 },
  { id: 'enterprise-one', name: 'Enterprise One', type: 'DEDICATED', status: 'suspended', isolationTier: 'strict', plan: 'enterprise', createdAt: '2022-03-10', userCount: 1200, monthlyRequests: 0 },
];

const TYPE_CONFIG = {
  DEDICATED: { bg: 'bg-purple-100', text: 'text-purple-700', label: 'Dedicated' },
  ISOLATED: { bg: 'bg-blue-100', text: 'text-blue-700', label: 'Isolated' },
  SHARED: { bg: 'bg-gray-100', text: 'text-gray-700', label: 'Shared' },
};

const STATUS_CONFIG = {
  active: { icon: CheckCircle2, bg: 'bg-green-100', text: 'text-green-700', label: 'Active' },
  suspended: { icon: AlertTriangle, bg: 'bg-red-100', text: 'text-red-700', label: 'Suspended' },
  pending: { icon: Clock, bg: 'bg-yellow-100', text: 'text-yellow-700', label: 'Pending' },
};

const PLAN_COLORS: Record<string, string> = {
  enterprise: 'bg-purple-100 text-purple-700',
  pro: 'bg-blue-100 text-blue-700',
  starter: 'bg-gray-100 text-gray-700',
};

function TenantCard({ tenant }: { tenant: Tenant }) {
  const typeConfig = TYPE_CONFIG[tenant.type];
  const statusConfig = STATUS_CONFIG[tenant.status];
  const StatusIcon = statusConfig.icon;

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5 hover:shadow-md transition-shadow">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-accent/10 rounded-lg flex items-center justify-center">
            <Building2 size={20} className="text-accent" />
          </div>
          <div>
            <h3 className="font-semibold text-ink">{tenant.name}</h3>
            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium mt-0.5 ${typeConfig.bg} ${typeConfig.text}`}>
              {typeConfig.label}
            </span>
          </div>
        </div>
        <button className="p-1 text-muted hover:text-ink rounded">
          <MoreHorizontal size={16} />
        </button>
      </div>

      {/* Status */}
      <div className="flex items-center gap-2 mb-4">
        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${statusConfig.bg} ${statusConfig.text}`}>
          <StatusIcon size={10} />
          {statusConfig.label}
        </span>
        <span className={`px-2 py-0.5 rounded-full text-xs font-medium capitalize ${PLAN_COLORS[tenant.plan]}`}>
          {tenant.plan}
        </span>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-2 gap-3 mb-4">
        <div className="bg-gray-50 rounded-lg p-3">
          <p className="text-xs text-muted">Users</p>
          <p className="text-lg font-semibold text-ink">{tenant.userCount.toLocaleString()}</p>
        </div>
        <div className="bg-gray-50 rounded-lg p-3">
          <p className="text-xs text-muted">Monthly requests</p>
          <p className="text-lg font-semibold text-ink">
            {tenant.monthlyRequests > 0 ? `${(tenant.monthlyRequests / 1000000).toFixed(1)}M` : '0'}
          </p>
        </div>
      </div>

      {/* Footer */}
      <div className="pt-3 border-t border-gray-100 flex items-center justify-between text-xs text-muted">
        <span>Tier: {tenant.isolationTier}</span>
        <span>Created {new Date(tenant.createdAt).toLocaleDateString()}</span>
      </div>
    </div>
  );
}

export default function TenantsPage() {
  const [tenants] = useState(MOCK_TENANTS);
  const [typeFilter, setTypeFilter] = useState('all');

  const filtered = typeFilter === 'all' ? tenants : tenants.filter((t) => t.type === typeFilter);

  const active = tenants.filter((t) => t.status === 'active').length;
  const totalUsers = tenants.reduce((acc, t) => acc + t.userCount, 0);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Tenants</h1>
          <p className="text-muted text-sm mt-1">Multi-tenant management and isolation monitoring</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-accent text-white rounded-lg text-sm font-medium hover:bg-accent/90">
          <Plus size={16} />
          Create tenant
        </button>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <p className="text-sm text-muted">Total tenants</p>
          <p className="text-2xl font-semibold text-ink mt-1">{tenants.length}</p>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <p className="text-sm text-muted">Active</p>
          <p className="text-2xl font-semibold text-green-600 mt-1">{active}</p>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <p className="text-sm text-muted">Total users</p>
          <p className="text-2xl font-semibold text-ink mt-1">{totalUsers.toLocaleString()}</p>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <p className="text-sm text-muted">Dedicated tenants</p>
          <p className="text-2xl font-semibold text-purple-600 mt-1">{tenants.filter((t) => t.type === 'DEDICATED').length}</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-1">
        {['all', 'DEDICATED', 'ISOLATED', 'SHARED'].map((t) => (
          <button
            key={t}
            onClick={() => setTypeFilter(t)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium ${
              typeFilter === t ? 'bg-accent text-white' : 'border border-gray-200 text-muted hover:bg-gray-50'
            }`}
          >
            {t === 'all' ? 'All' : t}
          </button>
        ))}
      </div>

      {/* Tenant grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {filtered.map((tenant) => (
          <TenantCard key={tenant.id} tenant={tenant} />
        ))}
      </div>
    </div>
  );
}
