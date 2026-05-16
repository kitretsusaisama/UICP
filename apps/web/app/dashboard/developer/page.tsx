'use client';

import { useState } from 'react';
import { Code2, Key, Webhook, Plus, Trash2, Copy, CheckCircle2, Clock, RefreshCw, MoreHorizontal } from 'lucide-react';
import { API_CONFIG } from '@/lib/api-client';

interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  createdAt: string;
  lastUsed: string;
  scopes: string[];
}

interface WebhookEndpoint {
  id: string;
  url: string;
  events: string[];
  status: 'active' | 'inactive';
  createdAt: string;
  lastTriggered?: string;
  successRate: number;
}

const MOCK_KEYS: ApiKey[] = [
  { id: 'key_001', name: 'Production API', prefix: 'uicp_live_', createdAt: '2024-01-15', lastUsed: '2024-05-12T09:00:00Z', scopes: ['auth:read', 'auth:write', 'users:read'] },
  { id: 'key_002', name: 'Development', prefix: 'uicp_test_', createdAt: '2024-03-20', lastUsed: '2024-05-11T18:30:00Z', scopes: ['auth:read', 'auth:write'] },
  { id: 'key_003', name: 'Analytics Read', prefix: 'uicp_ana_', createdAt: '2024-04-10', lastUsed: '2024-05-10T12:00:00Z', scopes: ['analytics:read'] },
];

const MOCK_WEBHOOKS: WebhookEndpoint[] = [
  { id: 'wh_001', url: 'https://api.acme.com/webhooks/uicp', events: ['auth.login', 'auth.logout'], status: 'active', createdAt: '2024-02-01', lastTriggered: '2024-05-12T10:30:00Z', successRate: 99.2 },
  { id: 'wh_002', url: 'https://hooks.company.io/auth', events: ['security.threat_detected'], status: 'active', createdAt: '2024-03-15', lastTriggered: '2024-05-12T08:00:00Z', successRate: 97.8 },
  { id: 'wh_003', url: 'https://dev.example.com/webhook', events: ['auth.signup', 'auth.otp_sent'], status: 'inactive', createdAt: '2024-04-20', successRate: 0 },
];

export default function DeveloperPage() {
  const [activeSection, setActiveSection] = useState<'keys' | 'webhooks' | 'docs'>('keys');

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-ink">Developer</h1>
        <p className="text-muted text-sm mt-1">API keys, webhook endpoints, and integration documentation</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1">
        {[
          { id: 'keys', label: 'API Keys', icon: Key },
          { id: 'webhooks', label: 'Webhooks', icon: Webhook },
          { id: 'docs', label: 'Documentation', icon: Code2 },
        ].map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveSection(tab.id as typeof activeSection)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                activeSection === tab.id ? 'bg-accent text-white' : 'border border-gray-200 text-muted hover:bg-gray-50'
              }`}
            >
              <Icon size={14} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {activeSection === 'keys' && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button className="flex items-center gap-2 px-4 py-2 bg-accent text-white rounded-lg text-sm font-medium hover:bg-accent/90">
              <Plus size={14} />
              Create API key
            </button>
          </div>

          <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200 bg-gray-50">
                  <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase">Name</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase">Key</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase">Scopes</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase">Last used</th>
                  <th className="w-20"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {MOCK_KEYS.map((key) => (
                  <tr key={key.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3">
                      <p className="font-medium text-ink text-sm">{key.name}</p>
                      <p className="text-xs text-muted mt-0.5">{key.id}</p>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <code className="text-xs font-mono bg-gray-100 px-2 py-1 rounded">{key.prefix}****</code>
                        <button className="p-1 text-muted hover:text-ink rounded">
                          <Copy size={12} />
                        </button>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {key.scopes.map((s) => (
                          <span key={s} className="px-1.5 py-0.5 bg-gray-100 text-muted rounded text-xs">{s}</span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted">
                      {new Date(key.lastUsed).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3">
                      <button className="p-1 text-red-600 hover:bg-red-50 rounded">
                        <Trash2 size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeSection === 'webhooks' && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button className="flex items-center gap-2 px-4 py-2 bg-accent text-white rounded-lg text-sm font-medium hover:bg-accent/90">
              <Plus size={14} />
              Add endpoint
            </button>
          </div>

          <div className="space-y-4">
            {MOCK_WEBHOOKS.map((wh) => (
              <div key={wh.id} className="bg-white rounded-xl border border-gray-200 p-5">
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="font-medium text-ink text-sm">{wh.url}</h3>
                      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${wh.status === 'active' ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600'}`}>
                        {wh.status}
                      </span>
                    </div>
                    <p className="text-xs text-muted mt-1">{wh.id}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    {wh.successRate && (
                      <span className={`text-xs font-medium ${wh.successRate >= 98 ? 'text-green-600' : 'text-yellow-600'}`}>
                        {wh.successRate}% success
                      </span>
                    )}
                    <button className="p-1 text-muted hover:text-ink rounded"><MoreHorizontal size={14} /></button>
                  </div>
                </div>
                <div className="flex flex-wrap gap-1 mb-3">
                  {wh.events.map((e) => (
                    <span key={e} className="px-2 py-0.5 bg-accent/10 text-accent rounded text-xs">{e}</span>
                  ))}
                </div>
                <div className="flex items-center gap-4 text-xs text-muted">
                  <span>Created {new Date(wh.createdAt).toLocaleDateString()}</span>
                  {wh.lastTriggered && <span>Last triggered {new Date(wh.lastTriggered).toLocaleTimeString()}</span>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeSection === 'docs' && (
        <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-6">
          <h2 className="font-semibold text-ink">API Documentation</h2>
          <div className="prose prose-sm max-w-none">
            <div className="space-y-4">
              <div className="bg-gray-50 rounded-lg p-4">
                <h3 className="font-semibold text-ink text-sm mb-2">Base URL</h3>
                <code className="text-sm font-mono">{API_CONFIG.baseUrl ? `${API_CONFIG.baseUrl}/v1` : '/v1'}</code>
              </div>
              <div className="bg-gray-50 rounded-lg p-4">
                <h3 className="font-semibold text-ink text-sm mb-2">Authentication</h3>
                <p className="text-sm text-muted mb-2">All requests require a Bearer token in the Authorization header:</p>
                <code className="text-xs font-mono bg-gray-100 px-3 py-2 rounded block">Authorization: Bearer &lt;access_token&gt;</code>
              </div>
              <div className="bg-gray-50 rounded-lg p-4">
                <h3 className="font-semibold text-ink text-sm mb-2">Tenant Scope</h3>
                <p className="text-sm text-muted mb-2">All requests require a tenant header:</p>
                <code className="text-xs font-mono bg-gray-100 px-3 py-2 rounded block">X-Tenant-Slug: &lt;tenant_slug&gt;</code>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {[
                  { method: 'POST', path: '/auth/login', desc: 'Authenticate user' },
                  { method: 'POST', path: '/auth/signup', desc: 'Create new account' },
                  { method: 'POST', path: '/auth/otp/send', desc: 'Send OTP code' },
                  { method: 'POST', path: '/auth/otp/verify', desc: 'Verify OTP code' },
                  { method: 'GET', path: '/users', desc: 'List users' },
                  { method: 'GET', path: '/sessions', desc: 'List active sessions' },
                  { method: 'GET', path: '/providers', desc: 'List providers' },
                  { method: 'GET', path: '/audit', desc: 'Query audit logs' },
                ].map((endpoint) => (
                  <div key={endpoint.path} className="flex items-center gap-2 p-3 bg-gray-50 rounded-lg">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${endpoint.method === 'GET' ? 'bg-blue-100 text-blue-700' : 'bg-green-100 text-green-700'}`}>
                      {endpoint.method}
                    </span>
                    <code className="text-xs font-mono text-ink">{endpoint.path}</code>
                    <span className="text-xs text-muted">{endpoint.desc}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
