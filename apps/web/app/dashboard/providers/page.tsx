'use client';

import { useState } from 'react';
import { Database, ArrowUpRight, ArrowDownRight, CheckCircle2, AlertTriangle, XCircle, RefreshCw, Settings } from 'lucide-react';

interface Provider {
  id: string;
  name: string;
  type: 'SMS' | 'EMAIL' | 'WHATSAPP' | 'VOICE';
  status: 'healthy' | 'degraded' | 'unavailable';
  successRate: number;
  avgLatencyMs: number;
  priority: number;
  fallbackChain: string[];
  failures24h: number;
  lastHealthCheck: string;
}

const MOCK_PROVIDERS: Provider[] = [
  { id: 'prov_twilio', name: 'Twilio SMS', type: 'SMS', status: 'healthy', successRate: 99.2, avgLatencyMs: 120, priority: 1, fallbackChain: ['prov_twilio_2', 'prov_vonage'], failures24h: 3, lastHealthCheck: '2024-05-12T10:00:00Z' },
  { id: 'prov_sendgrid', name: 'SendGrid Email', type: 'EMAIL', status: 'healthy', successRate: 99.8, avgLatencyMs: 180, priority: 1, fallbackChain: ['prov_aws_ses'], failures24h: 1, lastHealthCheck: '2024-05-12T10:00:00Z' },
  { id: 'prov_firebase', name: 'Firebase OTP', type: 'SMS', status: 'degraded', successRate: 94.5, avgLatencyMs: 450, priority: 2, fallbackChain: [], failures24h: 12, lastHealthCheck: '2024-05-12T10:00:00Z' },
  { id: 'prov_whatsapp', name: 'WhatsApp Cloud', type: 'WHATSAPP', status: 'healthy', successRate: 98.9, avgLatencyMs: 220, priority: 1, fallbackChain: ['prov_twilio_wa'], failures24h: 5, lastHealthCheck: '2024-05-12T10:00:00Z' },
  { id: 'prov_aws_ses', name: 'AWS SES', type: 'EMAIL', status: 'healthy', successRate: 99.5, avgLatencyMs: 200, priority: 2, fallbackChain: [], failures24h: 2, lastHealthCheck: '2024-05-12T10:00:00Z' },
  { id: 'prov_twilio_voice', name: 'Twilio Voice', type: 'VOICE', status: 'unavailable', successRate: 87.3, avgLatencyMs: 800, priority: 1, fallbackChain: ['prov_vonage_voice'], failures24h: 28, lastHealthCheck: '2024-05-12T09:58:00Z' },
];

const STATUS_CONFIG = {
  healthy: { icon: CheckCircle2, color: 'text-green-600', bg: 'bg-green-100', label: 'Healthy' },
  degraded: { icon: AlertTriangle, color: 'text-yellow-600', bg: 'bg-yellow-100', label: 'Degraded' },
  unavailable: { icon: XCircle, color: 'text-red-600', bg: 'bg-red-100', label: 'Unavailable' },
};

function ProviderCard({ provider }: { provider: Provider }) {
  const config = STATUS_CONFIG[provider.status];
  const Icon = config.icon;

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 ${config.bg} rounded-lg flex items-center justify-center ${config.color}`}>
            <Database size={20} />
          </div>
          <div>
            <h3 className="font-semibold text-ink">{provider.name}</h3>
            <div className="flex items-center gap-2 mt-0.5">
              <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${config.bg} ${config.color}`}>
                <Icon size={10} />
                {config.label}
              </span>
              <span className="text-xs text-muted">{provider.type}</span>
            </div>
          </div>
        </div>
        <button className="p-1.5 text-muted hover:text-ink rounded-lg hover:bg-gray-50">
          <Settings size={14} />
        </button>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-3 gap-4 mb-4">
        <div>
          <p className="text-xs text-muted">Success rate</p>
          <div className="flex items-center gap-1 mt-1">
            {provider.successRate >= 99 ? (
              <ArrowUpRight size={12} className="text-green-600" />
            ) : provider.successRate >= 95 ? (
              <ArrowUpRight size={12} className="text-yellow-600" />
            ) : (
              <ArrowDownRight size={12} className="text-red-600" />
            )}
            <span className="font-semibold text-ink">{provider.successRate.toFixed(1)}%</span>
          </div>
        </div>
        <div>
          <p className="text-xs text-muted">Avg latency</p>
          <p className="font-semibold text-ink mt-1">{provider.avgLatencyMs}ms</p>
        </div>
        <div>
          <p className="text-xs text-muted">Failures 24h</p>
          <p className={`font-semibold mt-1 ${provider.failures24h > 10 ? 'text-red-600' : 'text-ink'}`}>{provider.failures24h}</p>
        </div>
      </div>

      {/* Fallback chain */}
      {provider.fallbackChain.length > 0 && (
        <div className="flex items-center gap-2 text-xs text-muted">
          <span>Fallback:</span>
          {provider.fallbackChain.map((id, i) => (
            <span key={id}>
              <span className="font-mono bg-gray-100 px-1 rounded">{id.split('_').pop()}</span>
              {i < provider.fallbackChain.length - 1 && <span className="mx-1">→</span>}
            </span>
          ))}
        </div>
      )}

      <div className="mt-3 pt-3 border-t border-gray-100 text-xs text-muted">
        Last check: {new Date(provider.lastHealthCheck).toLocaleTimeString()}
      </div>
    </div>
  );
}

export default function ProvidersPage() {
  const [providers] = useState(MOCK_PROVIDERS);
  const [typeFilter, setTypeFilter] = useState<string>('all');

  const filtered = typeFilter === 'all' ? providers : providers.filter((p) => p.type === typeFilter);
  const healthy = providers.filter((p) => p.status === 'healthy').length;
  const degraded = providers.filter((p) => p.status === 'degraded').length;
  const unavailable = providers.filter((p) => p.status === 'unavailable').length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Providers</h1>
          <p className="text-muted text-sm mt-1">SMS, Email, WhatsApp, and Voice provider health</p>
        </div>
        <button className="flex items-center gap-2 px-3 py-2 border border-gray-200 rounded-lg text-sm hover:bg-gray-50">
          <RefreshCw size={14} />
          Refresh health
        </button>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <p className="text-sm text-muted">Total providers</p>
          <p className="text-2xl font-semibold text-ink mt-1">{providers.length}</p>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <p className="text-sm text-muted">Healthy</p>
          <p className="text-2xl font-semibold text-green-600 mt-1">{healthy}</p>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <p className="text-sm text-muted">Degraded</p>
          <p className="text-2xl font-semibold text-yellow-600 mt-1">{degraded}</p>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <p className="text-sm text-muted">Unavailable</p>
          <p className="text-2xl font-semibold text-red-600 mt-1">{unavailable}</p>
        </div>
      </div>

      {/* Filter */}
      <div className="flex gap-2">
        {['all', 'SMS', 'EMAIL', 'WHATSAPP', 'VOICE'].map((t) => (
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

      {/* Provider grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {filtered.map((p) => (
          <ProviderCard key={p.id} provider={p} />
        ))}
      </div>
    </div>
  );
}