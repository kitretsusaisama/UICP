'use client';

/**
 * Health Check Page — Public endpoint for backend health
 */

import { useEffect, useState } from 'react';
import { ShieldCheck, AlertCircle, RefreshCw } from 'lucide-react';
import { getApiUrl } from '@/lib/api-client';

interface HealthStatus {
  ok: boolean;
  surface?: string;
  uptime?: number;
  version?: string;
  dependencies?: Record<string, { ok: boolean; latencyMs?: number }>;
}

export default function HealthPage() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    checkHealth();
  }, []);

  async function checkHealth() {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch(getApiUrl('v1/admin/health'), { credentials: 'include' });
      const data = await resp.json();
      setHealth(data.data ?? { ok: true });
    } catch (err) {
      setError('Backend unreachable. Check the configured API endpoint.');
      setHealth({ ok: false });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="w-full max-w-md px-4">
        <div className="card p-6">
          <div className="mb-6 text-center">
            <ShieldCheck className={`mx-auto h-10 w-10 ${health?.ok ? 'text-accent' : 'text-destructive'}`} />
            <h1 className="mt-3 text-lg font-semibold">UICP Status</h1>
          </div>

          {loading && (
            <div className="flex items-center justify-center py-8">
              <div className="h-6 w-6 animate-spin rounded-full border-2 border-accent border-t-transparent" />
            </div>
          )}

          {!loading && error && (
            <div className="flex items-start gap-2 rounded border border-destructive/20 bg-destructive/5 p-4 text-sm text-destructive">
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {!loading && health && (
            <div className="space-y-3">
              <div className="flex items-center justify-between rounded border border-border p-3">
                <span className="text-sm font-medium">Status</span>
                <span className={`flex items-center gap-1.5 text-sm ${health.ok ? 'text-[#40c057]' : 'text-destructive'}`}>
                  <span className={`status-dot status-${health.ok ? 'active' : 'revoked'}`} />
                  {health.ok ? 'Healthy' : 'Unhealthy'}
                </span>
              </div>
              {health.surface && (
                <div className="flex items-center justify-between rounded border border-border p-3">
                  <span className="text-sm font-medium">Surface</span>
                  <code className="text-xs">{health.surface}</code>
                </div>
              )}
              {health.version && (
                <div className="flex items-center justify-between rounded border border-border p-3">
                  <span className="text-sm font-medium">Version</span>
                  <code className="text-xs">{health.version}</code>
                </div>
              )}
            </div>
          )}

          <button
            onClick={checkHealth}
            disabled={loading}
            className="mt-4 flex w-full items-center justify-center gap-2 rounded border border-border py-2 text-sm hover:bg-muted disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>
    </div>
  );
}
