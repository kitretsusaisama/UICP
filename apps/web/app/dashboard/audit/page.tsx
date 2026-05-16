'use client';

import { useState } from 'react';
import { FileText, Search, Filter, Download, ChevronLeft, ChevronRight, ChevronDown } from 'lucide-react';

interface AuditLog {
  id: string;
  eventType: string;
  tenantId: string;
  principalId: string;
  actorId?: string;
  sessionId?: string;
  timestamp: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
  correlationId?: string;
}

const MOCK_LOGS: AuditLog[] = [
  { id: 'log_001', eventType: 'auth.login', tenantId: 'alpha-corp', principalId: 'u1', actorId: 'u1', sessionId: 'sess_abc', timestamp: '2024-05-12T10:30:00Z', ipAddress: '192.168.1.100', userAgent: 'Chrome/124' },
  { id: 'log_002', eventType: 'auth.otp_sent', tenantId: 'alpha-corp', principalId: 'u1', sessionId: 'sess_abc', timestamp: '2024-05-12T10:30:05Z', ipAddress: '192.168.1.100' },
  { id: 'log_003', eventType: 'auth.otp_verified', tenantId: 'alpha-corp', principalId: 'u1', sessionId: 'sess_abc', timestamp: '2024-05-12T10:30:12Z', ipAddress: '192.168.1.100' },
  { id: 'log_004', eventType: 'session.revoked', tenantId: 'alpha-corp', principalId: 'u2', actorId: 'u_admin', sessionId: 'sess_def', timestamp: '2024-05-12T10:28:00Z', ipAddress: '10.0.0.50' },
  { id: 'log_005', eventType: 'provider.fallback', tenantId: 'alpha-corp', principalId: 'system', timestamp: '2024-05-12T10:27:30Z', ipAddress: '10.0.0.1' },
  { id: 'log_006', eventType: 'security.threat_detected', tenantId: 'alpha-corp', principalId: 'u_anon', timestamp: '2024-05-12T10:25:00Z', ipAddress: '203.0.113.50', correlationId: 'th_001' },
  { id: 'log_007', eventType: 'auth.signup', tenantId: 'alpha-corp', principalId: 'u_new', sessionId: 'sess_new', timestamp: '2024-05-12T10:20:00Z', ipAddress: '172.16.0.44' },
  { id: 'log_008', eventType: 'queue.job_failed', tenantId: 'alpha-corp', principalId: 'system', timestamp: '2024-05-12T10:18:00Z', ipAddress: '10.0.0.1' },
];

const EVENT_LABELS: Record<string, string> = {
  'auth.login': 'Login',
  'auth.logout': 'Logout',
  'auth.signup': 'Signup',
  'auth.otp_sent': 'OTP Sent',
  'auth.otp_verified': 'OTP Verified',
  'session.revoked': 'Session Revoked',
  'user.updated': 'User Updated',
  'provider.fallback': 'Provider Fallback',
  'queue.job_failed': 'Job Failed',
  'security.threat_detected': 'Threat Detected',
};

const EVENT_COLORS: Record<string, string> = {
  'auth.login': 'bg-blue-100 text-blue-700',
  'auth.logout': 'bg-gray-100 text-gray-700',
  'auth.signup': 'bg-green-100 text-green-700',
  'auth.otp_sent': 'bg-purple-100 text-purple-700',
  'auth.otp_verified': 'bg-purple-100 text-purple-700',
  'session.revoked': 'bg-red-100 text-red-700',
  'user.updated': 'bg-yellow-100 text-yellow-700',
  'provider.fallback': 'bg-orange-100 text-orange-700',
  'queue.job_failed': 'bg-red-100 text-red-700',
  'security.threat_detected': 'bg-red-100 text-red-700',
};

export default function AuditPage() {
  const [logs] = useState(MOCK_LOGS);
  const [search, setSearch] = useState('');
  const [eventFilter, setEventFilter] = useState('all');
  const [expandedLog, setExpandedLog] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const pageSize = 10;

  const eventTypes = [...new Set(logs.map((l) => l.eventType))];

  const filtered = logs.filter((log) => {
    const matchSearch = !search ||
      log.id.includes(search) ||
      log.principalId.includes(search) ||
      log.eventType.includes(search);
    const matchEvent = eventFilter === 'all' || log.eventType === eventFilter;
    return matchSearch && matchEvent;
  });

  const paginated = filtered.slice((page - 1) * pageSize, page * pageSize);
  const totalPages = Math.ceil(filtered.length / pageSize);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Audit Logs</h1>
          <p className="text-muted text-sm mt-1">Complete event history with filtering and export</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-accent text-white rounded-lg text-sm font-medium hover:bg-accent/90">
          <Download size={14} />
          Export
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="text"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            placeholder="Search by ID, principal, or event..."
            className="w-full pl-9 pr-4 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
          />
        </div>
        <select
          value={eventFilter}
          onChange={(e) => { setEventFilter(e.target.value); setPage(1); }}
          className="px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20"
        >
          <option value="all">All events</option>
          {eventTypes.map((t) => (
            <option key={t} value={t}>{EVENT_LABELS[t] || t}</option>
          ))}
        </select>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: 'Total events', value: logs.length },
          { label: 'Auth events', value: logs.filter((l) => l.eventType.startsWith('auth.')).length },
          { label: 'Security events', value: logs.filter((l) => l.eventType.startsWith('security.') || l.eventType.startsWith('session.')).length },
          { label: 'System events', value: logs.filter((l) => l.eventType.startsWith('provider.') || l.eventType.startsWith('queue.')).length },
        ].map((stat) => (
          <div key={stat.label} className="bg-white rounded-xl border border-gray-200 p-4">
            <p className="text-sm text-muted">{stat.label}</p>
            <p className="text-2xl font-semibold text-ink mt-1">{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Log list */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 bg-gray-50">
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Log ID</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Event</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Principal</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Tenant</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">IP</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Time</th>
              <th className="w-10"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {paginated.map((log) => (
              <>
                <tr key={log.id} className="hover:bg-gray-50 cursor-pointer" onClick={() => setExpandedLog(expandedLog === log.id ? null : log.id)}>
                  <td className="px-4 py-3 font-mono text-xs text-accent">{log.id}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex px-2 py-0.5 rounded-full text-xs font-medium ${EVENT_COLORS[log.eventType] || 'bg-gray-100 text-gray-700'}`}>
                      {EVENT_LABELS[log.eventType] || log.eventType}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-ink">{log.principalId}</td>
                  <td className="px-4 py-3 text-xs text-muted">{log.tenantId}</td>
                  <td className="px-4 py-3 font-mono text-xs text-muted">{log.ipAddress || '—'}</td>
                  <td className="px-4 py-3 text-xs text-muted">{new Date(log.timestamp).toLocaleString()}</td>
                  <td className="px-4 py-3">
                    <ChevronDown size={14} className={`text-muted transition-transform ${expandedLog === log.id ? 'rotate-180' : ''}`} />
                  </td>
                </tr>
                {expandedLog === log.id && (
                  <tr key={`${log.id}-detail`}>
                    <td colSpan={7} className="px-4 py-3 bg-gray-50">
                      <div className="grid grid-cols-2 gap-3 text-sm">
                        {log.sessionId && <div><p className="text-muted text-xs">Session</p><p className="font-mono text-ink">{log.sessionId}</p></div>}
                        {log.actorId && <div><p className="text-muted text-xs">Actor</p><p className="text-ink">{log.actorId}</p></div>}
                        {log.userAgent && <div><p className="text-muted text-xs">User Agent</p><p className="text-ink">{log.userAgent}</p></div>}
                        {log.correlationId && <div><p className="text-muted text-xs">Correlation</p><p className="font-mono text-ink">{log.correlationId}</p></div>}
                        {log.metadata && <div className="col-span-2"><p className="text-muted text-xs">Metadata</p><pre className="text-xs bg-white p-2 rounded border border-gray-200 overflow-x-auto">{JSON.stringify(log.metadata, null, 2)}</pre></div>}
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>

        {/* Pagination */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 bg-gray-50">
          <p className="text-sm text-muted">
            Showing {(page - 1) * pageSize + 1} to {Math.min(page * pageSize, filtered.length)} of {filtered.length}
          </p>
          <div className="flex items-center gap-1">
            <button onClick={() => setPage(Math.max(1, page - 1))} disabled={page === 1} className="p-1.5 rounded border border-gray-200 disabled:opacity-50"><ChevronLeft size={14} /></button>
            <span className="px-3 py-1 text-sm">{page} / {totalPages}</span>
            <button onClick={() => setPage(Math.min(totalPages, page + 1))} disabled={page === totalPages} className="p-1.5 rounded border border-gray-200 disabled:opacity-50"><ChevronRight size={14} /></button>
          </div>
        </div>
      </div>
    </div>
  );
}
