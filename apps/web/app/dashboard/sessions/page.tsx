'use client';

import { useState } from 'react';
import { Search, Monitor, AlertTriangle, Shield, CheckCircle2, XCircle, RefreshCw, ChevronLeft, ChevronRight } from 'lucide-react';

interface Session {
  id: string;
  userId: string;
  userName: string;
  userEmail: string;
  status: 'active' | 'revoked' | 'expired' | 'invalidated';
  createdAt: string;
  expiresAt: string;
  ipHash: string;
  deviceType: string;
  browser: string;
  os: string;
  threatScore: number;
  isCurrent: boolean;
}

const MOCK_SESSIONS: Session[] = [
  { id: 'sess_abc123', userId: 'u1', userName: 'Alice Johnson', userEmail: 'alice@acme.com', status: 'active', createdAt: '2024-05-10T10:30:00Z', expiresAt: '2024-05-11T10:30:00Z', ipHash: '192.168.1.100', deviceType: 'desktop', browser: 'Chrome 124', os: 'Windows 11', threatScore: 5, isCurrent: true },
  { id: 'sess_def456', userId: 'u1', userName: 'Alice Johnson', userEmail: 'alice@acme.com', status: 'active', createdAt: '2024-05-09T08:15:00Z', expiresAt: '2024-05-10T08:15:00Z', ipHash: '10.0.0.55', deviceType: 'mobile', browser: 'Safari iOS', os: 'iOS 17', threatScore: 12, isCurrent: false },
  { id: 'sess_ghi789', userId: 'u2', userName: 'Bob Smith', userEmail: 'bob@acme.com', status: 'revoked', createdAt: '2024-05-08T14:22:00Z', expiresAt: '2024-05-09T14:22:00Z', ipHash: '172.16.0.88', deviceType: 'desktop', browser: 'Firefox 125', os: 'macOS 14', threatScore: 78, isCurrent: false },
  { id: 'sess_jkl012', userId: 'u3', userName: 'Carol White', userEmail: 'carol@corp.io', status: 'active', createdAt: '2024-05-11T06:45:00Z', expiresAt: '2024-05-12T06:45:00Z', ipHash: '203.0.113.42', deviceType: 'tablet', browser: 'Chrome 124', os: 'Android 14', threatScore: 0, isCurrent: false },
  { id: 'sess_mno345', userId: 'u4', userName: 'David Brown', userEmail: 'david@startup.dev', status: 'expired', createdAt: '2024-05-07T16:00:00Z', expiresAt: '2024-05-08T16:00:00Z', ipHash: '198.51.100.17', deviceType: 'desktop', browser: 'Edge 124', os: 'Windows 10', threatScore: 3, isCurrent: false },
];

function ThreatScoreBadge({ score }: { score: number }) {
  if (score === 0) {
    return <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-green-100 text-green-700 rounded-full text-xs font-medium"><CheckCircle2 size={10} /> Clean</span>;
  }
  if (score < 30) {
    return <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-yellow-100 text-yellow-700 rounded-full text-xs font-medium"><Shield size={10} /> {score}</span>;
  }
  return <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-red-100 text-red-700 rounded-full text-xs font-medium"><AlertTriangle size={10} /> {score}</span>;
}

const STATUS_STYLES = {
  active: { badge: 'bg-green-100 text-green-700', label: 'Active' },
  revoked: { badge: 'bg-red-100 text-red-700', label: 'Revoked' },
  expired: { badge: 'bg-gray-100 text-gray-600', label: 'Expired' },
  invalidated: { badge: 'bg-red-100 text-red-700', label: 'Invalidated' },
};

export default function SessionsPage() {
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [sessions] = useState(MOCK_SESSIONS);
  const pageSize = 10;

  const filtered = sessions.filter((s) =>
    !search || s.userName.toLowerCase().includes(search.toLowerCase()) || s.userEmail.toLowerCase().includes(search.toLowerCase()) || s.id.includes(search)
  );

  const paginated = filtered.slice((page - 1) * pageSize, page * pageSize);
  const totalPages = Math.ceil(filtered.length / pageSize);

  const handleRevoke = (sessionId: string) => {
    console.log('Revoke session:', sessionId);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Sessions</h1>
          <p className="text-muted text-sm mt-1">{filtered.length} sessions tracked</p>
        </div>
        <div className="flex items-center gap-2">
          <button className="flex items-center gap-2 px-3 py-2 border border-gray-200 rounded-lg text-sm hover:bg-gray-50">
            <RefreshCw size={14} />
            Refresh
          </button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        {[
          { label: 'Total active', value: sessions.filter((s) => s.status === 'active').length, color: 'text-green-600' },
          { label: 'Revoked', value: sessions.filter((s) => s.status === 'revoked').length, color: 'text-red-600' },
          { label: 'High threat', value: sessions.filter((s) => s.threatScore >= 50).length, color: 'text-red-600' },
          { label: 'Current device', value: sessions.filter((s) => s.isCurrent).length, color: 'text-accent' },
        ].map((stat) => (
          <div key={stat.label} className="bg-white rounded-xl border border-gray-200 p-4">
            <p className="text-sm text-muted">{stat.label}</p>
            <p className={`text-2xl font-semibold mt-1 ${stat.color}`}>{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Search */}
      <div className="relative max-w-md">
        <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
        <input
          type="text"
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(1); }}
          placeholder="Search by user or session ID..."
          className="w-full pl-9 pr-4 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
        />
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 bg-gray-50">
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">User</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Session ID</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Status</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Device</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Threat</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">IP</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Expires</th>
              <th className="w-20"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {paginated.map((session) => {
              const status = STATUS_STYLES[session.status];
              return (
                <tr key={session.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-ink text-sm">{session.userName}</span>
                      {session.isCurrent && (
                        <span className="px-1.5 py-0.5 bg-accent/10 text-accent rounded text-xs">current</span>
                      )}
                    </div>
                    <p className="text-xs text-muted mt-0.5">{session.userEmail}</p>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-muted">{session.id}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex px-2 py-0.5 rounded-full text-xs font-medium ${status.badge}`}>{status.label}</span>
                  </td>
                  <td className="px-4 py-3 text-sm text-muted">
                    {session.browser} / {session.os}
                  </td>
                  <td className="px-4 py-3">
                    <ThreatScoreBadge score={session.threatScore} />
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-muted">{session.ipHash}</td>
                  <td className="px-4 py-3 text-xs text-muted">
                    {new Date(session.expiresAt).toLocaleString()}
                  </td>
                  <td className="px-4 py-3">
                    {session.status === 'active' && (
                      <button
                        onClick={() => handleRevoke(session.id)}
                        className="px-2 py-1 text-xs text-red-600 border border-red-200 rounded hover:bg-red-50"
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
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