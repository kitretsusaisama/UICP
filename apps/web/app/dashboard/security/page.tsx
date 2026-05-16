'use client';

import { useState } from 'react';
import { Shield, AlertTriangle, Activity, CheckCircle2, Clock, Search, Filter, X } from 'lucide-react';

interface Threat {
  id: string;
  type: 'credential_stuffing' | 'brute_force' | 'replay_attack' | 'anomaly';
  severity: 'critical' | 'high' | 'medium' | 'low';
  timestamp: string;
  principalId: string;
  ipHash: string;
  score: number;
  indicators: string[];
  mitigated: boolean;
  userAgent: string;
}

const MOCK_THREATS: Threat[] = [
  { id: 'th_001', type: 'credential_stuffing', severity: 'critical', timestamp: '2024-05-12T09:45:00Z', principalId: 'u_anon_1234', ipHash: '203.0.113.50', score: 92, indicators: ['multiple_failed_logins', 'known_bot_ip', 'rapid_fire_attempts'], mitigated: true, userAgent: 'python-requests/3.0' },
  { id: 'th_002', type: 'brute_force', severity: 'high', timestamp: '2024-05-12T08:30:00Z', principalId: 'u_anon_5678', ipHash: '198.51.100.22', score: 78, indicators: ['rapid_otp_requests', 'sequential_guessing'], mitigated: true, userAgent: 'curl/7.68.0' },
  { id: 'th_003', type: 'anomaly', severity: 'medium', timestamp: '2024-05-12T07:15:00Z', principalId: 'u3', ipHash: '172.16.0.99', score: 55, indicators: ['unusual_time_zone', 'new_device'], mitigated: false, userAgent: 'Chrome/124' },
  { id: 'th_004', type: 'replay_attack', severity: 'high', timestamp: '2024-05-12T06:00:00Z', principalId: 'u_anon_9012', ipHash: '192.0.2.77', score: 71, indicators: ['reused_otp_code', 'token_replay'], mitigated: true, userAgent: 'Go-http-client/2.0' },
  { id: 'th_005', type: 'credential_stuffing', severity: 'low', timestamp: '2024-05-11T22:00:00Z', principalId: 'u2', ipHash: '10.0.0.44', score: 28, indicators: ['suspicious_user_agent'], mitigated: false, userAgent: 'Mozilla/4.0' },
];

const SEVERITY_CONFIG = {
  critical: { bg: 'bg-red-100', text: 'text-red-700', label: 'Critical', pulse: true },
  high: { bg: 'bg-orange-100', text: 'text-orange-700', label: 'High' },
  medium: { bg: 'bg-yellow-100', text: 'text-yellow-700', label: 'Medium' },
  low: { bg: 'bg-blue-100', text: 'text-blue-700', label: 'Low' },
};

const TYPE_LABELS: Record<string, string> = {
  credential_stuffing: 'Credential Stuffing',
  brute_force: 'Brute Force',
  replay_attack: 'Replay Attack',
  anomaly: 'Anomaly Detection',
};

export default function SecurityPage() {
  const [threats] = useState(MOCK_THREATS);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);

  const filtered = threats.filter((t) => {
    const matchSearch = !search || t.id.includes(search) || t.ipHash.includes(search) || t.principalId.includes(search);
    const matchSeverity = severityFilter === 'all' || t.severity === severityFilter;
    return matchSearch && matchSeverity;
  });

  const mitigated = threats.filter((t) => t.mitigated).length;
  const critical = threats.filter((t) => t.severity === 'critical').length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-ink">Security Operations Center</h1>
        <p className="text-muted text-sm mt-1">Threat detection, mitigation status, and SOC analytics</p>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <div className="flex items-center gap-2">
            <AlertTriangle className="text-red-600" size={16} />
            <p className="text-sm text-muted">Total threats 24h</p>
          </div>
          <p className="text-2xl font-semibold text-ink mt-1">{threats.length}</p>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <div className="flex items-center gap-2">
            <Shield className="text-red-600" size={16} />
            <p className="text-sm text-muted">Critical</p>
          </div>
          <p className="text-2xl font-semibold text-red-600 mt-1">{critical}</p>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="text-green-600" size={16} />
            <p className="text-sm text-muted">Mitigated</p>
          </div>
          <p className="text-2xl font-semibold text-green-600 mt-1">{mitigated}/{threats.length}</p>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <div className="flex items-center gap-2">
            <Activity className="text-accent" size={16} />
            <p className="text-sm text-muted">Block rate</p>
          </div>
          <p className="text-2xl font-semibold text-ink mt-1">{((mitigated / threats.length) * 100).toFixed(0)}%</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by ID, IP, or principal..."
            className="w-full pl-9 pr-4 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
          />
        </div>
        <div className="flex gap-1">
          {['all', 'critical', 'high', 'medium', 'low'].map((s) => (
            <button
              key={s}
              onClick={() => setSeverityFilter(s)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium capitalize ${
                severityFilter === s ? 'bg-accent text-white' : 'border border-gray-200 text-muted hover:bg-gray-50'
              }`}
            >
              {s === 'all' ? 'All' : s}
            </button>
          ))}
        </div>
      </div>

      {/* Threat list */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 bg-gray-50">
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Threat ID</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Type</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Severity</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Score</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">IP</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Status</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {filtered.map((threat) => {
              const sev = SEVERITY_CONFIG[threat.severity];
              return (
                <tr
                  key={threat.id}
                  className="hover:bg-gray-50 cursor-pointer"
                  onClick={() => setSelectedThreat(threat)}
                >
                  <td className="px-4 py-3 font-mono text-xs text-accent">{threat.id}</td>
                  <td className="px-4 py-3 text-sm text-ink">{TYPE_LABELS[threat.type]}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex px-2 py-0.5 rounded-full text-xs font-medium capitalize ${sev.bg} ${sev.text}`}>
                      {sev.label}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${threat.score >= 70 ? 'bg-red-500' : threat.score >= 40 ? 'bg-yellow-500' : 'bg-green-500'}`}
                          style={{ width: `${threat.score}%` }}
                        />
                      </div>
                      <span className="text-xs text-muted">{threat.score}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-muted">{threat.ipHash}</td>
                  <td className="px-4 py-3">
                    {threat.mitigated ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-green-100 text-green-700 rounded-full text-xs">
                        <CheckCircle2 size={10} /> Mitigated
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-yellow-100 text-yellow-700 rounded-full text-xs">
                        <Clock size={10} /> Pending
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs text-muted">{new Date(threat.timestamp).toLocaleString()}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Detail modal */}
      {selectedThreat && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4" onClick={() => setSelectedThreat(null)}>
          <div className="bg-white rounded-xl max-w-lg w-full p-6" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-semibold text-lg text-ink">Threat Details</h2>
              <button onClick={() => setSelectedThreat(null)} className="p-1 hover:bg-gray-100 rounded"><X size={16} /></button>
            </div>
            <div className="space-y-3 text-sm">
              <div className="grid grid-cols-2 gap-3">
                <div><p className="text-muted">Threat ID</p><p className="font-mono text-ink">{selectedThreat.id}</p></div>
                <div><p className="text-muted">Type</p><p className="text-ink">{TYPE_LABELS[selectedThreat.type]}</p></div>
                <div><p className="text-muted">Severity</p><span className={`inline-flex px-2 py-0.5 rounded-full text-xs font-medium capitalize ${SEVERITY_CONFIG[selectedThreat.severity].bg} ${SEVERITY_CONFIG[selectedThreat.severity].text}`}>{selectedThreat.severity}</span></div>
                <div><p className="text-muted">Score</p><p className="text-ink">{selectedThreat.score}/100</p></div>
                <div><p className="text-muted">IP</p><p className="font-mono text-ink">{selectedThreat.ipHash}</p></div>
                <div><p className="text-muted">User Agent</p><p className="text-ink truncate">{selectedThreat.userAgent}</p></div>
              </div>
              <div>
                <p className="text-muted mb-1">Indicators</p>
                <div className="flex flex-wrap gap-1">
                  {selectedThreat.indicators.map((ind) => (
                    <span key={ind} className="px-2 py-0.5 bg-red-50 text-red-700 rounded text-xs">{ind}</span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}