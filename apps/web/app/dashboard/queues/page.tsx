'use client';

import { useState } from 'react';
import { Layers, RefreshCw, Play, Pause, Trash2, AlertCircle, CheckCircle2, Clock, Loader2, ChevronLeft, ChevronRight } from 'lucide-react';

interface QueueJob {
  id: string;
  name: string;
  status: 'active' | 'delayed' | 'completed' | 'failed' | 'waiting';
  attempts: number;
  maxAttempts: number;
  progress: number;
  createdAt: string;
  processedAt?: string;
  failedAt?: string;
  error?: string;
}

interface QueueMetrics {
  name: string;
  waiting: number;
  active: number;
  completed: number;
  failed: number;
  delayed: number;
  paused: boolean;
}

const MOCK_QUEUE_METRICS: QueueMetrics[] = [
  { name: 'audit-write', waiting: 3, active: 1, completed: 1247, failed: 12, delayed: 0, paused: false },
  { name: 'audit-export', waiting: 8, active: 2, completed: 456, failed: 5, delayed: 1, paused: false },
  { name: 'otp-delivery', waiting: 15, active: 5, completed: 8934, failed: 28, delayed: 2, paused: false },
  { name: 'email-notify', waiting: 42, active: 3, completed: 3201, failed: 14, delayed: 5, paused: false },
  { name: 'webhook-dispatch', waiting: 6, active: 1, completed: 1876, failed: 9, delayed: 0, paused: true },
];

const MOCK_JOBS: QueueJob[] = [
  { id: 'job_001', name: 'audit-write', status: 'active', attempts: 1, maxAttempts: 3, progress: 65, createdAt: '2024-05-12T10:30:00Z', processedAt: undefined },
  { id: 'job_002', name: 'otp-delivery', status: 'completed', attempts: 1, maxAttempts: 3, progress: 100, createdAt: '2024-05-12T10:29:00Z', processedAt: '2024-05-12T10:29:05Z' },
  { id: 'job_003', name: 'email-notify', status: 'failed', attempts: 3, maxAttempts: 3, progress: 0, createdAt: '2024-05-12T10:28:00Z', failedAt: '2024-05-12T10:28:30Z', error: 'SMTP connection timeout' },
  { id: 'job_004', name: 'audit-export', status: 'delayed', attempts: 0, maxAttempts: 3, progress: 0, createdAt: '2024-05-12T10:27:00Z' },
  { id: 'job_005', name: 'webhook-dispatch', status: 'waiting', attempts: 0, maxAttempts: 3, progress: 0, createdAt: '2024-05-12T10:26:00Z' },
  { id: 'job_006', name: 'otp-delivery', status: 'active', attempts: 1, maxAttempts: 3, progress: 40, createdAt: '2024-05-12T10:25:00Z' },
];

const STATUS_CONFIG = {
  active: { icon: Loader2, bg: 'bg-blue-100', text: 'text-blue-700', label: 'Active', spin: true },
  waiting: { icon: Clock, bg: 'bg-gray-100', text: 'text-gray-600', label: 'Waiting' },
  completed: { icon: CheckCircle2, bg: 'bg-green-100', text: 'text-green-700', label: 'Completed' },
  failed: { icon: AlertCircle, bg: 'bg-red-100', text: 'text-red-700', label: 'Failed' },
  delayed: { icon: Clock, bg: 'bg-yellow-100', text: 'text-yellow-700', label: 'Delayed' },
};

function QueueCard({ queue }: { queue: QueueMetrics }) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Layers size={16} className="text-muted" />
          <span className="font-medium text-ink">{queue.name}</span>
          {queue.paused && (
            <span className="px-1.5 py-0.5 bg-yellow-100 text-yellow-700 rounded text-xs">Paused</span>
          )}
        </div>
        <button className="p-1 text-muted hover:text-ink rounded hover:bg-gray-50">
          {queue.paused ? <Play size={14} /> : <Pause size={14} />}
        </button>
      </div>
      <div className="grid grid-cols-4 gap-2">
        {[
          { label: 'Waiting', value: queue.waiting, color: 'text-ink' },
          { label: 'Active', value: queue.active, color: 'text-blue-600' },
          { label: 'Completed', value: queue.completed, color: 'text-green-600' },
          { label: 'Failed', value: queue.failed, color: queue.failed > 5 ? 'text-red-600' : 'text-muted' },
        ].map((stat) => (
          <div key={stat.label} className="text-center">
            <p className={`text-lg font-semibold ${stat.color}`}>{stat.value}</p>
            <p className="text-xs text-muted">{stat.label}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function QueuesPage() {
  const [jobs] = useState(MOCK_JOBS);
  const [queueMetrics] = useState(MOCK_QUEUE_METRICS);
  const [selectedQueue, setSelectedQueue] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  const filtered = jobs.filter((j) => {
    const matchQueue = selectedQueue === 'all' || j.name === selectedQueue;
    const matchStatus = statusFilter === 'all' || j.status === statusFilter;
    return matchQueue && matchStatus;
  });

  const queueNames = [...new Set(jobs.map((j) => j.name))];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Queue Monitoring</h1>
          <p className="text-muted text-sm mt-1">BullMQ job queues, workers, and failure handling</p>
        </div>
        <button className="flex items-center gap-2 px-3 py-2 border border-gray-200 rounded-lg text-sm hover:bg-gray-50">
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>

      {/* Queue metrics grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
        {queueMetrics.map((q) => (
          <QueueCard key={q.name} queue={q} />
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <select
          value={selectedQueue}
          onChange={(e) => setSelectedQueue(e.target.value)}
          className="px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20"
        >
          <option value="all">All queues</option>
          {queueNames.map((n) => (
            <option key={n} value={n}>{n}</option>
          ))}
        </select>
        <div className="flex gap-1">
          {['all', 'active', 'waiting', 'completed', 'failed', 'delayed'].map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium capitalize ${
                statusFilter === s ? 'bg-accent text-white' : 'border border-gray-200 text-muted hover:bg-gray-50'
              }`}
            >
              {s === 'all' ? 'All' : s}
            </button>
          ))}
        </div>
      </div>

      {/* Job list */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 bg-gray-50">
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Job ID</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Name</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Status</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Progress</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Attempts</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Created</th>
              <th className="w-20"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {filtered.map((job) => {
              const config = STATUS_CONFIG[job.status];
              const Icon = config.icon;
              return (
                <tr key={job.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 font-mono text-xs text-accent">{job.id}</td>
                  <td className="px-4 py-3 text-sm font-medium text-ink">{job.name}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${config.bg} ${config.text}`}>
                      <Icon size={10} className={(config as { spin?: boolean }).spin ? 'animate-spin' : ''} />
                      {config.label}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-20 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                        <div className="h-full bg-accent rounded-full" style={{ width: `${job.progress}%` }} />
                      </div>
                      <span className="text-xs text-muted">{job.progress}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-muted">
                    {job.attempts}/{job.maxAttempts}
                  </td>
                  <td className="px-4 py-3 text-xs text-muted">
                    {new Date(job.createdAt).toLocaleTimeString()}
                  </td>
                  <td className="px-4 py-3">
                    {job.status === 'failed' && (
                      <button className="p-1 text-muted hover:text-red-600 rounded">
                        <Trash2 size={14} />
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}