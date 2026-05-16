'use client';

import { useQuery } from '@tanstack/react-query';
import {
  Users, Activity, Shield, Database, TrendingUp, TrendingDown,
  AlertTriangle, CheckCircle2, Clock, ArrowUpRight, ArrowDownRight
} from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string | number;
  change?: number;
  icon: React.ReactNode;
  subtitle?: string;
}

function MetricCard({ title, value, change, icon, subtitle }: MetricCardProps) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-muted text-sm font-medium">{title}</p>
          <p className="text-2xl font-semibold text-ink mt-1">{value}</p>
          {subtitle && <p className="text-muted text-xs mt-1">{subtitle}</p>}
        </div>
        <div className="w-10 h-10 bg-accent/10 rounded-lg flex items-center justify-center text-accent">
          {icon}
        </div>
      </div>
      {change !== undefined && (
        <div className={`flex items-center gap-1 mt-3 text-sm ${change >= 0 ? 'text-green-600' : 'text-red-600'}`}>
          {change >= 0 ? <ArrowUpRight size={14} /> : <ArrowDownRight size={14} />}
          <span>{Math.abs(change)}%</span>
          <span className="text-muted">vs last period</span>
        </div>
      )}
    </div>
  );
}

interface ProviderStatusProps {
  name: string;
  status: 'healthy' | 'degraded' | 'unavailable';
  successRate: number;
  latency: number;
}

function ProviderStatus({ name, status, successRate, latency }: ProviderStatusProps) {
  const statusColors = {
    healthy: 'bg-green-500',
    degraded: 'bg-yellow-500',
    unavailable: 'bg-red-500',
  };

  return (
    <div className="flex items-center justify-between py-2">
      <div className="flex items-center gap-3">
        <div className={`w-2 h-2 rounded-full ${statusColors[status]}`} />
        <span className="text-sm font-medium text-ink">{name}</span>
      </div>
      <div className="flex items-center gap-6 text-xs text-muted">
        <span>{successRate.toFixed(1)}%</span>
        <span>{latency}ms</span>
      </div>
    </div>
  );
}

export default function OverviewPage() {
  // Mock data — replace with actual API calls
  const metrics = [
    { title: 'Active Users', value: '12,847', change: 8.2, icon: <Users size={20} />, subtitle: 'Last 24h' },
    { title: 'Total Sessions', value: '48,392', change: 12.5, icon: <Activity size={20} />, subtitle: 'Last 24h' },
    { title: 'Threats Blocked', value: '127', change: -3.1, icon: <Shield size={20} />, subtitle: 'Last 24h' },
    { title: 'Avg Latency', value: '142ms', change: -15.3, icon: <Clock size={20} />, subtitle: 'Last 24h' },
  ];

  const providers: ProviderStatusProps[] = [
    { name: 'Twilio SMS', status: 'healthy', successRate: 99.2, latency: 120 },
    { name: 'SendGrid Email', status: 'healthy', successRate: 99.8, latency: 180 },
    { name: 'Firebase OTP', status: 'degraded', successRate: 94.5, latency: 450 },
    { name: 'WhatsApp Cloud', status: 'healthy', successRate: 98.9, latency: 220 },
  ];

  const recentActivity = [
    { type: 'login', user: 'user@acme.com', time: '2m ago', status: 'success' },
    { type: 'otp_sent', user: '+1 555 1234', time: '5m ago', status: 'success' },
    { type: 'threat_blocked', user: '192.168.1.x', time: '8m ago', status: 'blocked' },
    { type: 'signup', user: 'new@company.io', time: '12m ago', status: 'success' },
    { type: 'mfa_challenge', user: 'admin@corp.com', time: '15m ago', status: 'success' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-ink">Dashboard Overview</h1>
        <p className="text-muted text-sm mt-1">Real-time system health and activity</p>
      </div>

      {/* Metrics grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {metrics.map((m) => (
          <MetricCard key={m.title} {...m} />
        ))}
      </div>

      {/* Provider health + Recent activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Provider health */}
        <div className="bg-white rounded-xl border border-gray-200 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-semibold text-ink">Provider Health</h2>
            <a href="/dashboard/providers" className="text-accent text-sm hover:underline">View all</a>
          </div>
          <div className="space-y-0">
            {providers.map((p) => (
              <ProviderStatus key={p.name} {...p} />
            ))}
          </div>
        </div>

        {/* Recent activity */}
        <div className="bg-white rounded-xl border border-gray-200 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-semibold text-ink">Recent Activity</h2>
            <a href="/dashboard/audit" className="text-accent text-sm hover:underline">View all</a>
          </div>
          <div className="space-y-3">
            {recentActivity.map((a, i) => (
              <div key={i} className="flex items-center gap-3 text-sm">
                <div className={`w-1.5 h-1.5 rounded-full ${a.status === 'success' ? 'bg-green-500' : 'bg-red-500'}`} />
                <span className="text-muted">{a.type.replace('_', ' ')}</span>
                <span className="text-ink font-medium truncate max-w-[120px]">{a.user}</span>
                <span className="text-muted ml-auto">{a.time}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Quick stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-white rounded-xl border border-gray-200 p-5 flex items-center gap-4">
          <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center text-green-600">
            <CheckCircle2 size={24} />
          </div>
          <div>
            <p className="text-2xl font-semibold text-ink">99.4%</p>
            <p className="text-muted text-sm">Delivery rate</p>
          </div>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-5 flex items-center gap-4">
          <div className="w-12 h-12 bg-yellow-100 rounded-full flex items-center justify-center text-yellow-600">
            <AlertTriangle size={24} />
          </div>
          <div>
            <p className="text-2xl font-semibold text-ink">23</p>
            <p className="text-muted text-sm">Pending OTPs</p>
          </div>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-5 flex items-center gap-4">
          <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center text-blue-600">
            <TrendingUp size={24} />
          </div>
          <div>
            <p className="text-2xl font-semibold text-ink">+18%</p>
            <p className="text-muted text-sm">Auth growth</p>
          </div>
        </div>
      </div>
    </div>
  );
}