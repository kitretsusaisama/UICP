'use client';

import { useState } from 'react';
import { BarChart3, TrendingUp, Users, Shield, Clock } from 'lucide-react';

interface TrendPoint {
  date: string;
  logins: number;
  signups: number;
  otpRequests: number;
  threats: number;
}

const MOCK_TRENDS: TrendPoint[] = [
  { date: '2024-05-06', logins: 1200, signups: 45, otpRequests: 890, threats: 3 },
  { date: '2024-05-07', logins: 1350, signups: 52, otpRequests: 940, threats: 5 },
  { date: '2024-05-08', logins: 1180, signups: 38, otpRequests: 820, threats: 2 },
  { date: '2024-05-09', logins: 1420, signups: 61, otpRequests: 1050, threats: 8 },
  { date: '2024-05-10', logins: 1580, signups: 70, otpRequests: 1120, threats: 4 },
  { date: '2024-05-11', logins: 1650, signups: 75, otpRequests: 1200, threats: 6 },
  { date: '2024-05-12', logins: 1720, signups: 82, otpRequests: 1280, threats: 7 },
];

export default function AnalyticsPage() {
  const [period, setPeriod] = useState('7d');

  const totalLogins = MOCK_TRENDS.reduce((acc, t) => acc + t.logins, 0);
  const totalSignups = MOCK_TRENDS.reduce((acc, t) => acc + t.signups, 0);
  const totalOtp = MOCK_TRENDS.reduce((acc, t) => acc + t.otpRequests, 0);
  const totalThreats = MOCK_TRENDS.reduce((acc, t) => acc + t.threats, 0);
  const maxVal = Math.max(...MOCK_TRENDS.map((t) => t.logins));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Analytics</h1>
          <p className="text-muted text-sm mt-1">Authentication trends, user activity, and system metrics</p>
        </div>
        <div className="flex gap-1">
          {['24h', '7d', '30d'].map((p) => (
            <button
              key={p}
              onClick={() => setPeriod(p)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium ${
                period === p ? 'bg-accent text-white' : 'border border-gray-200 text-muted hover:bg-gray-50'
              }`}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total logins', value: totalLogins.toLocaleString(), icon: Users, color: 'text-blue-600', change: '+12%' },
          { label: 'New signups', value: totalSignups.toLocaleString(), icon: TrendingUp, color: 'text-green-600', change: '+8%' },
          { label: 'OTP requests', value: totalOtp.toLocaleString(), icon: Shield, color: 'text-purple-600', change: '+15%' },
          { label: 'Threats blocked', value: totalThreats.toString(), icon: Clock, color: 'text-red-600', change: '-3%' },
        ].map((stat) => {
          const Icon = stat.icon;
          return (
            <div key={stat.label} className="bg-white rounded-xl border border-gray-200 p-5">
              <div className="flex items-center gap-2">
                <Icon size={16} className={stat.color} />
                <p className="text-sm text-muted">{stat.label}</p>
              </div>
              <p className="text-2xl font-semibold text-ink mt-1">{stat.value}</p>
              <p className={`text-xs mt-1 ${stat.change.startsWith('+') ? 'text-green-600' : 'text-red-600'}`}>{stat.change} vs prev period</p>
            </div>
          );
        })}
      </div>

      {/* Bar chart placeholder */}
      <div className="bg-white rounded-xl border border-gray-200 p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="font-semibold text-ink">Login Activity (7 days)</h2>
        </div>

        {/* Simple SVG bar chart */}
        <div className="flex items-end gap-4 h-48">
          {MOCK_TRENDS.map((point, i) => {
            const height = (point.logins / maxVal) * 100;
            return (
              <div key={i} className="flex-1 flex flex-col items-center gap-2">
                <div className="w-full flex flex-col gap-1">
                  <div
                    className="w-full bg-accent rounded-t-sm transition-all"
                    style={{ height: `${(point.logins / maxVal) * 60}%`, minHeight: '4px' }}
                    title={`Logins: ${point.logins}`}
                  />
                  <div
                    className="w-full bg-green-400 rounded-t-sm transition-all"
                    style={{ height: `${(point.signups / maxVal) * 40}%`, minHeight: '2px' }}
                    title={`Signups: ${point.signups}`}
                  />
                </div>
                <span className="text-xs text-muted">{point.date.split('-')[2]}</span>
              </div>
            );
          })}
        </div>

        {/* Legend */}
        <div className="flex items-center justify-center gap-6 mt-4">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-accent rounded" />
            <span className="text-xs text-muted">Logins</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-green-400 rounded" />
            <span className="text-xs text-muted">Signups</span>
          </div>
        </div>
      </div>

      {/* Metric breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-xl border border-gray-200 p-5">
          <h2 className="font-semibold text-ink mb-4">OTP Channel Distribution</h2>
          <div className="space-y-3">
            {[
              { channel: 'Email', count: Math.round(totalOtp * 0.55), pct: 55, color: 'bg-blue-500' },
              { channel: 'SMS', count: Math.round(totalOtp * 0.30), pct: 30, color: 'bg-green-500' },
              { channel: 'WhatsApp', count: Math.round(totalOtp * 0.12), pct: 12, color: 'bg-purple-500' },
              { channel: 'Voice', count: Math.round(totalOtp * 0.03), pct: 3, color: 'bg-yellow-500' },
            ].map((item) => (
              <div key={item.channel} className="flex items-center gap-3">
                <span className="w-20 text-sm text-muted">{item.channel}</span>
                <div className="flex-1 h-2 bg-gray-100 rounded-full overflow-hidden">
                  <div className={`h-full ${item.color} rounded-full`} style={{ width: `${item.pct}%` }} />
                </div>
                <span className="w-12 text-sm text-ink text-right">{item.count.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-5">
          <h2 className="font-semibold text-ink mb-4">Threat by Type</h2>
          <div className="space-y-3">
            {[
              { type: 'Credential Stuffing', count: 12, color: 'bg-red-500' },
              { type: 'Brute Force', count: 8, color: 'bg-orange-500' },
              { type: 'Anomaly Detection', count: 5, color: 'bg-yellow-500' },
              { type: 'Replay Attack', count: 2, color: 'bg-blue-500' },
            ].map((item) => (
              <div key={item.type} className="flex items-center gap-3">
                <span className="w-32 text-sm text-muted">{item.type}</span>
                <div className="flex-1 h-2 bg-gray-100 rounded-full overflow-hidden">
                  <div className={`h-full ${item.color} rounded-full`} style={{ width: `${(item.count / 27) * 100}%` }} />
                </div>
                <span className="w-8 text-sm text-ink text-right">{item.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}