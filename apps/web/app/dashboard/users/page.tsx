'use client';

import { useState, useMemo } from 'react';
import { Search, Plus, MoreHorizontal, Mail, Phone, CheckCircle2, XCircle, ChevronLeft, ChevronRight } from 'lucide-react';

interface User {
  id: string;
  displayName: string;
  email: string;
  phone?: string;
  status: 'active' | 'suspended' | 'pending';
  createdAt: string;
  lastActive: string;
  authMethods: string[];
}

const MOCK_USERS: User[] = [
  { id: '1', displayName: 'Alice Johnson', email: 'alice@acme.com', status: 'active', createdAt: '2024-01-15', lastActive: '2m ago', authMethods: ['EMAIL', 'PHONE'] },
  { id: '2', displayName: 'Bob Smith', email: 'bob@acme.com', phone: '+1 555 1234', status: 'active', createdAt: '2024-02-20', lastActive: '1h ago', authMethods: ['EMAIL'] },
  { id: '3', displayName: 'Carol White', email: 'carol@corp.io', status: 'suspended', createdAt: '2023-11-08', lastActive: '3d ago', authMethods: ['PHONE'] },
  { id: '4', displayName: 'David Brown', email: 'david@startup.dev', status: 'pending', createdAt: '2024-05-01', lastActive: 'Never', authMethods: ['EMAIL', 'OAUTH'] },
  { id: '5', displayName: 'Eve Davis', email: 'eve@enterprise.com', status: 'active', createdAt: '2023-08-14', lastActive: '5m ago', authMethods: ['EMAIL', 'PHONE', 'MFA'] },
];

const STATUS_STYLES = {
  active: { bg: 'bg-green-100', text: 'text-green-700', label: 'Active' },
  suspended: { bg: 'bg-red-100', text: 'text-red-700', label: 'Suspended' },
  pending: { bg: 'bg-yellow-100', text: 'text-yellow-700', label: 'Pending' },
};

const PAGE_SIZE = 10;

export default function UsersPage() {
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [selectedStatus, setSelectedStatus] = useState<string>('all');

  const filteredUsers = useMemo(() => {
    return MOCK_USERS.filter((u) => {
      const matchSearch =
        !search ||
        u.displayName.toLowerCase().includes(search.toLowerCase()) ||
        u.email.toLowerCase().includes(search.toLowerCase());
      const matchStatus = selectedStatus === 'all' || u.status === selectedStatus;
      return matchSearch && matchStatus;
    });
  }, [search, selectedStatus]);

  const paginatedUsers = useMemo(() => {
    const start = (page - 1) * PAGE_SIZE;
    return filteredUsers.slice(start, start + PAGE_SIZE);
  }, [filteredUsers, page]);

  const totalPages = Math.ceil(filteredUsers.length / PAGE_SIZE);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Users</h1>
          <p className="text-muted text-sm mt-1">{filteredUsers.length} users found</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-accent text-white rounded-lg text-sm font-medium hover:bg-accent/90">
          <Plus size={16} />
          Add user
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
            placeholder="Search by name or email..."
            className="w-full pl-9 pr-4 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
          />
        </div>
        <select
          value={selectedStatus}
          onChange={(e) => { setSelectedStatus(e.target.value); setPage(1); }}
          className="px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
        >
          <option value="all">All statuses</option>
          <option value="active">Active</option>
          <option value="pending">Pending</option>
          <option value="suspended">Suspended</option>
        </select>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 bg-gray-50">
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Name</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Contact</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Status</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Methods</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Last active</th>
              <th className="w-10"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {paginatedUsers.map((user) => {
              const statusStyle = STATUS_STYLES[user.status];
              return (
                <tr key={user.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 bg-accent/10 rounded-full flex items-center justify-center">
                        <span className="text-accent font-medium text-sm">{user.displayName[0]}</span>
                      </div>
                      <span className="font-medium text-ink text-sm">{user.displayName}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-1.5 text-sm text-muted">
                        <Mail size={12} />
                        {user.email}
                      </div>
                      {user.phone && (
                        <div className="flex items-center gap-1.5 text-sm text-muted">
                          <Phone size={12} />
                          {user.phone}
                        </div>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${statusStyle.bg} ${statusStyle.text}`}>
                      {statusStyle.label}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {user.authMethods.map((m) => (
                        <span key={m} className="inline-flex items-center px-1.5 py-0.5 bg-gray-100 rounded text-xs text-muted">
                          {m}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-muted">{user.lastActive}</td>
                  <td className="px-4 py-3">
                    <button className="p-1 text-muted hover:text-ink rounded">
                      <MoreHorizontal size={16} />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {/* Pagination */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 bg-gray-50">
          <p className="text-sm text-muted">
            Showing {(page - 1) * PAGE_SIZE + 1} to {Math.min(page * PAGE_SIZE, filteredUsers.length)} of {filteredUsers.length}
          </p>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setPage(Math.max(1, page - 1))}
              disabled={page === 1}
              className="p-1.5 rounded border border-gray-200 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-100"
            >
              <ChevronLeft size={14} />
            </button>
            {Array.from({ length: totalPages }, (_, i) => i + 1).map((p) => (
              <button
                key={p}
                onClick={() => setPage(p)}
                className={`w-8 h-8 rounded text-sm ${p === page ? 'bg-accent text-white' : 'border border-gray-200 hover:bg-gray-100'}`}
              >
                {p}
              </button>
            ))}
            <button
              onClick={() => setPage(Math.min(totalPages, page + 1))}
              disabled={page === totalPages}
              className="p-1.5 rounded border border-gray-200 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-100"
            >
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}