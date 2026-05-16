'use client';

import { useState, useMemo, useEffect } from 'react';
import {
  Search, Plus, MoreHorizontal, ChevronLeft, ChevronRight,
  Shield, Users, Trash2, Edit, Eye, X, Check, AlertCircle
} from 'lucide-react';
import { governanceService, type Role, type Permission, type RoleAssignment } from '@/services/governance.service';

// Mock data for fallback when API is unavailable
const MOCK_PERMISSIONS: Permission[] = [
  { id: 'p1', name: 'users:read', action: 'read', resource: 'users', description: 'View users', createdAt: '2024-01-01' },
  { id: 'p2', name: 'users:create', action: 'create', resource: 'users', description: 'Create users', createdAt: '2024-01-01' },
  { id: 'p3', name: 'users:update', action: 'update', resource: 'users', description: 'Update users', createdAt: '2024-01-01' },
  { id: 'p4', name: 'users:delete', action: 'delete', resource: 'users', description: 'Delete users', createdAt: '2024-01-01' },
  { id: 'p5', name: 'roles:read', action: 'read', resource: 'roles', description: 'View roles', createdAt: '2024-01-01' },
  { id: 'p6', name: 'roles:create', action: 'create', resource: 'roles', description: 'Create roles', createdAt: '2024-01-01' },
  { id: 'p7', name: 'roles:update', action: 'update', resource: 'roles', description: 'Update roles', createdAt: '2024-01-01' },
  { id: 'p8', name: 'roles:delete', action: 'delete', resource: 'roles', description: 'Delete roles', createdAt: '2024-01-01' },
  { id: 'p9', name: 'sessions:read', action: 'read', resource: 'sessions', description: 'View sessions', createdAt: '2024-01-01' },
  { id: 'p10', name: 'audit:read', action: 'read', resource: 'audit', description: 'View audit logs', createdAt: '2024-01-01' },
];

const MOCK_ROLES: Role[] = [
  {
    id: 'r1', name: 'Admin', description: 'Full system access', status: 'active',
    permissions: MOCK_PERMISSIONS, memberCount: 3, tenantId: 't1',
    createdAt: '2024-01-01', updatedAt: '2024-01-15'
  },
  {
    id: 'r2', name: 'Manager', description: 'Manage users and view reports', status: 'active',
    permissions: MOCK_PERMISSIONS.slice(0, 5), memberCount: 8, tenantId: 't1',
    createdAt: '2024-01-05', updatedAt: '2024-02-10'
  },
  {
    id: 'r3', name: 'Viewer', description: 'Read-only access', status: 'active',
    permissions: MOCK_PERMISSIONS.filter(p => p.action === 'read'), memberCount: 15, tenantId: 't1',
    createdAt: '2024-02-01', updatedAt: '2024-02-01'
  },
  {
    id: 'r4', name: 'Developer', description: 'Access to developer tools', status: 'deprecated',
    permissions: MOCK_PERMISSIONS.slice(4, 8), memberCount: 0, tenantId: 't1',
    createdAt: '2023-06-15', updatedAt: '2024-03-01'
  },
];

const MOCK_ASSIGNMENTS: RoleAssignment[] = [
  { id: 'a1', userId: 'u1', roleId: 'r1', assignedAt: '2024-01-01' },
  { id: 'a2', userId: 'u2', roleId: 'r2', assignedAt: '2024-01-10' },
  { id: 'a3', userId: 'u3', roleId: 'r2', assignedAt: '2024-02-15' },
  { id: 'a4', userId: 'u4', roleId: 'r3', assignedAt: '2024-03-01' },
];

const MOCK_USERS = [
  { id: 'u1', displayName: 'Alice Johnson', email: 'alice@acme.com' },
  { id: 'u2', displayName: 'Bob Smith', email: 'bob@acme.com' },
  { id: 'u3', displayName: 'Carol White', email: 'carol@acme.com' },
  { id: 'u4', displayName: 'David Brown', email: 'david@acme.com' },
  { id: 'u5', displayName: 'Eve Davis', email: 'eve@acme.com' },
];

const PAGE_SIZE = 10;

const STATUS_STYLES = {
  active: { bg: 'bg-green-100', text: 'text-green-700', label: 'Active' },
  suspended: { bg: 'bg-red-100', text: 'text-red-700', label: 'Suspended' },
  deprecated: { bg: 'bg-gray-100', text: 'text-gray-700', label: 'Deprecated' },
};

// Modal component
function Modal({ isOpen, onClose, title, children }: { isOpen: boolean; onClose: () => void; title: string; children: React.ReactNode }) {
  if (!isOpen) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="relative bg-white rounded-xl shadow-xl w-full max-w-lg max-h-[90vh] overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-ink">{title}</h2>
          <button onClick={onClose} className="p-1 text-muted hover:text-ink rounded">
            <X size={20} />
          </button>
        </div>
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-120px)]">{children}</div>
      </div>
    </div>
  );
}

// Create/Edit Role Form
interface RoleFormData {
  name: string;
  description: string;
  permissionIds: string[];
}

function RoleForm({
  role,
  permissions,
  onSubmit,
  onCancel
}: {
  role?: Role;
  permissions: Permission[];
  onSubmit: (data: RoleFormData) => void;
  onCancel: () => void;
}) {
  const [formData, setFormData] = useState<RoleFormData>({
    name: role?.name || '',
    description: role?.description || '',
    permissionIds: role?.permissions.map(p => p.id) || [],
  });
  const [errors, setErrors] = useState<Record<string, string>>({});

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const newErrors: Record<string, string> = {};
    if (!formData.name.trim()) newErrors.name = 'Name is required';
    if (formData.name.length > 50) newErrors.name = 'Name must be 50 characters or less';
    if (formData.description.length > 200) newErrors.description = 'Description must be 200 characters or less';
    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }
    onSubmit(formData);
  };

  const togglePermission = (permId: string) => {
    setFormData(prev => ({
      ...prev,
      permissionIds: prev.permissionIds.includes(permId)
        ? prev.permissionIds.filter(id => id !== permId)
        : [...prev.permissionIds, permId],
    }));
  };

  const selectAll = () => setFormData(prev => ({ ...prev, permissionIds: permissions.map(p => p.id) }));
  const selectNone = () => setFormData(prev => ({ ...prev, permissionIds: [] }));

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-ink mb-1">Role Name</label>
        <input
          type="text"
          value={formData.name}
          onChange={e => setFormData(prev => ({ ...prev, name: e.target.value }))}
          className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
          placeholder="Enter role name"
        />
        {errors.name && <p className="text-red-500 text-xs mt-1">{errors.name}</p>}
      </div>

      <div>
        <label className="block text-sm font-medium text-ink mb-1">Description</label>
        <textarea
          value={formData.description}
          onChange={e => setFormData(prev => ({ ...prev, description: e.target.value }))}
          className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
          placeholder="Enter role description"
          rows={3}
        />
        {errors.description && <p className="text-red-500 text-xs mt-1">{errors.description}</p>}
      </div>

      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="block text-sm font-medium text-ink">Permissions</label>
          <div className="flex gap-2">
            <button type="button" onClick={selectAll} className="text-xs text-accent hover:underline">Select all</button>
            <span className="text-muted">|</span>
            <button type="button" onClick={selectNone} className="text-xs text-accent hover:underline">Select none</button>
          </div>
        </div>
        <div className="border border-gray-200 rounded-lg max-h-48 overflow-y-auto p-3 space-y-2">
          {permissions.map(perm => (
            <label key={perm.id} className="flex items-center gap-2 cursor-pointer hover:bg-gray-50 p-1 rounded">
              <input
                type="checkbox"
                checked={formData.permissionIds.includes(perm.id)}
                onChange={() => togglePermission(perm.id)}
                className="rounded border-gray-300 text-accent focus:ring-accent"
              />
              <span className="text-sm text-ink">{perm.name}</span>
              {perm.description && <span className="text-xs text-muted">- {perm.description}</span>}
            </label>
          ))}
        </div>
      </div>

      <div className="flex justify-end gap-3 pt-4">
        <button type="button" onClick={onCancel} className="px-4 py-2 border border-gray-200 rounded-lg text-sm font-medium text-ink hover:bg-gray-50">
          Cancel
        </button>
        <button type="submit" className="px-4 py-2 bg-accent text-white rounded-lg text-sm font-medium hover:bg-accent/90">
          {role ? 'Update Role' : 'Create Role'}
        </button>
      </div>
    </form>
  );
}

// Assign User Modal
function AssignUserModal({
  isOpen,
  onClose,
  role,
  users,
  assignments,
  onAssign,
  onRevoke
}: {
  isOpen: boolean;
  onClose: () => void;
  role: Role | null;
  users: typeof MOCK_USERS;
  assignments: RoleAssignment[];
  onAssign: (userId: string) => void;
  onRevoke: (assignmentId: string) => void;
}) {
  const [selectedUser, setSelectedUser] = useState<string>('');
  const [search, setSearch] = useState('');

  if (!role) return null;

  const assignedUserIds = assignments.filter(a => a.roleId === role.id).map(a => a.userId);
  const availableUsers = users.filter(u => !assignedUserIds.includes(u.id));

  const filteredUsers = availableUsers.filter(u =>
    u.displayName.toLowerCase().includes(search.toLowerCase()) ||
    u.email.toLowerCase().includes(search.toLowerCase())
  );

  const handleAssign = () => {
    if (selectedUser) {
      onAssign(selectedUser);
      setSelectedUser('');
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={`Assign Users to "${role.name}"`}>
      <div className="space-y-4">
        {/* Current assignments */}
        <div>
          <h3 className="text-sm font-medium text-ink mb-2">Assigned Users ({assignedUserIds.length})</h3>
          {assignedUserIds.length === 0 ? (
            <p className="text-sm text-muted">No users assigned to this role</p>
          ) : (
            <div className="space-y-2 max-h-40 overflow-y-auto">
              {assignments.filter(a => a.roleId === role.id).map(a => {
                const user = users.find(u => u.id === a.userId);
                return user ? (
                  <div key={a.id} className="flex items-center justify-between p-2 bg-gray-50 rounded-lg">
                    <div>
                      <p className="text-sm font-medium text-ink">{user.displayName}</p>
                      <p className="text-xs text-muted">{user.email}</p>
                    </div>
                    <button onClick={() => onRevoke(a.id)} className="text-red-500 hover:text-red-700">
                      <Trash2 size={16} />
                    </button>
                  </div>
                ) : null;
              })}
            </div>
          )}
        </div>

        {/* Add new user */}
        <div>
          <h3 className="text-sm font-medium text-ink mb-2">Assign New User</h3>
          <div className="flex gap-2">
            <select
              value={selectedUser}
              onChange={e => setSelectedUser(e.target.value)}
              className="flex-1 px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
            >
              <option value="">Select a user</option>
              {filteredUsers.map(u => (
                <option key={u.id} value={u.id}>{u.displayName} ({u.email})</option>
              ))}
            </select>
            <button
              onClick={handleAssign}
              disabled={!selectedUser}
              className="px-4 py-2 bg-accent text-white rounded-lg text-sm font-medium hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Assign
            </button>
          </div>
        </div>
      </div>
    </Modal>
  );
}

// Role Details Drawer
function RoleDetailsDrawer({
  role,
  permissions,
  users,
  assignments,
  onClose,
  onAssign,
  onRevoke
}: {
  role: Role | null;
  permissions: Permission[];
  users: typeof MOCK_USERS;
  assignments: RoleAssignment[];
  onClose: () => void;
  onAssign: () => void;
  onRevoke: (assignmentId: string) => void;
}) {
  if (!role) return null;

  const rolePermissions = permissions.filter(p => role.permissions.some(rp => rp.id === p.id));
  const roleAssignments = assignments.filter(a => a.roleId === role.id);

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="relative w-full max-w-md bg-white shadow-xl h-full overflow-y-auto">
        <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-ink">Role Details</h2>
          <button onClick={onClose} className="p-1 text-muted hover:text-ink rounded">
            <X size={20} />
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Basic Info */}
          <div>
            <h3 className="text-sm font-medium text-muted mb-1">Name</h3>
            <p className="text-ink font-medium">{role.name}</p>
          </div>

          <div>
            <h3 className="text-sm font-medium text-muted mb-1">Description</h3>
            <p className="text-ink">{role.description || 'No description'}</p>
          </div>

          <div>
            <h3 className="text-sm font-medium text-muted mb-1">Status</h3>
            <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${STATUS_STYLES[role.status].bg} ${STATUS_STYLES[role.status].text}`}>
              {STATUS_STYLES[role.status].label}
            </span>
          </div>

          <div>
            <h3 className="text-sm font-medium text-muted mb-1">Created</h3>
            <p className="text-ink text-sm">{new Date(role.createdAt).toLocaleDateString()}</p>
          </div>

          {/* Permissions */}
          <div>
            <h3 className="text-sm font-medium text-muted mb-2">Permissions ({rolePermissions.length})</h3>
            <div className="flex flex-wrap gap-1">
              {rolePermissions.map(p => (
                <span key={p.id} className="inline-flex items-center px-2 py-1 bg-blue-50 text-blue-700 rounded text-xs">
                  {p.name}
                </span>
              ))}
            </div>
          </div>

          {/* Assigned Users */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-medium text-muted">Assigned Users ({roleAssignments.length})</h3>
              <button onClick={onAssign} className="text-accent text-sm hover:underline">
                Manage
              </button>
            </div>
            {roleAssignments.length === 0 ? (
              <p className="text-sm text-muted">No users assigned</p>
            ) : (
              <div className="space-y-2">
                {roleAssignments.map(a => {
                  const user = users.find(u => u.id === a.userId);
                  return user ? (
                    <div key={a.id} className="flex items-center justify-between p-2 bg-gray-50 rounded-lg">
                      <div>
                        <p className="text-sm font-medium text-ink">{user.displayName}</p>
                        <p className="text-xs text-muted">{user.email}</p>
                      </div>
                      <button onClick={() => onRevoke(a.id)} className="text-red-500 hover:text-red-700">
                        <Trash2 size={14} />
                      </button>
                    </div>
                  ) : null;
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function RolesPage() {
  const [roles, setRoles] = useState<Role[]>(MOCK_ROLES);
  const [permissions] = useState<Permission[]>(MOCK_PERMISSIONS);
  const [assignments, setAssignments] = useState<RoleAssignment[]>(MOCK_ASSIGNMENTS);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState<string>('all');

  // Modal states
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingRole, setEditingRole] = useState<Role | null>(null);
  const [selectedRole, setSelectedRole] = useState<Role | null>(null);
  const [showAssignModal, setShowAssignModal] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<Role | null>(null);

  // Load data from API
  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        setError(null);
        const [rolesRes, permsRes] = await Promise.all([
          governanceService.listRoles(),
          governanceService.listPermissions(),
        ]);
        if (rolesRes.data?.items) setRoles(rolesRes.data.items);
        if (permsRes.data) permissions = permsRes.data;
      } catch (err) {
        // Use mock data on error
        console.log('Using mock data:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const filteredRoles = useMemo(() => {
    return roles.filter(r => {
      const matchSearch = !search || r.name.toLowerCase().includes(search.toLowerCase()) ||
        r.description?.toLowerCase().includes(search.toLowerCase());
      const matchStatus = statusFilter === 'all' || r.status === statusFilter;
      return matchSearch && matchStatus;
    });
  }, [roles, search, statusFilter]);

  const paginatedRoles = useMemo(() => {
    const start = (page - 1) * PAGE_SIZE;
    return filteredRoles.slice(start, start + PAGE_SIZE);
  }, [filteredRoles, page]);

  const totalPages = Math.ceil(filteredRoles.length / PAGE_SIZE);

  const handleCreateRole = async (formData: RoleFormData) => {
    setLoading(true);
    try {
      const selectedPerms = permissions.filter(p => formData.permissionIds.includes(p.id));
      const newRole: Role = {
        id: `r${Date.now()}`,
        name: formData.name,
        description: formData.description,
        status: 'active',
        permissions: selectedPerms,
        memberCount: 0,
        tenantId: 't1',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      setRoles(prev => [newRole, ...prev]);
      setShowCreateModal(false);
    } catch (err) {
      setError('Failed to create role');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateRole = async (formData: RoleFormData) => {
    if (!editingRole) return;
    setLoading(true);
    try {
      const selectedPerms = permissions.filter(p => formData.permissionIds.includes(p.id));
      const updatedRole: Role = {
        ...editingRole,
        name: formData.name,
        description: formData.description,
        permissions: selectedPerms,
        updatedAt: new Date().toISOString(),
      };
      setRoles(prev => prev.map(r => r.id === editingRole.id ? updatedRole : r));
      setEditingRole(null);
    } catch (err) {
      setError('Failed to update role');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteRole = async (role: Role) => {
    setLoading(true);
    try {
      setRoles(prev => prev.filter(r => r.id !== role.id));
      setDeleteConfirm(null);
    } catch (err) {
      setError('Failed to delete role');
    } finally {
      setLoading(false);
    }
  };

  const handleAssignUser = (userId: string) => {
    if (!selectedRole) return;
    const newAssignment: RoleAssignment = {
      id: `a${Date.now()}`,
      userId,
      roleId: selectedRole.id,
      assignedAt: new Date().toISOString(),
    };
    setAssignments(prev => [...prev, newAssignment]);
    setRoles(prev => prev.map(r =>
      r.id === selectedRole.id ? { ...r, memberCount: r.memberCount + 1 } : r
    ));
  };

  const handleRevokeAssignment = (assignmentId: string) => {
    const assignment = assignments.find(a => a.id === assignmentId);
    if (!assignment) return;
    setAssignments(prev => prev.filter(a => a.id !== assignmentId));
    setRoles(prev => prev.map(r =>
      r.id === assignment.roleId ? { ...r, memberCount: Math.max(0, r.memberCount - 1) } : r
    ));
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Roles</h1>
          <p className="text-muted text-sm mt-1">{filteredRoles.length} roles found</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-accent text-white rounded-lg text-sm font-medium hover:bg-accent/90"
        >
          <Plus size={16} />
          Create role
        </button>
      </div>

      {/* Error banner */}
      {error && (
        <div className="flex items-center gap-2 p-3 bg-red-50 text-red-700 rounded-lg text-sm">
          <AlertCircle size={16} />
          {error}
          <button onClick={() => setError(null)} className="ml-auto text-red-700 hover:text-red-900">
            <X size={16} />
          </button>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="text"
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1); }}
            placeholder="Search by name or description..."
            className="w-full pl-9 pr-4 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
          />
        </div>
        <select
          value={statusFilter}
          onChange={e => { setStatusFilter(e.target.value); setPage(1); }}
          className="px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
        >
          <option value="all">All statuses</option>
          <option value="active">Active</option>
          <option value="suspended">Suspended</option>
          <option value="deprecated">Deprecated</option>
        </select>
      </div>

      {/* Loading state */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <div className="w-8 h-8 border-2 border-accent border-t-transparent rounded-full animate-spin" />
        </div>
      )}

      {/* Table */}
      {!loading && (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200 bg-gray-50">
                <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Role</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Description</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Status</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Permissions</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Members</th>
                <th className="w-10"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {paginatedRoles.map(role => {
                const statusStyle = STATUS_STYLES[role.status];
                return (
                  <tr key={role.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 bg-purple-100 rounded-lg flex items-center justify-center">
                          <Shield size={16} className="text-purple-600" />
                        </div>
                        <span className="font-medium text-ink text-sm">{role.name}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-muted">{role.description || '-'}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${statusStyle.bg} ${statusStyle.text}`}>
                        {statusStyle.label}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-muted">{role.permissions.length} permissions</span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1 text-sm text-muted">
                        <Users size={14} />
                        {role.memberCount}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => setSelectedRole(role)}
                          className="p-1 text-muted hover:text-ink rounded"
                          title="View details"
                        >
                          <Eye size={16} />
                        </button>
                        <button
                          onClick={() => setEditingRole(role)}
                          className="p-1 text-muted hover:text-ink rounded"
                          title="Edit role"
                        >
                          <Edit size={16} />
                        </button>
                        <button
                          onClick={() => setDeleteConfirm(role)}
                          className="p-1 text-muted hover:text-red-600 rounded"
                          title="Delete role"
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {/* Empty state */}
          {paginatedRoles.length === 0 && (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <Shield size={48} className="text-muted mb-3" />
              <p className="text-muted">No roles found</p>
              <button
                onClick={() => setShowCreateModal(true)}
                className="mt-2 text-accent text-sm hover:underline"
              >
                Create your first role
              </button>
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 bg-gray-50">
              <p className="text-sm text-muted">
                Showing {(page - 1) * PAGE_SIZE + 1} to {Math.min(page * PAGE_SIZE, filteredRoles.length)} of {filteredRoles.length}
              </p>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setPage(Math.max(1, page - 1))}
                  disabled={page === 1}
                  className="p-1.5 rounded border border-gray-200 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-100"
                >
                  <ChevronLeft size={14} />
                </button>
                {Array.from({ length: totalPages }, (_, i) => i + 1).map(p => (
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
          )}
        </div>
      )}

      {/* Create Role Modal */}
      <Modal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Create New Role"
      >
        <RoleForm
          permissions={permissions}
          onSubmit={handleCreateRole}
          onCancel={() => setShowCreateModal(false)}
        />
      </Modal>

      {/* Edit Role Modal */}
      <Modal
        isOpen={!!editingRole}
        onClose={() => setEditingRole(null)}
        title="Edit Role"
      >
        {editingRole && (
          <RoleForm
            role={editingRole}
            permissions={permissions}
            onSubmit={handleUpdateRole}
            onCancel={() => setEditingRole(null)}
          />
        )}
      </Modal>

      {/* Role Details Drawer */}
      <RoleDetailsDrawer
        role={selectedRole}
        permissions={permissions}
        users={MOCK_USERS}
        assignments={assignments}
        onClose={() => setSelectedRole(null)}
        onAssign={() => setShowAssignModal(true)}
        onRevoke={handleRevokeAssignment}
      />

      {/* Assign User Modal */}
      <AssignUserModal
        isOpen={showAssignModal}
        onClose={() => setShowAssignModal(false)}
        role={selectedRole}
        users={MOCK_USERS}
        assignments={assignments}
        onAssign={handleAssignUser}
        onRevoke={handleRevokeAssignment}
      />

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={!!deleteConfirm}
        onClose={() => setDeleteConfirm(null)}
        title="Delete Role"
      >
        <div className="space-y-4">
          <p className="text-ink">
            Are you sure you want to delete the role <strong>"{deleteConfirm?.name}"</strong>?
          </p>
          <p className="text-sm text-muted">
            This action cannot be undone. {deleteConfirm?.memberCount || 0} users will lose this role.
          </p>
          <div className="flex justify-end gap-3 pt-4">
            <button
              onClick={() => setDeleteConfirm(null)}
              className="px-4 py-2 border border-gray-200 rounded-lg text-sm font-medium text-ink hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              onClick={() => deleteConfirm && handleDeleteRole(deleteConfirm)}
              className="px-4 py-2 bg-red-500 text-white rounded-lg text-sm font-medium hover:bg-red-600"
            >
              Delete
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}