'use client';

import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Key, Plus, Search, Copy, Check, RefreshCw, Trash2, Eye, EyeOff,
  Shield, Clock, AlertTriangle, X, CheckCircle2, XCircle, Info
} from 'lucide-react';
import { getApiUrl, buildHeaders, resolveTenantKey, timeAgo } from '@/lib/api-client';

// ============== Types ==============

interface ApiKey {
  id: string;
  ulid: string;
  type: string;
  env: string;
  scopes: string[];
  rateLimit: number;
  createdAt: string;
  expiresAt: string;
  isActive: boolean;
  metadata: {
    name?: string;
    description?: string;
    lastUsedAt?: string;
  };
}

interface CreateApiKeyRequest {
  name?: string;
  description?: string;
  scopes?: string[];
  expiresInDays?: number;
  env?: string;
}

interface CreateApiKeyResponse {
  publishableKey: string;
  secretKey: string;
  apiKey: ApiKey;
}

interface NewKeyCreated {
  publishableKey: string;
  secretKey: string;
  keyName: string;
}

// ============== Constants ==============

const SCOPE_OPTIONS = [
  { value: 'read', label: 'Read', description: 'Read access to resources' },
  { value: 'write', label: 'Write', description: 'Create and update resources' },
  { value: 'admin', label: 'Admin', description: 'Full administrative access' },
  { value: 'identity:read', label: 'Identity: Read', description: 'Read identity data' },
  { value: 'identity:write', label: 'Identity: Write', description: 'Manage identities' },
  { value: 'tenant:read', label: 'Tenant: Read', description: 'Read tenant data' },
  { value: 'tenant:write', label: 'Tenant: Write', description: 'Manage tenants' },
  { value: 'api:read', label: 'API: Read', description: 'Read API configurations' },
  { value: 'api:write', label: 'API: Write', description: 'Manage API keys' },
];

const ENV_OPTIONS = [
  { value: 'live', label: 'Live', description: 'Production environment' },
  { value: 'dev', label: 'Development', description: 'Development environment' },
  { value: 'staging', label: 'Staging', description: 'Staging environment' },
];

const EXPIRY_OPTIONS = [
  { value: 30, label: '30 days' },
  { value: 60, label: '60 days' },
  { value: 90, label: '90 days' },
  { value: 180, label: '180 days' },
  { value: 365, label: '1 year' },
];

// ============== API Functions ==============

async function fetchApiKeys(): Promise<ApiKey[]> {
  const response = await fetch(getApiUrl('/api-keys'), {
    headers: buildHeaders(resolveTenantKey()),
  });
  if (!response.ok) {
    throw new Error('Failed to fetch API keys');
  }
  return response.json();
}

async function createApiKey(data: CreateApiKeyRequest): Promise<CreateApiKeyResponse> {
  const response = await fetch(getApiUrl('/api-keys'), {
    method: 'POST',
    headers: buildHeaders(resolveTenantKey()),
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    throw new Error('Failed to create API key');
  }
  return response.json();
}

async function rotateApiKey(id: string): Promise<CreateApiKeyResponse> {
  const response = await fetch(getApiUrl(`/api-keys/${id}/rotate`), {
    method: 'POST',
    headers: buildHeaders(resolveTenantKey()),
  });
  if (!response.ok) {
    throw new Error('Failed to rotate API key');
  }
  return response.json();
}

async function revokeApiKey(id: string, reason?: string): Promise<void> {
  const response = await fetch(getApiUrl(`/api-keys/${id}/revoke`), {
    method: 'POST',
    headers: buildHeaders(resolveTenantKey()),
    body: JSON.stringify({ reason }),
  });
  if (!response.ok) {
    throw new Error('Failed to revoke API key');
  }
}

// ============== Components ==============

function StatusBadge({ isActive }: { isActive: boolean }) {
  if (isActive) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-green-100 text-green-700 rounded-full text-xs font-medium">
        <CheckCircle2 size={10} /> Active
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-gray-100 text-gray-600 rounded-full text-xs font-medium">
      <XCircle size={10} /> Inactive
    </span>
  );
}

function EnvBadge({ env }: { env: string }) {
  const colors = {
    live: 'bg-red-100 text-red-700',
    dev: 'bg-blue-100 text-blue-700',
    staging: 'bg-yellow-100 text-yellow-700',
  };
  return (
    <span className={`inline-flex px-2 py-0.5 rounded-full text-xs font-medium capitalize ${colors[env as keyof typeof colors] || 'bg-gray-100 text-gray-600'}`}>
      {env}
    </span>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      className="flex items-center gap-1 px-2 py-1 text-xs text-accent hover:bg-accent/10 rounded transition-colors"
    >
      {copied ? <Check size={12} /> : <Copy size={12} />}
      {copied ? 'Copied!' : 'Copy'}
    </button>
  );
}

// ============== Create Key Modal ==============

function CreateKeyModal({
  onClose,
  onSubmit,
  isLoading
}: {
  onClose: () => void;
  onSubmit: (data: CreateApiKeyRequest) => void;
  isLoading: boolean;
}) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [selectedScopes, setSelectedScopes] = useState<string[]>(['read', 'write']);
  const [expiresInDays, setExpiresInDays] = useState(90);
  const [env, setEnv] = useState('live');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const toggleScope = (scope: string) => {
    setSelectedScopes(prev =>
      prev.includes(scope)
        ? prev.filter(s => s !== scope)
        : [...prev, scope]
    );
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({
      name: name || 'API Key',
      description: description || undefined,
      scopes: selectedScopes,
      expiresInDays,
      env,
    });
  };

  return (
    <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-white rounded-xl max-w-lg w-full p-6 max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-6">
          <h2 className="font-semibold text-lg text-ink">Create New API Key</h2>
          <button onClick={onClose} className="p-1 hover:bg-gray-100 rounded">
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Key Name</label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="My API Key"
              className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-ink mb-1">Description (optional)</label>
            <input
              type="text"
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="Description for this key"
              className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-ink mb-2">Environment</label>
            <div className="flex gap-2">
              {ENV_OPTIONS.map(option => (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => setEnv(option.value)}
                  className={`flex-1 px-3 py-2 rounded-lg text-sm font-medium border transition-colors ${
                    env === option.value
                      ? 'bg-accent text-white border-accent'
                      : 'border-gray-200 text-muted hover:border-accent'
                  }`}
                >
                  {option.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-ink mb-2">Expiration</label>
            <select
              value={expiresInDays}
              onChange={e => setExpiresInDays(Number(e.target.value))}
              className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
            >
              {EXPIRY_OPTIONS.map(option => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-ink mb-2">Scopes</label>
            <div className="grid grid-cols-2 gap-2">
              {SCOPE_OPTIONS.map(scope => (
                <button
                  key={scope.value}
                  type="button"
                  onClick={() => toggleScope(scope.value)}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm border transition-colors text-left ${
                    selectedScopes.includes(scope.value)
                      ? 'bg-accent/10 border-accent text-accent'
                      : 'border-gray-200 text-muted hover:border-gray-300'
                  }`}
                >
                  <div className={`w-4 h-4 rounded border flex items-center justify-center ${
                    selectedScopes.includes(scope.value) ? 'bg-accent border-accent' : 'border-gray-300'
                  }`}>
                    {selectedScopes.includes(scope.value) && <Check size={10} className="text-white" />}
                  </div>
                  {scope.label}
                </button>
              ))}
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-accent text-white rounded-lg font-medium text-sm hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isLoading ? (
              <RefreshCw size={16} className="animate-spin" />
            ) : (
              <Plus size={16} />
            )}
            {isLoading ? 'Creating...' : 'Create API Key'}
          </button>
        </form>
      </div>
    </div>
  );
}

// ============== Key Details Modal ==============

function KeyDetailsModal({
  key: apiKey,
  newKey,
  onClose
}: {
  key: ApiKey | null;
  newKey: NewKeyCreated | null;
  onClose: () => void;
}) {
  const [showSecret, setShowSecret] = useState(false);
  const [copiedPublishable, setCopiedPublishable] = useState(false);
  const [copiedSecret, setCopiedSecret] = useState(false);

  const copyPublishable = async () => {
    if (newKey) {
      await navigator.clipboard.writeText(newKey.publishableKey);
      setCopiedPublishable(true);
      setTimeout(() => setCopiedPublishable(false), 2000);
    }
  };

  const copySecret = async () => {
    if (newKey) {
      await navigator.clipboard.writeText(newKey.secretKey);
      setCopiedSecret(true);
      setTimeout(() => setCopiedSecret(false), 2000);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-white rounded-xl max-w-lg w-full p-6" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-6">
          <h2 className="font-semibold text-lg text-ink">
            {newKey ? 'API Key Created' : 'API Key Details'}
          </h2>
          <button onClick={onClose} className="p-1 hover:bg-gray-100 rounded">
            <X size={18} />
          </button>
        </div>

        {newKey ? (
          <>
            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
              <div className="flex items-start gap-3">
                <AlertTriangle className="text-yellow-600 flex-shrink-0 mt-0.5" size={18} />
                <div>
                  <p className="font-medium text-yellow-800 text-sm">Save your secret key</p>
                  <p className="text-yellow-700 text-xs mt-1">
                    This is the only time you will see the secret key. Copy it and store it securely.
                  </p>
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-ink mb-1">Publishable Key</label>
                <div className="flex items-center gap-2">
                  <code className="flex-1 px-3 py-2 bg-gray-50 border border-gray-200 rounded text-xs font-mono text-muted truncate">
                    {newKey.publishableKey}
                  </code>
                  <button
                    onClick={copyPublishable}
                    className="flex items-center gap-1 px-2 py-1.5 text-xs text-accent hover:bg-accent/10 rounded transition-colors"
                  >
                    {copiedPublishable ? <Check size={12} /> : <Copy size={12} />}
                    {copiedPublishable ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-ink mb-1">Secret Key</label>
                <div className="flex items-center gap-2">
                  <code className="flex-1 px-3 py-2 bg-gray-50 border border-gray-200 rounded text-xs font-mono text-muted truncate">
                    {showSecret ? newKey.secretKey : '••••••••••••••••••••••••••••••••'}
                  </code>
                  <button
                    onClick={() => setShowSecret(!showSecret)}
                    className="p-1.5 text-muted hover:text-ink rounded transition-colors"
                  >
                    {showSecret ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                  <button
                    onClick={copySecret}
                    className="flex items-center gap-1 px-2 py-1.5 text-xs text-accent hover:bg-accent/10 rounded transition-colors"
                  >
                    {copiedSecret ? <Check size={12} /> : <Copy size={12} />}
                    {copiedSecret ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>

              <div className="pt-4 border-t border-gray-200">
                <p className="text-xs text-muted">
                  Key name: <span className="text-ink font-medium">{newKey.keyName}</span>
                </p>
              </div>
            </div>
          </>
        ) : apiKey ? (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-muted">Name</p>
                <p className="font-medium text-ink">{apiKey.metadata?.name || 'Unnamed'}</p>
              </div>
              <div>
                <p className="text-sm text-muted">Status</p>
                <StatusBadge isActive={apiKey.isActive} />
              </div>
              <div>
                <p className="text-sm text-muted">Environment</p>
                <EnvBadge env={apiKey.env} />
              </div>
              <div>
                <p className="text-sm text-muted">Rate Limit</p>
                <p className="text-ink">{apiKey.rateLimit} req/min</p>
              </div>
              <div>
                <p className="text-sm text-muted">Created</p>
                <p className="text-ink">{new Date(apiKey.createdAt).toLocaleDateString()}</p>
              </div>
              <div>
                <p className="text-sm text-muted">Expires</p>
                <p className="text-ink">{new Date(apiKey.expiresAt).toLocaleDateString()}</p>
              </div>
            </div>

            <div>
              <p className="text-sm text-muted mb-2">Scopes</p>
              <div className="flex flex-wrap gap-1">
                {apiKey.scopes.map(scope => (
                  <span key={scope} className="px-2 py-0.5 bg-gray-100 text-gray-700 rounded text-xs">
                    {scope}
                  </span>
                ))}
              </div>
            </div>

            {apiKey.metadata?.description && (
              <div>
                <p className="text-sm text-muted">Description</p>
                <p className="text-ink">{apiKey.metadata.description}</p>
              </div>
            )}

            {apiKey.metadata?.lastUsedAt && (
              <div>
                <p className="text-sm text-muted">Last Used</p>
                <p className="text-ink">{timeAgo(apiKey.metadata.lastUsedAt)}</p>
              </div>
            )}
          </div>
        ) : null}

        <div className="mt-6 pt-4 border-t border-gray-200">
          <button
            onClick={onClose}
            className="w-full px-4 py-2 border border-gray-200 rounded-lg text-sm font-medium text-ink hover:bg-gray-50"
          >
            {newKey ? 'I have saved my keys' : 'Close'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ============== Confirm Dialog ==============

function ConfirmDialog({
  title,
  message,
  confirmLabel,
  onConfirm,
  onCancel,
  isLoading,
  variant = 'danger'
}: {
  title: string;
  message: string;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
  isLoading?: boolean;
  variant?: 'danger' | 'warning';
}) {
  return (
    <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4" onClick={onCancel}>
      <div className="bg-white rounded-xl max-w-md w-full p-6" onClick={e => e.stopPropagation()}>
        <div className="flex items-start gap-4">
          <div className={`w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0 ${
            variant === 'danger' ? 'bg-red-100' : 'bg-yellow-100'
          }`}>
            {variant === 'danger' ? (
              <Trash2 className="text-red-600" size={20} />
            ) : (
              <RefreshCw className="text-yellow-600" size={20} />
            )}
          </div>
          <div>
            <h3 className="font-semibold text-ink">{title}</h3>
            <p className="text-sm text-muted mt-1">{message}</p>
          </div>
        </div>
        <div className="flex gap-3 mt-6">
          <button
            onClick={onCancel}
            className="flex-1 px-4 py-2 border border-gray-200 rounded-lg text-sm font-medium text-ink hover:bg-gray-50"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={isLoading}
            className={`flex-1 px-4 py-2 rounded-lg text-sm font-medium text-white ${
              variant === 'danger' ? 'bg-red-600 hover:bg-red-700' : 'bg-yellow-600 hover:bg-yellow-700'
            } disabled:opacity-50`}
          >
            {isLoading ? <RefreshCw size={16} className="animate-spin mx-auto" /> : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

// ============== Main Component ==============

export default function ApiKeysPage() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedKey, setSelectedKey] = useState<ApiKey | null>(null);
  const [newKeyCreated, setNewKeyCreated] = useState<NewKeyCreated | null>(null);
  const [keyToRevoke, setKeyToRevoke] = useState<ApiKey | null>(null);
  const [keyToRotate, setKeyToRotate] = useState<ApiKey | null>(null);

  // Fetch API keys
  const { data: apiKeys = [], isLoading, error } = useQuery({
    queryKey: ['api-keys'],
    queryFn: fetchApiKeys,
  });

  // Create mutation
  const createMutation = useMutation({
    mutationFn: createApiKey,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] });
      setShowCreateModal(false);
      setNewKeyCreated({
        publishableKey: data.publishableKey,
        secretKey: data.secretKey,
        keyName: data.apiKey.metadata?.name || 'API Key',
      });
      setSelectedKey(data.apiKey);
    },
    onError: (error) => {
      alert(`Failed to create API key: ${error.message}`);
    },
  });

  // Rotate mutation
  const rotateMutation = useMutation({
    mutationFn: (id: string) => rotateApiKey(id),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] });
      setKeyToRotate(null);
      setNewKeyCreated({
        publishableKey: data.publishableKey,
        secretKey: data.secretKey,
        keyName: data.apiKey.metadata?.name || 'API Key (Rotated)',
      });
      setSelectedKey(data.apiKey);
    },
    onError: (error) => {
      alert(`Failed to rotate API key: ${error.message}`);
    },
  });

  // Revoke mutation
  const revokeMutation = useMutation({
    mutationFn: (id: string) => revokeApiKey(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] });
      setKeyToRevoke(null);
    },
    onError: (error) => {
      alert(`Failed to revoke API key: ${error.message}`);
    },
  });

  // Filter by search
  const filteredKeys = apiKeys.filter(key => {
    const name = key.metadata?.name || '';
    const ulid = key.ulid || '';
    return !search || name.toLowerCase().includes(search.toLowerCase()) || ulid.includes(search);
  });

  const activeKeys = apiKeys.filter(k => k.isActive).length;
  const expiredKeys = apiKeys.filter(k => !k.isActive).length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">API Keys</h1>
          <p className="text-muted text-sm mt-1">Manage your API keys for programmatic access</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-accent text-white rounded-lg font-medium text-sm hover:bg-accent/90"
        >
          <Plus size={16} />
          Create API Key
        </button>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <div className="flex items-center gap-2">
            <Key className="text-accent" size={16} />
            <p className="text-sm text-muted">Total Keys</p>
          </div>
          <p className="text-2xl font-semibold text-ink mt-1">{apiKeys.length}</p>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="text-green-600" size={16} />
            <p className="text-sm text-muted">Active</p>
          </div>
          <p className="text-2xl font-semibold text-green-600 mt-1">{activeKeys}</p>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <div className="flex items-center gap-2">
            <Clock className="text-gray-500" size={16} />
            <p className="text-sm text-muted">Inactive/Expired</p>
          </div>
          <p className="text-2xl font-semibold text-gray-600 mt-1">{expiredKeys}</p>
        </div>
      </div>

      {/* Search */}
      <div className="relative max-w-md">
        <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
        <input
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search by name or ID..."
          className="w-full pl-9 pr-4 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
        />
      </div>

      {/* Keys list */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="animate-spin text-accent" size={24} />
          <span className="ml-2 text-muted">Loading API keys...</span>
        </div>
      ) : error ? (
        <div className="flex items-center justify-center py-12 text-red-600">
          <AlertTriangle size={20} />
          <span className="ml-2">Failed to load API keys</span>
        </div>
      ) : filteredKeys.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <Key className="text-gray-300" size={48} />
          <p className="text-muted mt-4">No API keys found</p>
          <button
            onClick={() => setShowCreateModal(true)}
            className="mt-2 text-accent hover:underline text-sm"
          >
            Create your first API key
          </button>
        </div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200 bg-gray-50">
                <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Name</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Key ID</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Environment</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Status</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Created</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Expires</th>
                <th className="w-32"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {filteredKeys.map(key => (
                <tr key={key.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Key size={14} className="text-muted" />
                      <span className="font-medium text-ink text-sm">{key.metadata?.name || 'Unnamed'}</span>
                    </div>
                    {key.metadata?.description && (
                      <p className="text-xs text-muted mt-0.5 truncate max-w-[200px]">{key.metadata.description}</p>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <code className="text-xs font-mono text-muted">{key.ulid}</code>
                  </td>
                  <td className="px-4 py-3">
                    <EnvBadge env={key.env} />
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge isActive={key.isActive} />
                  </td>
                  <td className="px-4 py-3 text-xs text-muted">
                    {new Date(key.createdAt).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3 text-xs text-muted">
                    {new Date(key.expiresAt).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => setSelectedKey(key)}
                        className="p-1.5 text-muted hover:text-ink hover:bg-gray-100 rounded"
                        title="View details"
                      >
                        <Eye size={14} />
                      </button>
                      <button
                        onClick={() => setKeyToRotate(key)}
                        className="p-1.5 text-muted hover:text-accent hover:bg-accent/10 rounded"
                        title="Rotate key"
                        disabled={!key.isActive}
                      >
                        <RefreshCw size={14} />
                      </button>
                      <button
                        onClick={() => setKeyToRevoke(key)}
                        className="p-1.5 text-muted hover:text-red-600 hover:bg-red-10 rounded"
                        title="Revoke key"
                        disabled={!key.isActive}
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Modals */}
      {showCreateModal && (
        <CreateKeyModal
          onClose={() => setShowCreateModal(false)}
          onSubmit={(data) => createMutation.mutate(data)}
          isLoading={createMutation.isPending}
        />
      )}

      {(selectedKey || newKeyCreated) && (
        <KeyDetailsModal
          key={selectedKey}
          newKey={newKeyCreated}
          onClose={() => {
            setSelectedKey(null);
            setNewKeyCreated(null);
          }}
        />
      )}

      {keyToRevoke && (
        <ConfirmDialog
          title="Revoke API Key"
          message={`Are you sure you want to revoke "${keyToRevoke.metadata?.name || keyToRevoke.ulid}"? This action cannot be undone and all applications using this key will lose access.`}
          confirmLabel="Revoke Key"
          onConfirm={() => revokeMutation.mutate(keyToRevoke.id)}
          onCancel={() => setKeyToRevoke(null)}
          isLoading={revokeMutation.isPending}
          variant="danger"
        />
      )}

      {keyToRotate && (
        <ConfirmDialog
          title="Rotate API Key"
          message={`Are you sure you want to rotate "${keyToRotate.metadata?.name || keyToRotate.ulid}"? A new key will be generated and the old one will be revoked.`}
          confirmLabel="Rotate Key"
          onConfirm={() => rotateMutation.mutate(keyToRotate.id)}
          onCancel={() => setKeyToRotate(null)}
          isLoading={rotateMutation.isPending}
          variant="warning"
        />
      )}
    </div>
  );
}