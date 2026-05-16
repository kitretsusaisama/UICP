'use client';

import { useState, useEffect } from 'react';
import { Settings, User, Shield, Bell, Palette, Key, Trash2, Download, Plus, RotateCw, Eye, EyeOff, Copy, Check, AlertTriangle, X } from 'lucide-react';
import { apiKeyService, ApiKeyResponse, ApiKeyScope } from '@/services/api-key.service';

type Tab = 'profile' | 'security' | 'api-keys' | 'notifications' | 'preferences';

// Scope options for creating API keys
const SCOPE_OPTIONS: { value: ApiKeyScope; label: string }[] = [
  { value: 'read', label: 'Read' },
  { value: 'write', label: 'Write' },
  { value: 'admin', label: 'Admin' },
  { value: 'identity:read', label: 'Identity Read' },
  { value: 'identity:write', label: 'Identity Write' },
  { value: 'identity:admin', label: 'Identity Admin' },
  { value: 'tenant:read', label: 'Tenant Read' },
  { value: 'tenant:write', label: 'Tenant Write' },
  { value: 'tenant:admin', label: 'Tenant Admin' },
  { value: 'api:read', label: 'API Read' },
  { value: 'api:write', label: 'API Write' },
  { value: 'api:admin', label: 'API Admin' },
  { value: 'resource:read', label: 'Resource Read' },
  { value: 'resource:write', label: 'Resource Write' },
  { value: 'resource:delete', label: 'Resource Delete' },
];

// Expiration options
const EXPIRATION_OPTIONS = [
  { value: 7, label: '7 days' },
  { value: 30, label: '30 days' },
  { value: 60, label: '60 days' },
  { value: 90, label: '90 days' },
  { value: 180, label: '6 months' },
  { value: 365, label: '1 year' },
  { value: 730, label: '2 years' },
];

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<Tab>('profile');
  const [apiKeys, setApiKeys] = useState<ApiKeyResponse[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showSecretModal, setShowSecretModal] = useState(false);
  const [newKeyData, setNewKeyData] = useState<{ name: string; secretKey: string } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [confirmRotate, setConfirmRotate] = useState<string | null>(null);
  const [rotatedKeyData, setRotatedKeyData] = useState<{ name: string; secretKey: string } | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [showSecretId, setShowSecretId] = useState<string | null>(null);

  // Form state
  const [keyName, setKeyName] = useState('');
  const [keyScopes, setKeyScopes] = useState<ApiKeyScope[]>(['read']);
  const [keyExpiresIn, setKeyExpiresIn] = useState(30);
  const [keyScopeError, setKeyScopeError] = useState('');

  // Fetch API keys when tab is active
  useEffect(() => {
    if (activeTab === 'api-keys') {
      fetchApiKeys();
    }
  }, [activeTab]);

  const fetchApiKeys = async () => {
    setIsLoading(true);
    try {
      const response = await apiKeyService.list();
      setApiKeys(response.data || []);
    } catch (error) {
      console.error('Failed to fetch API keys:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreateKey = async () => {
    if (keyScopes.length === 0) {
      setKeyScopeError('Please select at least one scope');
      return;
    }
    setKeyScopeError('');

    try {
      const response = await apiKeyService.create({
        name: keyName || undefined,
        scopes: keyScopes,
        expiresInDays: keyExpiresIn,
      });
      setNewKeyData({ name: keyName || 'Unnamed Key', secretKey: response.secretKey });
      setShowCreateModal(false);
      setShowSecretModal(true);
      setKeyName('');
      setKeyScopes(['read']);
      setKeyExpiresIn(30);
      fetchApiKeys();
    } catch (error) {
      console.error('Failed to create API key:', error);
      alert('Failed to create API key. Please try again.');
    }
  };

  const handleRotateKey = async (id: string) => {
    try {
      const response = await apiKeyService.rotate(id);
      const key = apiKeys.find(k => k.id === id);
      setRotatedKeyData({ name: key?.metadata?.name as string || 'Rotated Key', secretKey: response.secretKey });
      setConfirmRotate(null);
      setShowSecretModal(true);
      fetchApiKeys();
    } catch (error) {
      console.error('Failed to rotate API key:', error);
      alert('Failed to rotate API key. Please try again.');
    }
  };

  const handleRevokeKey = async (id: string) => {
    try {
      await apiKeyService.revoke(id);
      setConfirmDelete(null);
      fetchApiKeys();
    } catch (error) {
      console.error('Failed to revoke API key:', error);
      alert('Failed to revoke API key. Please try again.');
    }
  };

  const toggleScope = (scope: ApiKeyScope) => {
    setKeyScopes(prev =>
      prev.includes(scope)
        ? prev.filter(s => s !== scope)
        : [...prev, scope]
    );
  };

  const copyToClipboard = async (text: string, id: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'Never';
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  const tabs = [
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'api-keys', label: 'API Keys', icon: Key },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'preferences', label: 'Preferences', icon: Palette },
  ] as const;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-ink">Settings</h1>
        <p className="text-muted text-sm mt-1">Manage your profile, security, and preferences</p>
      </div>

      <div className="flex flex-col lg:flex-row gap-6">
        {/* Sidebar tabs */}
        <div className="lg:w-56 flex-shrink-0">
          <div className="bg-white rounded-xl border border-gray-200 p-2">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                    activeTab === tab.id ? 'bg-accent text-white' : 'text-muted hover:text-ink hover:bg-gray-50'
                  }`}
                >
                  <Icon size={16} />
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Content */}
        <div className="flex-1">
          {activeTab === 'profile' && (
            <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-6">
              <h2 className="font-semibold text-ink">Profile Information</h2>
              <div className="flex items-center gap-4 mb-6">
                <div className="w-16 h-16 bg-accent/10 rounded-full flex items-center justify-center">
                  <span className="text-accent font-semibold text-xl">V</span>
                </div>
                <div>
                  <p className="font-medium text-ink">Victor Amit</p>
                  <p className="text-sm text-muted">Super Admin</p>
                </div>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-ink mb-1">Display name</label>
                  <input type="text" defaultValue="Victor Amit" className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-ink mb-1">Email</label>
                  <input type="email" defaultValue="victor@uicp.com" className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-ink mb-1">Phone</label>
                  <input type="tel" defaultValue="+1 555 000 0000" className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-ink mb-1">Role</label>
                  <input type="text" defaultValue="super_admin" disabled className="w-full px-3 py-2 border border-gray-100 rounded-lg text-sm bg-gray-50 text-muted" />
                </div>
              </div>
              <div className="flex justify-end">
                <button className="px-4 py-2 bg-accent text-white rounded-lg text-sm font-medium hover:bg-accent/90">Save changes</button>
              </div>
            </div>
          )}

          {activeTab === 'security' && (
            <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-6">
              <h2 className="font-semibold text-ink">Security Settings</h2>

              <div className="space-y-4">
                <div className="flex items-center justify-between py-3 border-b border-gray-100">
                  <div>
                    <p className="font-medium text-ink">Password</p>
                    <p className="text-sm text-muted">Last changed 30 days ago</p>
                  </div>
                  <button className="px-3 py-1.5 border border-gray-200 rounded-lg text-sm hover:bg-gray-50">Change</button>
                </div>
                <div className="flex items-center justify-between py-3 border-b border-gray-100">
                  <div>
                    <p className="font-medium text-ink">Two-factor authentication</p>
                    <p className="text-sm text-muted">Not enabled</p>
                  </div>
                  <button className="px-3 py-1.5 bg-accent text-white rounded-lg text-sm hover:bg-accent/90">Enable</button>
                </div>
                <div className="flex items-center justify-between py-3 border-b border-gray-100">
                  <div>
                    <p className="font-medium text-ink">Active sessions</p>
                    <p className="text-sm text-muted">3 devices logged in</p>
                  </div>
                  <button className="px-3 py-1.5 border border-gray-200 rounded-lg text-sm hover:bg-gray-50">View all</button>
                </div>
                <div className="flex items-center justify-between py-3">
                  <div>
                    <p className="font-medium text-ink">API keys</p>
                    <p className="text-sm text-muted">Manage API access tokens</p>
                  </div>
                  <button className="px-3 py-1.5 border border-gray-200 rounded-lg text-sm hover:bg-gray-50">Manage</button>
                </div>
              </div>

              <div className="pt-4 border-t border-gray-200">
                <h3 className="font-semibold text-ink mb-3">Danger zone</h3>
                <div className="flex items-center justify-between p-4 bg-red-50 rounded-lg">
                  <div>
                    <p className="font-medium text-ink">Delete account</p>
                    <p className="text-sm text-muted">Permanently remove your account and all data</p>
                  </div>
                  <button className="px-3 py-1.5 bg-red-600 text-white rounded-lg text-sm hover:bg-red-700">Delete account</button>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'api-keys' && (
            <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="font-semibold text-ink">API Keys</h2>
                  <p className="text-sm text-muted mt-1">Manage your personal API keys for programmatic access</p>
                </div>
                <button
                  onClick={() => setShowCreateModal(true)}
                  className="flex items-center gap-2 px-4 py-2 bg-accent text-white rounded-lg text-sm font-medium hover:bg-accent/90"
                >
                  <Plus size={16} />
                  Create Key
                </button>
              </div>

              {isLoading ? (
                <div className="flex items-center justify-center py-12">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-accent"></div>
                </div>
              ) : apiKeys.length === 0 ? (
                <div className="text-center py-12">
                  <div className="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <Key size={24} className="text-muted" />
                  </div>
                  <h3 className="font-medium text-ink mb-2">No API keys yet</h3>
                  <p className="text-sm text-muted mb-4">Create your first API key to get started</p>
                  <button
                    onClick={() => setShowCreateModal(true)}
                    className="inline-flex items-center gap-2 px-4 py-2 border border-gray-200 rounded-lg text-sm hover:bg-gray-50"
                  >
                    <Plus size={16} />
                    Create API Key
                  </button>
                </div>
              ) : (
                <div className="space-y-4">
                  {apiKeys.map((key) => (
                    <div key={key.id} className={`p-4 border rounded-lg ${key.isActive ? 'border-gray-200' : 'border-red-200 bg-red-50'}`}>
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <p className="font-medium text-ink">{(key.metadata?.name as string) || 'Unnamed Key'}</p>
                            <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${key.isActive ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                              {key.isActive ? 'Active' : 'Revoked'}
                            </span>
                            <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600">
                              {key.env}
                            </span>
                          </div>
                          <div className="flex flex-wrap gap-1 mb-3">
                            {key.scopes.map((scope) => (
                              <span key={scope} className="px-2 py-0.5 bg-accent/10 text-accent text-xs rounded">
                                {scope}
                              </span>
                            ))}
                          </div>
                          <div className="flex flex-wrap gap-x-6 gap-y-2 text-sm text-muted">
                            <span>ID: {key.ulid.slice(0, 8)}...</span>
                            <span>Created: {formatDate(key.createdAt)}</span>
                            <span>Expires: {formatDate(key.expiresAt)}</span>
                            <span>Rate limit: {key.rateLimit}/min</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 ml-4">
                          {key.isActive && (
                            <>
                              <button
                                onClick={() => setConfirmRotate(key.id)}
                                className="p-2 text-muted hover:text-ink hover:bg-gray-100 rounded-lg"
                                title="Rotate key"
                              >
                                <RotateCw size={16} />
                              </button>
                              <button
                                onClick={() => setConfirmDelete(key.id)}
                                className="p-2 text-muted hover:text-red-600 hover:bg-red-50 rounded-lg"
                                title="Revoke key"
                              >
                                <Trash2 size={16} />
                              </button>
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'notifications' && (
            <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-6">
              <h2 className="font-semibold text-ink">Notification Preferences</h2>
              {[
                { label: 'Login alerts', desc: 'Get notified when a new login occurs', enabled: true },
                { label: 'Security threats', desc: 'Immediate alerts for detected threats', enabled: true },
                { label: 'Provider failures', desc: 'Notify when a provider goes down', enabled: true },
                { label: 'Weekly report', desc: 'Summary of platform activity', enabled: false },
                { label: 'Marketing emails', desc: 'Product updates and announcements', enabled: false },
              ].map((item, i) => (
                <div key={i} className="flex items-center justify-between py-3 border-b border-gray-100 last:border-0">
                  <div>
                    <p className="font-medium text-ink">{item.label}</p>
                    <p className="text-sm text-muted">{item.desc}</p>
                  </div>
                  <button className={`w-10 h-6 rounded-full transition-colors ${item.enabled ? 'bg-accent' : 'bg-gray-200'}`}>
                    <div className={`w-4 h-4 bg-white rounded-full shadow mx-1 transition-transform ${item.enabled ? 'translate-x-4' : ''}`} />
                  </button>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'preferences' && (
            <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-6">
              <h2 className="font-semibold text-ink">Preferences</h2>
              <div>
                <label className="block text-sm font-medium text-ink mb-1">Language</label>
                <select className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20">
                  <option>English</option>
                  <option>Spanish</option>
                  <option>French</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-ink mb-1">Timezone</label>
                <select className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20">
                  <option>UTC</option>
                  <option>America/New_York</option>
                  <option>Europe/London</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-ink mb-1">Date format</label>
                <select className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20">
                  <option>MM/DD/YYYY</option>
                  <option>DD/MM/YYYY</option>
                  <option>YYYY-MM-DD</option>
                </select>
              </div>
              <div className="flex justify-end">
                <button className="px-4 py-2 bg-accent text-white rounded-lg text-sm font-medium hover:bg-accent/90">Save preferences</button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Create API Key Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-ink text-lg">Create API Key</h3>
              <button onClick={() => setShowCreateModal(false)} className="text-muted hover:text-ink">
                <X size={20} />
              </button>
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Name (optional)</label>
              <input
                type="text"
                value={keyName}
                onChange={(e) => setKeyName(e.target.value)}
                placeholder="My API Key"
                className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-2">Scopes (select at least one)</label>
              {keyScopeError && <p className="text-red-500 text-sm mb-2">{keyScopeError}</p>}
              <div className="grid grid-cols-2 gap-2 max-h-48 overflow-y-auto p-2 border border-gray-100 rounded-lg">
                {SCOPE_OPTIONS.map((scope) => (
                  <label key={scope.value} className="flex items-center gap-2 text-sm cursor-pointer">
                    <input
                      type="checkbox"
                      checked={keyScopes.includes(scope.value)}
                      onChange={() => toggleScope(scope.value)}
                      className="rounded border-gray-300 text-accent focus:ring-accent"
                    />
                    {scope.label}
                  </label>
                ))}
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Expires after</label>
              <select
                value={keyExpiresIn}
                onChange={(e) => setKeyExpiresIn(Number(e.target.value))}
                className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20"
              >
                {EXPIRATION_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
            </div>
            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setShowCreateModal(false)}
                className="px-4 py-2 border border-gray-200 rounded-lg text-sm hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateKey}
                className="px-4 py-2 bg-accent text-white rounded-lg text-sm font-medium hover:bg-accent/90"
              >
                Create Key
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Show Secret Key Modal - Only shown once at creation/rotation */}
      {showSecretModal && newKeyData && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md p-6 space-y-4">
            <div className="flex items-center gap-3 p-3 bg-amber-50 border border-amber-200 rounded-lg">
              <AlertTriangle className="text-amber-600 flex-shrink-0" size={20} />
              <div>
                <p className="font-medium text-amber-800 text-sm">Save this secret key now</p>
                <p className="text-amber-700 text-xs">This is the only time you'll see it. Copy it and store it securely.</p>
              </div>
            </div>
            <div>
              <p className="text-sm text-muted mb-1">Key Name</p>
              <p className="font-medium text-ink">{newKeyData.name}</p>
            </div>
            <div>
              <p className="text-sm text-muted mb-1">Secret Key</p>
              <div className="flex items-center gap-2">
                <code className="flex-1 px-3 py-2 bg-gray-100 rounded-lg text-sm font-mono break-all">
                  {newKeyData.secretKey}
                </code>
                <button
                  onClick={() => copyToClipboard(newKeyData.secretKey, 'secret')}
                  className="p-2 hover:bg-gray-100 rounded-lg"
                  title="Copy to clipboard"
                >
                  {copiedId === 'secret' ? <Check size={16} className="text-green-600" /> : <Copy size={16} />}
                </button>
              </div>
            </div>
            <div className="flex justify-end">
              <button
                onClick={() => {
                  setShowSecretModal(false);
                  setNewKeyData(null);
                  setRotatedKeyData(null);
                }}
                className="px-4 py-2 bg-accent text-white rounded-lg text-sm font-medium hover:bg-accent/90"
              >
                I've saved the key
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirm Revoke Dialog */}
      {confirmDelete && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-sm p-6 space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-red-100 rounded-full flex items-center justify-center">
                <AlertTriangle className="text-red-600" size={20} />
              </div>
              <div>
                <h3 className="font-semibold text-ink">Revoke API Key?</h3>
                <p className="text-sm text-muted">This action cannot be undone.</p>
              </div>
            </div>
            <p className="text-sm text-muted">
              Any applications using this key will lose access immediately. The key will be permanently deleted.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setConfirmDelete(null)}
                className="px-4 py-2 border border-gray-200 rounded-lg text-sm hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={() => handleRevokeKey(confirmDelete)}
                className="px-4 py-2 bg-red-600 text-white rounded-lg text-sm font-medium hover:bg-red-700"
              >
                Revoke Key
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirm Rotate Dialog */}
      {confirmRotate && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-sm p-6 space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-amber-100 rounded-full flex items-center justify-center">
                <RotateCw className="text-amber-600" size={20} />
              </div>
              <div>
                <h3 className="font-semibold text-ink">Rotate API Key?</h3>
                <p className="text-sm text-muted">This will create a new key and revoke the old one.</p>
              </div>
            </div>
            <p className="text-sm text-muted">
              The old key will stop working immediately. Make sure to update any applications using the old key with the new secret.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setConfirmRotate(null)}
                className="px-4 py-2 border border-gray-200 rounded-lg text-sm hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={() => handleRotateKey(confirmRotate)}
                className="px-4 py-2 bg-accent text-white rounded-lg text-sm font-medium hover:bg-accent/90"
              >
                Rotate Key
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}