'use client';

import { useState, useMemo } from 'react';
import {
  Search, Plus, MoreHorizontal, Trash2, Edit2, Play, X, Check,
  ChevronDown, ChevronRight, AlertCircle, CheckCircle2, Info
} from 'lucide-react';
import { governanceService, type Policy, type PolicyRule, type PolicyCondition, type PolicyType, type PolicyStatus, type TestPolicyRequest } from '@/services/governance.service';

// Mock data for demonstration
const MOCK_POLICIES: Policy[] = [
  {
    id: '1',
    name: 'Admin Full Access',
    description: 'Full administrative access to all resources',
    type: 'allow',
    status: 'active',
    effect: { type: 'allow', priority: 100 },
    rules: [
      { actions: ['*'], resources: ['*'], conditions: [] }
    ],
    tenantId: 't1',
    createdAt: '2024-01-15T10:00:00Z',
    updatedAt: '2024-01-15T10:00:00Z',
    createdBy: 'admin@uicp.com'
  },
  {
    id: '2',
    name: 'Read-Only Users',
    description: 'Users can only read resources',
    type: 'allow',
    status: 'active',
    effect: { type: 'allow', priority: 50 },
    rules: [
      { actions: ['read'], resources: ['users', 'sessions', 'audit'], conditions: [] }
    ],
    tenantId: 't1',
    createdAt: '2024-02-20T10:00:00Z',
    updatedAt: '2024-02-20T10:00:00Z',
    createdBy: 'admin@uicp.com'
  },
  {
    id: '3',
    name: 'Deny External Access',
    description: 'Block access from external IP ranges',
    type: 'deny',
    status: 'active',
    effect: { type: 'deny', priority: 90 },
    rules: [
      { actions: ['*'], resources: ['*'], conditions: [{ field: 'ip_range', operator: 'in', value: ['external'] }] }
    ],
    tenantId: 't1',
    createdAt: '2024-03-10T10:00:00Z',
    updatedAt: '2024-03-10T10:00:00Z',
    createdBy: 'admin@uicp.com'
  },
  {
    id: '4',
    name: 'MFA Required',
    description: 'Require MFA for sensitive operations',
    type: 'allow',
    status: 'draft',
    effect: { type: 'allow', priority: 75 },
    rules: [
      { actions: ['delete', 'admin'], resources: ['*'], conditions: [{ field: 'mfa_verified', operator: 'eq', value: true }] }
    ],
    tenantId: 't1',
    createdAt: '2024-05-01T10:00:00Z',
    updatedAt: '2024-05-01T10:00:00Z',
    createdBy: 'admin@uicp.com'
  }
];

const STATUS_STYLES: Record<PolicyStatus, { bg: string; text: string; label: string }> = {
  active: { bg: 'bg-green-100', text: 'text-green-700', label: 'Active' },
  suspended: { bg: 'bg-yellow-100', text: 'text-yellow-700', label: 'Suspended' },
  draft: { bg: 'bg-gray-100', text: 'text-gray-700', label: 'Draft' }
};

const TYPE_STYLES: Record<PolicyType, { bg: string; text: string; label: string }> = {
  allow: { bg: 'bg-blue-100', text: 'text-blue-700', label: 'Allow' },
  deny: { bg: 'bg-red-100', text: 'text-red-700', label: 'Deny' }
};

const OPERATORS = [
  { value: 'eq', label: 'Equals (=)' },
  { value: 'neq', label: 'Not Equals (!=)' },
  { value: 'in', label: 'In' },
  { value: 'not_in', label: 'Not In' },
  { value: 'contains', label: 'Contains' },
  { value: 'regex', label: 'Regex' },
  { value: 'gt', label: 'Greater Than (>)' },
  { value: 'gte', label: 'Greater or Equal (>=)' },
  { value: 'lt', label: 'Less Than (<)' },
  { value: 'lte', label: 'Less or Equal (<=)' }
];

const COMMON_ACTIONS = ['create', 'read', 'update', 'delete', 'execute', 'admin', 'manage'];
const COMMON_RESOURCES = ['users', 'roles', 'policies', 'sessions', 'tenants', 'providers', 'audit', 'api_keys', '*'];
const COMMON_FIELDS = ['user.role', 'user.department', 'ip_range', 'mfa_verified', 'time_of_day', 'day_of_week', 'resource.type', 'resource.owner'];

interface PolicyFormData {
  name: string;
  description: string;
  type: PolicyType;
  status: PolicyStatus;
  rules: PolicyRule[];
}

const EMPTY_RULE: PolicyRule = {
  actions: [],
  resources: [],
  conditions: []
};

const EMPTY_CONDITION: PolicyCondition = {
  field: '',
  operator: 'eq',
  value: ''
};

function initialFormData(): PolicyFormData {
  return {
    name: '',
    description: '',
    type: 'allow',
    status: 'draft',
    rules: [{ ...EMPTY_RULE }]
  };
}

export default function PoliciesPage() {
  const [search, setSearch] = useState('');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [policies, setPolicies] = useState<Policy[]>(MOCK_POLICIES);

  // Modal states
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showTestModal, setShowTestModal] = useState(false);
  const [selectedPolicy, setSelectedPolicy] = useState<Policy | null>(null);
  const [formData, setFormData] = useState<PolicyFormData>(initialFormData());

  // Test modal state
  const [testContext, setTestContext] = useState<TestPolicyRequest>({
    action: '',
    resource: '',
    context: {}
  });
  const [testResult, setTestResult] = useState<{ allowed: boolean; matchedPolicies: string[] } | null>(null);
  const [testLoading, setTestLoading] = useState(false);

  const filteredPolicies = useMemo(() => {
    return policies.filter((p) => {
      const matchSearch = !search || p.name.toLowerCase().includes(search.toLowerCase()) || p.description?.toLowerCase().includes(search.toLowerCase());
      const matchStatus = selectedStatus === 'all' || p.status === selectedStatus;
      return matchSearch && matchStatus;
    });
  }, [policies, search, selectedStatus]);

  const handleCreatePolicy = () => {
    const newPolicy: Policy = {
      id: String(Date.now()),
      ...formData,
      effect: { type: formData.type, priority: formData.type === 'allow' ? 50 : 90 },
      tenantId: 't1',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      createdBy: 'admin@uicp.com'
    };
    setPolicies([...policies, newPolicy]);
    setShowCreateModal(false);
    setFormData(initialFormData());
  };

  const handleUpdatePolicy = () => {
    if (!selectedPolicy) return;
    setPolicies(policies.map(p => p.id === selectedPolicy.id ? {
      ...p,
      ...formData,
      updatedAt: new Date().toISOString()
    } : p));
    setShowEditModal(false);
    setSelectedPolicy(null);
    setFormData(initialFormData());
  };

  const handleDeletePolicy = (policyId: string) => {
    if (!confirm('Are you sure you want to delete this policy?')) return;
    setPolicies(policies.filter(p => p.id !== policyId));
  };

  const handleTestPolicy = async () => {
    setTestLoading(true);
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 500));
    // Simple mock test logic
    const matchedPolicies: string[] = [];
    let allowed = false;

    for (const policy of policies) {
      if (policy.status !== 'active') continue;
      if (policy.rules.some(rule => {
        const actionMatch = rule.actions.includes('*') || rule.actions.includes(testContext.action);
        const resourceMatch = rule.resources.includes('*') || rule.resources.includes(testContext.resource);
        return actionMatch && resourceMatch;
      })) {
        matchedPolicies.push(policy.name);
        if (policy.type === 'allow') allowed = true;
        else if (policy.type === 'deny') allowed = false;
      }
    }

    setTestResult({ allowed, matchedPolicies });
    setTestLoading(false);
  };

  const openEditModal = (policy: Policy) => {
    setSelectedPolicy(policy);
    setFormData({
      name: policy.name,
      description: policy.description || '',
      type: policy.type,
      status: policy.status,
      rules: policy.rules.length > 0 ? policy.rules : [{ ...EMPTY_RULE }]
    });
    setShowEditModal(true);
  };

  const openTestModal = (policy: Policy) => {
    setSelectedPolicy(policy);
    setTestContext({
      action: '',
      resource: '',
      context: {}
    });
    setTestResult(null);
    setShowTestModal(true);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">ABAC Policies</h1>
          <p className="text-muted text-sm mt-1">{filteredPolicies.length} policies found</p>
        </div>
        <button
          onClick={() => { setFormData(initialFormData()); setShowCreateModal(true); }}
          className="flex items-center gap-2 px-4 py-2 bg-accent text-white rounded-lg text-sm font-medium hover:bg-accent/90"
        >
          <Plus size={16} />
          Create Policy
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search policies..."
            className="w-full pl-9 pr-4 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
          />
        </div>
        <select
          value={selectedStatus}
          onChange={(e) => setSelectedStatus(e.target.value)}
          className="px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
        >
          <option value="all">All statuses</option>
          <option value="active">Active</option>
          <option value="suspended">Suspended</option>
          <option value="draft">Draft</option>
        </select>
      </div>

      {/* Policy List */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 bg-gray-50">
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Name</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Type</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Status</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Rules</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Updated</th>
              <th className="text-right px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {filteredPolicies.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-12 text-center text-muted">
                  No policies found. Create one to get started.
                </td>
              </tr>
            ) : (
              filteredPolicies.map((policy) => {
                const statusStyle = STATUS_STYLES[policy.status];
                const typeStyle = TYPE_STYLES[policy.type];
                return (
                  <tr key={policy.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3">
                      <div>
                        <p className="font-medium text-ink text-sm">{policy.name}</p>
                        {policy.description && <p className="text-xs text-muted mt-0.5">{policy.description}</p>}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${typeStyle.bg} ${typeStyle.text}`}>
                        {typeStyle.label}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${statusStyle.bg} ${statusStyle.text}`}>
                        {statusStyle.label}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {policy.rules.slice(0, 2).map((rule, i) => (
                          <span key={i} className="inline-flex items-center px-1.5 py-0.5 bg-gray-100 rounded text-xs text-muted">
                            {rule.actions.join(', ')} / {rule.resources.join(', ')}
                          </span>
                        ))}
                        {policy.rules.length > 2 && (
                          <span className="text-xs text-muted">+{policy.rules.length - 2} more</span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-muted">
                      {new Date(policy.updatedAt).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => openTestModal(policy)}
                          className="p-1.5 text-muted hover:text-accent rounded hover:bg-accent/10"
                          title="Test Policy"
                        >
                          <Play size={14} />
                        </button>
                        <button
                          onClick={() => openEditModal(policy)}
                          className="p-1.5 text-muted hover:text-ink rounded hover:bg-gray-100"
                          title="Edit"
                        >
                          <Edit2 size={14} />
                        </button>
                        <button
                          onClick={() => handleDeletePolicy(policy.id)}
                          className="p-1.5 text-muted hover:text-danger rounded hover:bg-red-50"
                          title="Delete"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <PolicyModal
          title="Create Policy"
          formData={formData}
          setFormData={setFormData}
          onSubmit={handleCreatePolicy}
          onClose={() => setShowCreateModal(false)}
          submitLabel="Create Policy"
        />
      )}

      {/* Edit Modal */}
      {showEditModal && (
        <PolicyModal
          title="Edit Policy"
          formData={formData}
          setFormData={setFormData}
          onSubmit={handleUpdatePolicy}
          onClose={() => { setShowEditModal(false); setSelectedPolicy(null); }}
          submitLabel="Save Changes"
        />
      )}

      {/* Test Modal */}
      {showTestModal && selectedPolicy && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl max-w-lg w-full max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between p-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-ink">Test Policy: {selectedPolicy.name}</h2>
              <button onClick={() => { setShowTestModal(false); setSelectedPolicy(null); }} className="text-muted hover:text-ink">
                <X size={20} />
              </button>
            </div>
            <div className="p-4 space-y-4">
              <div>
                <label className="block text-sm font-medium text-ink mb-1">Action</label>
                <select
                  value={testContext.action}
                  onChange={(e) => setTestContext({ ...testContext, action: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20"
                >
                  <option value="">Select action...</option>
                  {COMMON_ACTIONS.map(a => <option key={a} value={a}>{a}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-ink mb-1">Resource</label>
                <select
                  value={testContext.resource}
                  onChange={(e) => setTestContext({ ...testContext, resource: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20"
                >
                  <option value="">Select resource...</option>
                  {COMMON_RESOURCES.map(r => <option key={r} value={r}>{r}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-ink mb-1">Context (JSON)</label>
                <textarea
                  value={JSON.stringify(testContext.context, null, 2)}
                  onChange={(e) => {
                    try {
                      setTestContext({ ...testContext, context: JSON.parse(e.target.value) });
                    } catch {}
                  }}
                  className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 font-mono"
                  rows={4}
                  placeholder='{ "user.role": "admin", "mfa_verified": true }'
                />
              </div>

              {testResult && (
                <div className={`p-4 rounded-lg ${testResult.allowed ? 'bg-green-50 border border-green-200' : 'bg-red-50 border border-red-200'}`}>
                  <div className="flex items-center gap-2">
                    {testResult.allowed ? <CheckCircle2 className="text-green-600" size={20} /> : <AlertCircle className="text-red-600" size={20} />}
                    <span className={`font-medium ${testResult.allowed ? 'text-green-700' : 'text-red-700'}`}>
                      {testResult.allowed ? 'Access Granted' : 'Access Denied'}
                    </span>
                  </div>
                  {testResult.matchedPolicies.length > 0 && (
                    <p className="text-sm mt-2 text-muted">
                      Matched policies: {testResult.matchedPolicies.join(', ')}
                    </p>
                  )}
                </div>
              )}
            </div>
            <div className="flex justify-end gap-2 p-4 border-t border-gray-200">
              <button
                onClick={() => { setShowTestModal(false); setSelectedPolicy(null); }}
                className="px-4 py-2 text-sm text-muted hover:text-ink border border-gray-200 rounded-lg hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleTestPolicy}
                disabled={!testContext.action || !testContext.resource || testLoading}
                className="px-4 py-2 text-sm bg-accent text-white rounded-lg hover:bg-accent/90 disabled:opacity-50"
              >
                {testLoading ? 'Testing...' : 'Run Test'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Policy Modal Component
interface PolicyModalProps {
  title: string;
  formData: PolicyFormData;
  setFormData: React.Dispatch<React.SetStateAction<PolicyFormData>>;
  onSubmit: () => void;
  onClose: () => void;
  submitLabel: string;
}

function PolicyModal({ title, formData, setFormData, onSubmit, onClose, submitLabel }: PolicyModalProps) {
  const [expandedRule, setExpandedRule] = useState<number | null>(0);

  const addRule = () => {
    setFormData({ ...formData, rules: [...formData.rules, { ...EMPTY_RULE }] });
  };

  const removeRule = (index: number) => {
    setFormData({ ...formData, rules: formData.rules.filter((_, i) => i !== index) });
  };

  const updateRule = (index: number, field: keyof PolicyRule, value: string[]) => {
    const newRules = [...formData.rules];
    newRules[index] = { ...newRules[index], [field]: value };
    setFormData({ ...formData, rules: newRules });
  };

  const addCondition = (ruleIndex: number) => {
    const newRules = [...formData.rules];
    newRules[ruleIndex].conditions = [...(newRules[ruleIndex].conditions || []), { ...EMPTY_CONDITION }];
    setFormData({ ...formData, rules: newRules });
  };

  const removeCondition = (ruleIndex: number, condIndex: number) => {
    const newRules = [...formData.rules];
    newRules[ruleIndex].conditions = newRules[ruleIndex].conditions?.filter((_, i) => i !== condIndex);
    setFormData({ ...formData, rules: newRules });
  };

  const updateCondition = (ruleIndex: number, condIndex: number, field: keyof PolicyCondition, value: string | unknown) => {
    const newRules = [...formData.rules];
    if (newRules[ruleIndex].conditions) {
      newRules[ruleIndex].conditions[condIndex] = { ...newRules[ruleIndex].conditions[condIndex], [field]: value };
    }
    setFormData({ ...formData, rules: newRules });
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-ink">{title}</h2>
          <button onClick={onClose} className="text-muted hover:text-ink">
            <X size={20} />
          </button>
        </div>

        <div className="p-4 space-y-4">
          {/* Basic Info */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Policy Name *</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20"
                placeholder="e.g., Admin Full Access"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Type</label>
              <select
                value={formData.type}
                onChange={(e) => setFormData({ ...formData, type: e.target.value as PolicyType })}
                className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20"
              >
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-ink mb-1">Description</label>
            <input
              type="text"
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20"
              placeholder="Brief description of this policy"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-ink mb-1">Status</label>
            <select
              value={formData.status}
              onChange={(e) => setFormData({ ...formData, status: e.target.value as PolicyStatus })}
              className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20"
            >
              <option value="active">Active</option>
              <option value="suspended">Suspended</option>
              <option value="draft">Draft</option>
            </select>
          </div>

          {/* Rules */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="block text-sm font-medium text-ink">Rules</label>
              <button onClick={addRule} className="text-xs text-accent hover:underline flex items-center gap-1">
                <Plus size={12} /> Add Rule
              </button>
            </div>

            <div className="space-y-3">
              {formData.rules.map((rule, ruleIndex) => (
                <div key={ruleIndex} className="border border-gray-200 rounded-lg overflow-hidden">
                  <div
                    className="flex items-center justify-between p-3 bg-gray-50 cursor-pointer"
                    onClick={() => setExpandedRule(expandedRule === ruleIndex ? null : ruleIndex)}
                  >
                    <div className="flex items-center gap-2">
                      {expandedRule === ruleIndex ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                      <span className="text-sm font-medium text-ink">Rule {ruleIndex + 1}</span>
                    </div>
                    {formData.rules.length > 1 && (
                      <button
                        onClick={(e) => { e.stopPropagation(); removeRule(ruleIndex); }}
                        className="text-xs text-red-500 hover:text-red-700"
                      >
                        Remove
                      </button>
                    )}
                  </div>

                  {expandedRule === ruleIndex && (
                    <div className="p-3 border-t border-gray-200 space-y-3">
                      {/* Actions */}
                      <div>
                        <label className="block text-xs font-medium text-muted mb-1">Actions</label>
                        <div className="flex flex-wrap gap-2">
                          {COMMON_ACTIONS.map((action) => (
                            <label key={action} className="flex items-center gap-1 text-xs">
                              <input
                                type="checkbox"
                                checked={rule.actions.includes(action)}
                                onChange={(e) => {
                                  const newActions = e.target.checked
                                    ? [...rule.actions, action]
                                    : rule.actions.filter(a => a !== action);
                                  updateRule(ruleIndex, 'actions', newActions);
                                }}
                                className="rounded border-gray-300 text-accent focus:ring-accent"
                              />
                              {action}
                            </label>
                          ))}
                        </div>
                      </div>

                      {/* Resources */}
                      <div>
                        <label className="block text-xs font-medium text-muted mb-1">Resources</label>
                        <div className="flex flex-wrap gap-2">
                          {COMMON_RESOURCES.map((resource) => (
                            <label key={resource} className="flex items-center gap-1 text-xs">
                              <input
                                type="checkbox"
                                checked={rule.resources.includes(resource)}
                                onChange={(e) => {
                                  const newResources = e.target.checked
                                    ? [...rule.resources, resource]
                                    : rule.resources.filter(r => r !== resource);
                                  updateRule(ruleIndex, 'resources', newResources);
                                }}
                                className="rounded border-gray-300 text-accent focus:ring-accent"
                              />
                              {resource}
                            </label>
                          ))}
                        </div>
                      </div>

                      {/* Conditions */}
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <label className="block text-xs font-medium text-muted">Conditions</label>
                          <button
                            onClick={() => addCondition(ruleIndex)}
                            className="text-xs text-accent hover:underline flex items-center gap-1"
                          >
                            <Plus size={12} /> Add Condition
                          </button>
                        </div>

                        {(rule.conditions?.length || 0) > 0 && (
                          <div className="space-y-2">
                            {rule.conditions?.map((cond, condIndex) => (
                              <div key={condIndex} className="flex items-center gap-2">
                                <select
                                  value={cond.field}
                                  onChange={(e) => updateCondition(ruleIndex, condIndex, 'field', e.target.value)}
                                  className="flex-1 px-2 py-1 border border-gray-200 rounded text-xs"
                                >
                                  <option value="">Select field...</option>
                                  {COMMON_FIELDS.map(f => <option key={f} value={f}>{f}</option>)}
                                </select>
                                <select
                                  value={cond.operator}
                                  onChange={(e) => updateCondition(ruleIndex, condIndex, 'operator', e.target.value)}
                                  className="w-24 px-2 py-1 border border-gray-200 rounded text-xs"
                                >
                                  {OPERATORS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                                </select>
                                <input
                                  type="text"
                                  value={String(cond.value)}
                                  onChange={(e) => updateCondition(ruleIndex, condIndex, 'value', e.target.value)}
                                  placeholder="Value"
                                  className="flex-1 px-2 py-1 border border-gray-200 rounded text-xs"
                                />
                                <button
                                  onClick={() => removeCondition(ruleIndex, condIndex)}
                                  className="text-red-500 hover:text-red-700"
                                >
                                  <X size={14} />
                                </button>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="flex justify-end gap-2 p-4 border-t border-gray-200">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-muted hover:text-ink border border-gray-200 rounded-lg hover:bg-gray-50"
          >
            Cancel
          </button>
          <button
            onClick={onSubmit}
            disabled={!formData.name || formData.rules.length === 0}
            className="px-4 py-2 text-sm bg-accent text-white rounded-lg hover:bg-accent/90 disabled:opacity-50"
          >
            {submitLabel}
          </button>
        </div>
      </div>
    </div>
  );
}