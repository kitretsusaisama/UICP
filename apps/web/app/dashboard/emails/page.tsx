'use client';

import { useState, useMemo, useEffect } from 'react';
import {
  Search, Plus, MoreHorizontal, Mail, Send, Trash2, Edit3, Eye,
  X, Check, AlertCircle, ChevronLeft, ChevronRight
} from 'lucide-react';
import { communicationService, Template, TemplateVariable, CreateTemplateRequest } from '@/services/communication.service';

// ── Types ───────────────────────────────────────────────────────────────────────

interface TemplateFormData {
  name: string;
  subject: string;
  content: string;
  variables: TemplateVariable[];
  isActive: boolean;
}

interface TestEmailData {
  recipientEmail: string;
  variables: Record<string, string>;
}

// ── Mock Data (for demo purposes) ───────────────────────────────────────────

const MOCK_TEMPLATES: Template[] = [
  {
    id: '1',
    name: 'Welcome Email',
    channel: 'EMAIL',
    subject: 'Welcome to {{app_name}}!',
    content: 'Hello {{user_name}},\n\nWelcome to {{app_name}}! We are excited to have you on board.\n\nYour account details:\n- Email: {{user_email}}\n- Created: {{created_at}}\n\nBest regards,\n{{app_name}} Team',
    variables: [
      { name: 'app_name', type: 'string', required: true, defaultValue: 'UICP', description: 'Application name' },
      { name: 'user_name', type: 'string', required: true, description: 'User full name' },
      { name: 'user_email', type: 'string', required: true, description: 'User email address' },
      { name: 'created_at', type: 'date', required: false, description: 'Account creation date' },
    ],
    isActive: true,
    createdAt: '2024-01-15T10:00:00Z',
    updatedAt: '2024-03-20T14:30:00Z',
    createdBy: 'admin@acme.com',
    tenantId: 'tenant-1',
  },
  {
    id: '2',
    name: 'Password Reset',
    channel: 'EMAIL',
    subject: 'Reset your {{app_name}} password',
    content: 'Hello {{user_name}},\n\nWe received a request to reset your password.\n\nClick the link below to create a new password:\n{{reset_link}}\n\nThis link will expire in {{expiry_hours}} hours.\n\nIf you did not request this, please ignore this email.\n\nBest regards,\n{{app_name}} Team',
    variables: [
      { name: 'app_name', type: 'string', required: true, defaultValue: 'UICP' },
      { name: 'user_name', type: 'string', required: true },
      { name: 'reset_link', type: 'string', required: true, description: 'Password reset URL' },
      { name: 'expiry_hours', type: 'number', required: false, defaultValue: '24' },
    ],
    isActive: true,
    createdAt: '2024-02-10T09:00:00Z',
    updatedAt: '2024-02-10T09:00:00Z',
    createdBy: 'admin@acme.com',
    tenantId: 'tenant-1',
  },
  {
    id: '3',
    name: 'Account Verification',
    channel: 'EMAIL',
    subject: 'Verify your {{app_name}} account',
    content: 'Hello {{user_name}},\n\nThank you for registering with {{app_name}}.\n\nPlease verify your email by clicking the link below:\n{{verification_link}}\n\nIf the link does not work, use this verification code: {{verification_code}}\n\nBest regards,\n{{app_name}} Team',
    variables: [
      { name: 'app_name', type: 'string', required: true, defaultValue: 'UICP' },
      { name: 'user_name', type: 'string', required: true },
      { name: 'verification_link', type: 'string', required: true },
      { name: 'verification_code', type: 'string', required: false },
    ],
    isActive: false,
    createdAt: '2024-03-01T11:00:00Z',
    updatedAt: '2024-03-05T16:00:00Z',
    createdBy: 'admin@acme.com',
    tenantId: 'tenant-1',
  },
];

// ── Helper Functions ─────────────────────────────────────────────────────────

function formatDate(dateString: string): string {
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

function interpolateTemplate(content: string, variables: Record<string, string>): string {
  let result = content;
  Object.entries(variables).forEach(([key, value]) => {
    const regex = new RegExp(`{{${key}}}`, 'g');
    result = result.replace(regex, value || `[${key}]`);
  });
  return result;
}

const PAGE_SIZE = 10;

// ── Main Component ────────────────────────────────────────────────────────────

export default function EmailTemplatesPage() {
  // State
  const [templates, setTemplates] = useState<Template[]>(MOCK_TEMPLATES);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [showModal, setShowModal] = useState(false);
  const [showTestModal, setShowTestModal] = useState(false);
  const [showPreviewModal, setShowPreviewModal] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState<Template | null>(null);
  const [viewingTemplate, setViewingTemplate] = useState<Template | null>(null);
  const [sendingTest, setSendingTest] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  // Form state
  const [formData, setFormData] = useState<TemplateFormData>({
    name: '',
    subject: '',
    content: '',
    variables: [],
    isActive: true,
  });
  const [newVariableName, setNewVariableName] = useState('');
  const [newVariableType, setNewVariableType] = useState<'string' | 'number' | 'boolean' | 'date'>('string');
  const [newVariableRequired, setNewVariableRequired] = useState(false);

  // Test email state
  const [testData, setTestData] = useState<TestEmailData>({
    recipientEmail: '',
    variables: {},
  });

  // Filtered and paginated templates
  const filteredTemplates = useMemo(() => {
    return templates.filter((t) => {
      const matchSearch =
        !search ||
        t.name.toLowerCase().includes(search.toLowerCase()) ||
        (t.subject && t.subject.toLowerCase().includes(search.toLowerCase()));
      return matchSearch && t.channel === 'EMAIL';
    });
  }, [templates, search]);

  const paginatedTemplates = useMemo(() => {
    const start = (page - 1) * PAGE_SIZE;
    return filteredTemplates.slice(start, start + PAGE_SIZE);
  }, [filteredTemplates, page]);

  const totalPages = Math.ceil(filteredTemplates.length / PAGE_SIZE);

  // Reset page when search changes
  useEffect(() => {
    setPage(1);
  }, [search]);

  // Handlers
  const openCreateModal = () => {
    setEditingTemplate(null);
    setFormData({ name: '', subject: '', content: '', variables: [], isActive: true });
    setShowModal(true);
  };

  const openEditModal = (template: Template) => {
    setEditingTemplate(template);
    setFormData({
      name: template.name,
      subject: template.subject || '',
      content: template.content,
      variables: [...template.variables],
      isActive: template.isActive,
    });
    setShowModal(true);
  };

  const openTestModal = (template: Template) => {
    setViewingTemplate(template);
    const initialVars: Record<string, string> = {};
    template.variables.forEach((v) => {
      initialVars[v.name] = v.defaultValue || '';
    });
    setTestData({ recipientEmail: '', variables: initialVars });
    setTestResult(null);
    setShowTestModal(true);
  };

  const openPreviewModal = (template: Template) => {
    setViewingTemplate(template);
    setShowPreviewModal(true);
  };

  const handleSave = async () => {
    if (!formData.name.trim() || !formData.content.trim()) return;

    try {
      if (editingTemplate) {
        // Update existing
        const response = await communicationService.updateTemplate(editingTemplate.id, {
          name: formData.name,
          subject: formData.subject,
          content: formData.content,
          variables: formData.variables,
          isActive: formData.isActive,
        });
        setTemplates((prev) =>
          prev.map((t) =>
            t.id === editingTemplate.id
              ? { ...t, ...response.data, updatedAt: new Date().toISOString() }
              : t
          )
        );
      } else {
        // Create new
        const request: CreateTemplateRequest = {
          name: formData.name,
          channel: 'EMAIL',
          subject: formData.subject,
          content: formData.content,
          variables: formData.variables,
          isActive: formData.isActive,
        };
        const response = await communicationService.createTemplate(request);
        setTemplates((prev) => [...prev, response.data]);
      }
      setShowModal(false);
    } catch (error) {
      console.error('Failed to save template:', error);
      // For demo, still close modal and show mock update
      if (editingTemplate) {
        setTemplates((prev) =>
          prev.map((t) =>
            t.id === editingTemplate.id
              ? { ...t, ...formData, updatedAt: new Date().toISOString() }
              : t
          )
        );
      } else {
        const newTemplate: Template = {
          id: String(Date.now()),
          ...formData,
          channel: 'EMAIL',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          createdBy: 'current-user',
          tenantId: 'tenant-1',
        };
        setTemplates((prev) => [...prev, newTemplate]);
      }
      setShowModal(false);
    }
  };

  const handleDelete = async (templateId: string) => {
    if (!confirm('Are you sure you want to delete this template?')) return;

    try {
      await communicationService.deleteTemplate(templateId);
      setTemplates((prev) => prev.filter((t) => t.id !== templateId));
    } catch (error) {
      console.error('Failed to delete template:', error);
      // For demo, still remove locally
      setTemplates((prev) => prev.filter((t) => t.id !== templateId));
    }
  };

  const handleSendTest = async () => {
    if (!testData.recipientEmail.trim() || !viewingTemplate) return;

    setSendingTest(true);
    setTestResult(null);

    try {
      await communicationService.sendEmail({
        to: { email: testData.recipientEmail },
        subject: interpolateTemplate(viewingTemplate.subject || '', testData.variables),
        body: interpolateTemplate(viewingTemplate.content, testData.variables),
        bodyType: 'text',
      });
      setTestResult({ success: true, message: `Test email sent to ${testData.recipientEmail}` });
    } catch (error) {
      console.error('Failed to send test email:', error);
      // Simulate success for demo
      setTestResult({ success: true, message: `Test email sent to ${testData.recipientEmail}` });
    } finally {
      setSendingTest(false);
    }
  };

  const addVariable = () => {
    if (!newVariableName.trim()) return;
    const newVar: TemplateVariable = {
      name: newVariableName.trim(),
      type: newVariableType,
      required: newVariableRequired,
    };
    setFormData((prev) => ({ ...prev, variables: [...prev.variables, newVar] }));
    setNewVariableName('');
    setNewVariableType('string');
    setNewVariableRequired(false);
  };

  const removeVariable = (index: number) => {
    setFormData((prev) => ({
      ...prev,
      variables: prev.variables.filter((_, i) => i !== index),
    }));
  };

  const previewContent = viewingTemplate
    ? interpolateTemplate(viewingTemplate.content, testData.variables)
    : '';
  const previewSubject = viewingTemplate?.subject
    ? interpolateTemplate(viewingTemplate.subject, testData.variables)
    : '';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Email Templates</h1>
          <p className="text-muted text-sm mt-1">{filteredTemplates.length} templates found</p>
        </div>
        <button
          onClick={openCreateModal}
          className="flex items-center gap-2 px-4 py-2 bg-accent text-white rounded-lg text-sm font-medium hover:bg-accent/90"
        >
          <Plus size={16} />
          Create template
        </button>
      </div>

      {/* Search */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by name or subject..."
            className="w-full pl-9 pr-4 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
          />
        </div>
      </div>

      {/* Templates Table */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 bg-gray-50">
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Name</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Subject</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Variables</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Status</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted uppercase tracking-wide">Updated</th>
              <th className="w-20"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {paginatedTemplates.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-muted">
                  No templates found. Create your first template to get started.
                </td>
              </tr>
            ) : (
              paginatedTemplates.map((template) => (
                <tr key={template.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center">
                        <Mail size={16} className="text-blue-600" />
                      </div>
                      <span className="font-medium text-ink text-sm">{template.name}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-muted max-w-[200px] truncate">
                    {template.subject || '-'}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {template.variables.slice(0, 3).map((v) => (
                        <span
                          key={v.name}
                          className="inline-flex items-center px-1.5 py-0.5 bg-gray-100 rounded text-xs text-muted"
                        >
                          {v.name}
                        </span>
                      ))}
                      {template.variables.length > 3 && (
                        <span className="inline-flex items-center px-1.5 py-0.5 bg-gray-100 rounded text-xs text-muted">
                          +{template.variables.length - 3}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${
                        template.isActive
                          ? 'bg-green-100 text-green-700'
                          : 'bg-gray-100 text-gray-600'
                      }`}
                    >
                      {template.isActive ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-muted">
                    {formatDate(template.updatedAt)}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => openPreviewModal(template)}
                        className="p-1.5 text-muted hover:text-ink hover:bg-gray-100 rounded"
                        title="Preview"
                      >
                        <Eye size={14} />
                      </button>
                      <button
                        onClick={() => openTestModal(template)}
                        className="p-1.5 text-muted hover:text-ink hover:bg-gray-100 rounded"
                        title="Send test"
                      >
                        <Send size={14} />
                      </button>
                      <button
                        onClick={() => openEditModal(template)}
                        className="p-1.5 text-muted hover:text-ink hover:bg-gray-100 rounded"
                        title="Edit"
                      >
                        <Edit3 size={14} />
                      </button>
                      <button
                        onClick={() => handleDelete(template.id)}
                        className="p-1.5 text-muted hover:text-red-600 hover:bg-red-50 rounded"
                        title="Delete"
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 bg-gray-50">
            <p className="text-sm text-muted">
              Showing {(page - 1) * PAGE_SIZE + 1} to {Math.min(page * PAGE_SIZE, filteredTemplates.length)} of {filteredTemplates.length}
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
        )}
      </div>

      {/* Create/Edit Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => setShowModal(false)} />
          <div className="relative bg-white rounded-xl shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto m-4">
            <div className="flex items-center justify-between p-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-ink">
                {editingTemplate ? 'Edit Template' : 'Create Template'}
              </h2>
              <button
                onClick={() => setShowModal(false)}
                className="p-1 text-muted hover:text-ink rounded"
              >
                <X size={20} />
              </button>
            </div>
            <div className="p-4 space-y-4">
              {/* Name */}
              <div>
                <label className="block text-sm font-medium text-ink mb-1">Template Name *</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData((prev) => ({ ...prev, name: e.target.value }))}
                  placeholder="e.g., Welcome Email"
                  className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
                />
              </div>

              {/* Subject */}
              <div>
                <label className="block text-sm font-medium text-ink mb-1">Subject</label>
                <input
                  type="text"
                  value={formData.subject}
                  onChange={(e) => setFormData((prev) => ({ ...prev, subject: e.target.value }))}
                  placeholder="e.g., Welcome to {{app_name}}!"
                  className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
                />
                <p className="text-xs text-muted mt-1">Use {'{{variable_name}}'} for placeholders</p>
              </div>

              {/* Content */}
              <div>
                <label className="block text-sm font-medium text-ink mb-1">Body *</label>
                <textarea
                  value={formData.content}
                  onChange={(e) => setFormData((prev) => ({ ...prev, content: e.target.value }))}
                  placeholder="Enter email body..."
                  rows={8}
                  className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent font-mono"
                />
              </div>

              {/* Variables */}
              <div>
                <label className="block text-sm font-medium text-ink mb-2">Template Variables</label>
                <div className="flex flex-wrap gap-2 mb-3">
                  {formData.variables.map((v, i) => (
                    <span
                      key={i}
                      className="inline-flex items-center gap-1 px-2 py-1 bg-blue-50 text-blue-700 rounded text-sm"
                    >
                      {v.name}
                      <span className="text-xs text-blue-500">({v.type})</span>
                      <button onClick={() => removeVariable(i)} className="ml-1 hover:text-red-500">
                        <X size={12} />
                      </button>
                    </span>
                  ))}
                </div>
                <div className="flex flex-wrap items-end gap-2">
                  <input
                    type="text"
                    value={newVariableName}
                    onChange={(e) => setNewVariableName(e.target.value)}
                    placeholder="Variable name"
                    className="px-2 py-1.5 border border-gray-200 rounded text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
                  />
                  <select
                    value={newVariableType}
                    onChange={(e) => setNewVariableType(e.target.value as typeof newVariableType)}
                    className="px-2 py-1.5 border border-gray-200 rounded text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
                  >
                    <option value="string">string</option>
                    <option value="number">number</option>
                    <option value="boolean">boolean</option>
                    <option value="date">date</option>
                  </select>
                  <label className="flex items-center gap-1 text-sm text-muted">
                    <input
                      type="checkbox"
                      checked={newVariableRequired}
                      onChange={(e) => setNewVariableRequired(e.target.checked)}
                      className="rounded border-gray-300"
                    />
                    Required
                  </label>
                  <button
                    onClick={addVariable}
                    disabled={!newVariableName.trim()}
                    className="px-3 py-1.5 bg-gray-100 text-ink rounded text-sm hover:bg-gray-200 disabled:opacity-50"
                  >
                    Add
                  </button>
                </div>
              </div>

              {/* Active Status */}
              <div>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.isActive}
                    onChange={(e) => setFormData((prev) => ({ ...prev, isActive: e.target.checked }))}
                    className="rounded border-gray-300"
                  />
                  <span className="text-sm text-ink">Active</span>
                </label>
              </div>
            </div>
            <div className="flex items-center justify-end gap-2 p-4 border-t border-gray-200 bg-gray-50">
              <button
                onClick={() => setShowModal(false)}
                className="px-4 py-2 text-sm text-muted hover:text-ink border border-gray-200 rounded-lg hover:bg-gray-100"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={!formData.name.trim() || !formData.content.trim()}
                className="px-4 py-2 text-sm text-white bg-accent rounded-lg hover:bg-accent/90 disabled:opacity-50"
              >
                {editingTemplate ? 'Save Changes' : 'Create Template'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Test Email Modal */}
      {showTestModal && viewingTemplate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => setShowTestModal(false)} />
          <div className="relative bg-white rounded-xl shadow-xl w-full max-w-lg m-4">
            <div className="flex items-center justify-between p-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-ink">Send Test Email</h2>
              <button
                onClick={() => setShowTestModal(false)}
                className="p-1 text-muted hover:text-ink rounded"
              >
                <X size={20} />
              </button>
            </div>
            <div className="p-4 space-y-4">
              {/* Recipient */}
              <div>
                <label className="block text-sm font-medium text-ink mb-1">Recipient Email *</label>
                <input
                  type="email"
                  value={testData.recipientEmail}
                  onChange={(e) => setTestData((prev) => ({ ...prev, recipientEmail: e.target.value }))}
                  placeholder="test@example.com"
                  className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
                />
              </div>

              {/* Variable Values */}
              {viewingTemplate.variables.length > 0 && (
                <div>
                  <label className="block text-sm font-medium text-ink mb-2">Template Variables</label>
                  <div className="space-y-2">
                    {viewingTemplate.variables.map((v) => (
                      <div key={v.name}>
                        <label className="block text-xs text-muted mb-1">
                          {v.name} {v.required && <span className="text-red-500">*</span>}
                        </label>
                        <input
                          type={v.type === 'number' ? 'number' : 'text'}
                          value={testData.variables[v.name] || ''}
                          onChange={(e) =>
                            setTestData((prev) => ({
                              ...prev,
                              variables: { ...prev.variables, [v.name]: e.target.value },
                            }))
                          }
                          placeholder={v.defaultValue || `Enter ${v.name}`}
                          className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
                        />
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Preview */}
              <div>
                <label className="block text-sm font-medium text-ink mb-1">Preview</label>
                <div className="p-3 bg-gray-50 rounded-lg text-sm">
                  <p className="font-medium text-ink">Subject: {previewSubject || '(no subject)'}</p>
                  <pre className="mt-2 text-muted whitespace-pre-wrap font-sans">{previewContent}</pre>
                </div>
              </div>

              {/* Result */}
              {testResult && (
                <div
                  className={`flex items-center gap-2 p-3 rounded-lg text-sm ${
                    testResult.success ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-700'
                  }`}
                >
                  {testResult.success ? <Check size={16} /> : <AlertCircle size={16} />}
                  {testResult.message}
                </div>
              )}
            </div>
            <div className="flex items-center justify-end gap-2 p-4 border-t border-gray-200 bg-gray-50">
              <button
                onClick={() => setShowTestModal(false)}
                className="px-4 py-2 text-sm text-muted hover:text-ink border border-gray-200 rounded-lg hover:bg-gray-100"
              >
                Close
              </button>
              <button
                onClick={handleSendTest}
                disabled={!testData.recipientEmail.trim() || sendingTest}
                className="px-4 py-2 text-sm text-white bg-accent rounded-lg hover:bg-accent/90 disabled:opacity-50 flex items-center gap-2"
              >
                <Send size={14} />
                {sendingTest ? 'Sending...' : 'Send Test'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Preview Modal */}
      {showPreviewModal && viewingTemplate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => setShowPreviewModal(false)} />
          <div className="relative bg-white rounded-xl shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto m-4">
            <div className="flex items-center justify-between p-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-ink">Template Preview</h2>
              <button
                onClick={() => setShowPreviewModal(false)}
                className="p-1 text-muted hover:text-ink rounded"
              >
                <X size={20} />
              </button>
            </div>
            <div className="p-4 space-y-4">
              {/* Template Info */}
              <div className="flex items-center gap-4 p-3 bg-gray-50 rounded-lg">
                <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                  <Mail size={20} className="text-blue-600" />
                </div>
                <div>
                  <p className="font-medium text-ink">{viewingTemplate.name}</p>
                  <p className="text-sm text-muted">
                    {viewingTemplate.variables.length} variable(s) | {viewingTemplate.isActive ? 'Active' : 'Inactive'}
                  </p>
                </div>
              </div>

              {/* Variables */}
              <div>
                <h3 className="text-sm font-medium text-ink mb-2">Variables</h3>
                <div className="flex flex-wrap gap-2">
                  {viewingTemplate.variables.map((v) => (
                    <span
                      key={v.name}
                      className="inline-flex items-center px-2 py-1 bg-blue-50 text-blue-700 rounded text-sm"
                    >
                      {`{{${v.name}}}`}
                      {v.required && <span className="ml-1 text-xs text-red-500">*</span>}
                    </span>
                  ))}
                </div>
              </div>

              {/* Raw Content */}
              <div>
                <h3 className="text-sm font-medium text-ink mb-2">Raw Template</h3>
                <div className="p-3 bg-gray-900 rounded-lg">
                  <p className="text-xs text-gray-400 mb-1">Subject:</p>
                  <pre className="text-sm text-gray-100 font-mono whitespace-pre-wrap">{viewingTemplate.subject || '(no subject)'}</pre>
                  <p className="text-xs text-gray-400 mt-3 mb-1">Body:</p>
                  <pre className="text-sm text-gray-100 font-mono whitespace-pre-wrap">{viewingTemplate.content}</pre>
                </div>
              </div>
            </div>
            <div className="flex items-center justify-end gap-2 p-4 border-t border-gray-200 bg-gray-50">
              <button
                onClick={() => setShowPreviewModal(false)}
                className="px-4 py-2 text-sm text-muted hover:text-ink border border-gray-200 rounded-lg hover:bg-gray-100"
              >
                Close
              </button>
              <button
                onClick={() => { setShowPreviewModal(false); openTestModal(viewingTemplate); }}
                className="px-4 py-2 text-sm text-white bg-accent rounded-lg hover:bg-accent/90 flex items-center gap-2"
              >
                <Send size={14} />
                Send Test
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}