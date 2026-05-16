/**
 * Communication Service — Email, SMS, and template management
 * All communication endpoints connect to /v1/communication/* endpoints
 */

import { getApiUrl, normalizeError } from '@/lib/api-client';
import { authService } from './auth.service';
import type { ApiResponse } from '@/types';

// ── Email Types ────────────────────────────────────────────────────────────────

export interface EmailRecipient {
  email: string;
  name?: string;
}

export interface EmailAttachment {
  filename: string;
  content: string; // Base64 encoded
  mimeType: string;
}

export interface EmailRequest {
  to: EmailRecipient | EmailRecipient[];
  subject: string;
  body: string;
  bodyType?: 'text' | 'html';
  from?: string;
  replyTo?: string;
  cc?: EmailRecipient[];
  bcc?: EmailRecipient[];
  attachments?: EmailAttachment[];
  metadata?: Record<string, unknown>;
}

export interface BatchEmailRequest {
  emails: EmailRequest[];
  priority?: 'low' | 'normal' | 'high';
}

export interface EmailSendResult {
  messageId: string;
  status: 'sent' | 'queued' | 'failed';
  provider?: string;
  sentAt?: string;
}

export interface BatchEmailResult {
  total: number;
  successful: number;
  failed: number;
  results: EmailSendResult[];
}

// ── Template Types ────────────────────────────────────────────────────────────

export type TemplateChannel = 'EMAIL' | 'SMS' | 'WHATSAPP' | 'VOICE';

export interface TemplateVariable {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'date';
  required: boolean;
  defaultValue?: string;
  description?: string;
}

export interface Template {
  id: string;
  name: string;
  channel: TemplateChannel;
  subject?: string; // For email templates
  content: string;
  variables: TemplateVariable[];
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  tenantId: string;
}

export interface CreateTemplateRequest {
  name: string;
  channel: TemplateChannel;
  subject?: string;
  content: string;
  variables?: TemplateVariable[];
  isActive?: boolean;
}

export interface UpdateTemplateRequest {
  name?: string;
  subject?: string;
  content?: string;
  variables?: TemplateVariable[];
  isActive?: boolean;
}

// ── SMS Types ────────────────────────────────────────────────────────────────

export interface SmsRequest {
  to: string | string[];
  body: string;
  from?: string;
  metadata?: Record<string, unknown>;
}

export interface SmsSendResult {
  messageId: string;
  status: 'sent' | 'queued' | 'failed';
  provider?: string;
  sentAt?: string;
}

// ── Communication Service ───────────────────────────────────────────────────

export class CommunicationService {
  private authHeaders(): Record<string, string> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = authService.getAccessToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
  }

  // POST /v1/communication/email/send
  async sendEmail(request: EmailRequest): Promise<ApiResponse<EmailSendResult>> {
    const response = await fetch(getApiUrl('v1/communication/email/send'), {
      method: 'POST',
      headers: this.authHeaders(),
      body: JSON.stringify(request),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // POST /v1/communication/email/batch
  async sendBatchEmail(request: BatchEmailRequest): Promise<ApiResponse<BatchEmailResult>> {
    const response = await fetch(getApiUrl('v1/communication/email/batch'), {
      method: 'POST',
      headers: this.authHeaders(),
      body: JSON.stringify(request),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // GET /v1/communication/templates
  async getTemplates(params?: {
    channel?: TemplateChannel;
    isActive?: boolean;
    page?: number;
    pageSize?: number;
  }): Promise<ApiResponse<{ items: Template[]; total: number; page: number; pageSize: number }>> {
    const searchParams = new URLSearchParams();
    if (params?.channel) searchParams.set('channel', params.channel);
    if (params?.isActive !== undefined) searchParams.set('isActive', String(params.isActive));
    if (params?.page) searchParams.set('page', String(params.page));
    if (params?.pageSize) searchParams.set('pageSize', String(params.pageSize));

    const query = searchParams.toString();
    const response = await fetch(getApiUrl(`v1/communication/templates${query ? `?${query}` : ''}`), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // POST /v1/communication/templates
  async createTemplate(request: CreateTemplateRequest): Promise<ApiResponse<Template>> {
    const response = await fetch(getApiUrl('v1/communication/templates'), {
      method: 'POST',
      headers: this.authHeaders(),
      body: JSON.stringify(request),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // GET /v1/communication/templates/:id
  async getTemplate(templateId: string): Promise<ApiResponse<Template>> {
    const response = await fetch(getApiUrl(`v1/communication/templates/${templateId}`), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // PUT /v1/communication/templates/:id
  async updateTemplate(templateId: string, request: UpdateTemplateRequest): Promise<ApiResponse<Template>> {
    const response = await fetch(getApiUrl(`v1/communication/templates/${templateId}`), {
      method: 'PUT',
      headers: this.authHeaders(),
      body: JSON.stringify(request),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // DELETE /v1/communication/templates/:id
  async deleteTemplate(templateId: string): Promise<ApiResponse<{ deleted: boolean }>> {
    const response = await fetch(getApiUrl(`v1/communication/templates/${templateId}`), {
      method: 'DELETE',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // POST /v1/communication/sms/send
  async sendSms(request: SmsRequest): Promise<ApiResponse<SmsSendResult>> {
    const response = await fetch(getApiUrl('v1/communication/sms/send'), {
      method: 'POST',
      headers: this.authHeaders(),
      body: JSON.stringify(request),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }
}

export const communicationService = new CommunicationService();