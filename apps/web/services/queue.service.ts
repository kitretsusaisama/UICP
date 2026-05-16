/**
 * Queue Service — BullMQ job monitoring, dead letter queue
 */

import { getApiUrl, normalizeError } from '@/lib/api-client';
import { authService } from './auth.service';
import type { QueueJob, QueueMetrics, ApiResponse } from '@/types';

export class QueueService {
  private authHeaders(): Record<string, string> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = authService.getAccessToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
  }

  async listQueues(): Promise<ApiResponse<QueueMetrics[]>> {
    const response = await fetch(getApiUrl('v1/queues'), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async getQueueJobs(queueName: string, params?: {
    status?: string;
    limit?: number;
    offset?: number;
  }): Promise<ApiResponse<{ items: QueueJob[]; total: number }>> {
    const searchParams = new URLSearchParams();
    if (params?.status) searchParams.set('status', params.status);
    if (params?.limit) searchParams.set('limit', String(params.limit));

    const query = searchParams.toString();
    const response = await fetch(getApiUrl(`v1/queues/${queueName}/jobs${query ? `?${query}` : ''}`), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async getDeadLetterQueue(limit = 50): Promise<ApiResponse<QueueJob[]>> {
    const response = await fetch(getApiUrl(`v1/queues/dead-letter?limit=${limit}`), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async retryJob(queueName: string, jobId: string): Promise<ApiResponse<{ retried: boolean }>> {
    const response = await fetch(getApiUrl(`v1/queues/${queueName}/jobs/${jobId}/retry`), {
      method: 'POST',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async discardJob(queueName: string, jobId: string): Promise<ApiResponse<{ discarded: boolean }>> {
    const response = await fetch(getApiUrl(`v1/queues/${queueName}/jobs/${jobId}/discard`), {
      method: 'POST',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async getQueueMetrics(queueName: string): Promise<ApiResponse<QueueMetrics>> {
    const response = await fetch(getApiUrl(`v1/queues/${queueName}/metrics`), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }
}

export const queueService = new QueueService();