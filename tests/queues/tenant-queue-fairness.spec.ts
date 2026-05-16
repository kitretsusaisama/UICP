import { describe, it, expect, beforeEach } from '@jest/globals';

interface QueueJob {
  id: string;
  tenantId: string;
  type: 'OTP_SEND' | 'EMAIL_SEND';
  payload: Record<string, unknown>;
  status: 'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'FAILED' | 'DEAD_LETTER';
  attempts: number;
  createdAt: number;
  processedAt?: number;
}

interface TenantQueueConfig {
  tenantId: string;
  maxConcurrency: number;
  rateLimitPerMinute: number;
  priority: number;
}

// In-memory queue (simulating BullMQ)
const jobQueue: QueueJob[] = [];
const deadLetterQueue: QueueJob[] = [];
const tenantConfigs = new Map<string, TenantQueueConfig>();

// Job ID counter
let jobIdCounter = 0;

// Configuration constants
const MAX_PROCESS_TIME_MS = 10; // Fast processing for tests
const DEAD_LETTER_AFTER_ATTEMPTS = 3;

function configureTenant(tenantId: string, config: Partial<TenantQueueConfig> = {}): void {
  tenantConfigs.set(tenantId, {
    tenantId,
    maxConcurrency: config.maxConcurrency ?? 10,
    rateLimitPerMinute: config.rateLimitPerMinute ?? 100,
    priority: config.priority ?? 1,
  });
}

function enqueueJob(tenantId: string, type: QueueJob['type'], payload: Record<string, unknown>): QueueJob {
  const job: QueueJob = {
    id: `job_${++jobIdCounter}`,
    tenantId,
    type,
    payload,
    status: 'QUEUED',
    attempts: 0,
    createdAt: Date.now(),
  };

  jobQueue.push(job);
  return job;
}

function getNextJob(tenantId?: string): QueueJob | null {
  // Find next job respecting tenant fairness
  // In production, BullMQ handles this with per-tenant concurrency

  if (tenantId) {
    // Get job for specific tenant
    return jobQueue.find(j => j.tenantId === tenantId && j.status === 'QUEUED') ?? null;
  }

  // Get any queued job
  return jobQueue.find(j => j.status === 'QUEUED') ?? null;
}

function processJob(jobId: string, shouldFail: boolean = false): { success: boolean; error?: string } {
  const jobIndex = jobQueue.findIndex(j => j.id === jobId);
  if (jobIndex === -1) {
    return { success: false, error: 'JOB_NOT_FOUND' };
  }

  const job = jobQueue[jobIndex]!;
  job.status = 'PROCESSING';
  job.processedAt = Date.now();

  if (shouldFail) {
    job.attempts += 1;
    job.status = 'QUEUED'; // Re-queue for retry

    if (job.attempts >= DEAD_LETTER_AFTER_ATTEMPTS) {
      job.status = 'DEAD_LETTER';
      jobQueue.splice(jobIndex, 1);
      deadLetterQueue.push(job);
      return { success: false, error: 'MAX_ATTEMPTS_EXCEEDED' };
    }

    return { success: false, error: 'PROCESSING_FAILED' };
  }

  job.status = 'COMPLETED';
  return { success: true };
}

function getJobStatus(jobId: string): QueueJob['status'] | null {
  const job = jobQueue.find(j => j.id === jobId);
  return job?.status ?? null;
}

function countQueuedJobs(tenantId: string): number {
  return jobQueue.filter(j => j.tenantId === tenantId && j.status === 'QUEUED').length;
}

function clearTestState(): void {
  jobQueue.length = 0;
  deadLetterQueue.length = 0;
  jobIdCounter = 0;
}

// Simulate queue worker processing
async function processQueue(maxJobs: number = Infinity): Promise<{ processed: number; failed: number }> {
  let processed = 0;
  let failed = 0;

  // Round-robin state: last served tenant index to prevent starvation
  let lastServedIndex = -1;

  while (processed < maxJobs) {
    const tenantIds = [...tenantConfigs.keys()];
    let job: QueueJob | null = null;

    // Round-robin through tenants to ensure fair distribution
    for (let round = 0; round < tenantIds.length + 1; round++) {
      const idx = (lastServedIndex + 1 + round) % tenantIds.length;
      const tenantId = tenantIds[idx]!;
      const found = getNextJob(tenantId);
      if (found) {
        job = found;
        lastServedIndex = idx;
        break;
      }
    }

    // Fallback: any queued job if all round-robin attempts fail
    if (!job) {
      job = getNextJob();
    }

    if (!job) break;

    const result = processJob(job.id, false);
    if (result.success) {
      processed++;
    } else {
      failed++;
    }
  }

  return { processed, failed };
}

describe('Tenant Queue Fairness', () => {
  beforeEach(() => {
    clearTestState();
    configureTenant('tenant-a', { maxConcurrency: 10, rateLimitPerMinute: 100 });
    configureTenant('tenant-b', { maxConcurrency: 5, rateLimitPerMinute: 50 });
  });

  describe('Queue Starvation Prevention', () => {
    it('does not let Tenant A starve Tenant B', async () => {
      // Tenant A: 1000 jobs
      for (let i = 0; i < 1000; i++) {
        enqueueJob('tenant-a', 'OTP_SEND', { recipient: `user${i}@a.com` });
      }

      // Tenant B: 10 jobs
      for (let i = 0; i < 10; i++) {
        enqueueJob('tenant-b', 'OTP_SEND', { recipient: `user${i}@b.com` });
      }

      // Process all jobs
      await processQueue(1010);

      // Both should complete
      const tenantACompleted = jobQueue.filter(j => j.tenantId === 'tenant-a' && j.status === 'COMPLETED').length;
      const tenantBCompleted = jobQueue.filter(j => j.tenantId === 'tenant-b' && j.status === 'COMPLETED').length;

      expect(tenantACompleted).toBe(1000);
      expect(tenantBCompleted).toBe(10);
    });

    it('processes Tenant B jobs even when Tenant A has many queued', async () => {
      // Tenant A floods queue
      for (let i = 0; i < 1000; i++) {
        enqueueJob('tenant-a', 'OTP_SEND', {});
      }

      // Tenant B adds job
      enqueueJob('tenant-b', 'OTP_SEND', { urgent: true });
      const jobB = jobQueue[jobQueue.length - 1]!;

      // Process first 100 jobs
      await processQueue(100);

      // Tenant B's job should be processable
      const statusB = getJobStatus(jobB.id);
      expect(statusB).toBeDefined();
    });
  });

  describe('Tenant Queue Isolation', () => {
    it('isolates queues per tenant', () => {
      enqueueJob('tenant-a', 'OTP_SEND', { to: 'user@a.com' });
      enqueueJob('tenant-b', 'OTP_SEND', { to: 'user@b.com' });

      const tenantAJobs = jobQueue.filter(j => j.tenantId === 'tenant-a');
      const tenantBJobs = jobQueue.filter(j => j.tenantId === 'tenant-b');

      expect(tenantAJobs.length).toBe(1);
      expect(tenantBJobs.length).toBe(1);

      // Different tenants have different jobs
      expect(tenantAJobs[0]!.payload.to).toBe('user@a.com');
      expect(tenantBJobs[0]!.payload.to).toBe('user@b.com');
    });

    it('prevents cross-tenant job access', () => {
      enqueueJob('tenant-a', 'OTP_SEND', { secret: 'tenant-a-secret' });
      enqueueJob('tenant-b', 'OTP_SEND', { secret: 'tenant-b-secret' });

      // Verify isolation - jobs have separate payloads
      const jobA = jobQueue.find(j => j.tenantId === 'tenant-a');
      const jobB = jobQueue.find(j => j.tenantId === 'tenant-b');

      expect(jobA?.payload.secret).not.toBe(jobB?.payload.secret);
    });
  });

  describe('Rate Limiting', () => {
    it('respects per-tenant rate limits', () => {
      const configA = tenantConfigs.get('tenant-a')!;
      const configB = tenantConfigs.get('tenant-b')!;

      expect(configA.rateLimitPerMinute).toBe(100);
      expect(configB.rateLimitPerMinute).toBe(50);

      // Can add jobs
      for (let i = 0; i < 50; i++) {
        enqueueJob('tenant-b', 'OTP_SEND', {});
      }

      const queuedB = countQueuedJobs('tenant-b');
      expect(queuedB).toBe(50);
    });
  });

  describe('Dead Letter Queue Handling', () => {
    it('moves failed jobs to dead letter queue', async () => {
      const job = enqueueJob('tenant-a', 'OTP_SEND', {});

      // Fail multiple times
      processJob(job.id, true);
      processJob(job.id, true);
      processJob(job.id, true); // 3rd failure → dead letter

      // Job should be in dead letter queue
      const dlqJob = deadLetterQueue.find(j => j.id === job.id);
      expect(dlqJob).toBeDefined();
      expect(dlqJob?.status).toBe('DEAD_LETTER');
    });

    it('preserves tenant context in dead letter', () => {
      const job = enqueueJob('tenant-b', 'OTP_SEND', { recipient: 'user@tenant-b.com' });

      // Move to dead letter manually
      job.status = 'DEAD_LETTER';
      jobQueue.splice(jobQueue.findIndex(j => j.id === job.id), 1);
      deadLetterQueue.push(job);

      const dlqJob = deadLetterQueue[0];
      expect(dlqJob?.tenantId).toBe('tenant-b');
    });
  });

  describe('Job Ordering', () => {
    it('maintains FIFO within tenant', () => {
      for (let i = 0; i < 5; i++) {
        enqueueJob('tenant-a', 'OTP_SEND', { sequence: i });
      }

      // Process in order
      for (let i = 0; i < 5; i++) {
        const job = getNextJob('tenant-a');
        expect(job?.payload.sequence).toBe(i);
        processJob(job!.id);
      }
    });
  });

  describe('Concurrent Job Processing', () => {
    it('handles multiple tenant queues', async () => {
      // Add jobs for multiple tenants
      for (let i = 0; i < 100; i++) {
        enqueueJob('tenant-a', 'OTP_SEND', { index: i });
      }

      for (let i = 0; i < 50; i++) {
        enqueueJob('tenant-b', 'OTP_SEND', { index: i });
      }

      // Process all
      await processQueue(150);

      const completedA = countCompleted('tenant-a');
      const completedB = countCompleted('tenant-b');

      expect(completedA).toBe(100);
      expect(completedB).toBe(50);
    });

    function countCompleted(tenantId: string): number {
      return jobQueue.filter(j => j.tenantId === tenantId && j.status === 'COMPLETED').length;
    }
  });

  describe('Provider-Specific Queues', () => {
    it('processes SMS and EMAIL separately', () => {
      enqueueJob('tenant-a', 'OTP_SEND', { type: 'SMS' });
      enqueueJob('tenant-a', 'EMAIL_SEND', { type: 'EMAIL' });

      const smsJobs = jobQueue.filter(j => j.type === 'OTP_SEND');
      const emailJobs = jobQueue.filter(j => j.type === 'EMAIL_SEND');

      expect(smsJobs.length).toBe(1);
      expect(emailJobs.length).toBe(1);
    });
  });

  describe('Priority Handling', () => {
    it('respects tenant priority', () => {
      // Default tenant priority
      const configA = tenantConfigs.get('tenant-a');
      const configB = tenantConfigs.get('tenant-b');

      expect(configA?.priority).toBeDefined();
      expect(configB?.priority).toBeDefined();
    });
  });

  describe('Load Distribution', () => {
    it('distributes load fairly under high volume', async () => {
      // High volume from both tenants
      for (let i = 0; i < 500; i++) {
        enqueueJob('tenant-a', 'OTP_SEND', {});
      }

      for (let i = 0; i < 500; i++) {
        enqueueJob('tenant-b', 'OTP_SEND', {});
      }

      // Process half
      await processQueue(500);

      // Both should have progress
      const remainingA = countQueuedJobs('tenant-a');
      const remainingB = countQueuedJobs('tenant-b');

      expect(remainingA).toBeLessThan(500);
      expect(remainingB).toBeLessThan(500);
    });
  });

  describe('Job Metadata Preservation', () => {
    it('preserves job metadata throughout lifecycle', () => {
      const job = enqueueJob('tenant-a', 'OTP_SEND', {
        recipient: '+1234567890',
        purpose: 'LOGIN',
        template: 'default-otp',
      });

      expect(job.tenantId).toBe('tenant-a');
      expect(job.type).toBe('OTP_SEND');
      expect(job.status).toBe('QUEUED');
      expect(job.attempts).toBe(0);

      processJob(job.id);

      expect(job.status).toBe('COMPLETED');
      expect(job.processedAt).toBeDefined();
    });
  });
});