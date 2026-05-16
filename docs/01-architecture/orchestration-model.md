# Orchestration Model

## Metadata
```yaml
title: Orchestration Model
domain: runtime
owner: Runtime Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - queue-first-design.md
  - event-driven-runtime.md
related-docs:
  - runtime-summary.md
  - dependency-model.md
related-queues:
  - all-queues
```

---

## Overview

The orchestration model defines how components coordinate to process requests. UICP uses a layered orchestration approach with clear separation between HTTP handling, business logic, and external operations.

---

## Orchestration Layers

### Layer 1: HTTP Handling

```typescript
@Controller('messages')
export class MessageController {
  constructor(
    private readonly sendMessageHandler: SendMessageHandler,
  ) {}

  @Post()
  @UseGuards(UnifiedAuthGuard)
  async sendMessage(
    @Req() req: Request,
    @Body() dto: SendMessageDto,
    @Headers('x-idempotency-key') idempotencyKey?: string
  ) {
    // 1. Get tenant context from request (set by guard)
    const context = req['tenantContext'] as TenantContext;

    // 2. Generate idempotency key if not provided
    const key = idempotencyKey || generateIdempotencyKey('send-message', context.tenantId, dto);

    // 3. Execute command handler
    const result = await this.sendMessageHandler.execute({
      ...dto,
      tenantId: context.tenantId,
      userId: context.userId,
      idempotencyKey: key,
    });

    return result;
  }
}
```

### Layer 2: Command/Query Handling

```typescript
@CommandHandler(SendMessageCommand)
export class SendMessageHandler {
  constructor(
    private readonly messageRepository: IMessageRepository,
    private readonly queueService: IQueueService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  async execute(command: SendMessageCommand): Promise<SendMessageResult> {
    // 1. Validate command
    await this.validate(command);

    // 2. Check quota
    await this.quotaService.check(command.tenantId, 'messages');

    // 3. Determine async vs sync
    const isAsync = this.shouldBeAsync(command.channel);

    if (isAsync) {
      // 4a. Enqueue job for async processing
      const jobId = await this.queueService.enqueue('message-delivery', {
        ...command,
        priority: command.priority || 'normal',
      });

      return { jobId, status: 'queued' };
    } else {
      // 4b. Process synchronously (rare, for critical notifications)
      const result = await this.processDirect(command);
      return { messageId: result.messageId, status: 'sent' };
    }
  }
}
```

### Layer 3: Queue Processing

```typescript
@Processor('message-delivery')
export class MessageDeliveryProcessor {
  constructor(
    private readonly providerRouter: ProviderRouter,
    private readonly messageRepository: IMessageRepository,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  @Process()
  async processJob(job: Job<MessageJobData>): Promise<void> {
    const { tenantId, channel, content, idempotencyKey } = job.data;

    // 1. Check idempotency (prevent duplicates)
    const exists = await this.messageRepository.findByIdempotencyKey(idempotencyKey);
    if (exists) {
      this.logger.log(`Skipping duplicate job: ${idempotencyKey}`);
      return;
    }

    // 2. Select provider
    const provider = await this.providerRouter.selectProvider(channel, tenantId, {
      to: content.to,
      channel,
      content,
    });

    // 3. Send message
    const result = await provider.send({
      to: content.to,
      channel,
      content,
    });

    // 4. Store result
    await this.messageRepository.save({
      idempotencyKey,
      tenantId,
      channel,
      provider: provider.type,
      status: result.success ? 'sent' : 'failed',
      providerMessageId: result.messageId,
      error: result.error,
    });

    // 5. Emit event
    this.eventEmitter.emit('message.delivered', {
      messageId: idempotencyKey,
      tenantId,
      success: result.success,
      provider: provider.type,
    });
  }
}
```

---

## Error Handling

### Retry Logic

```typescript
async function handleJobFailure(job: Job, error: Error): Promise<void> {
  const attempts = job.attemptsMade;
  const maxAttempts = job.opts.attempts;

  if (attempts < maxAttempts) {
    // Retry with exponential backoff
    const delay = Math.pow(2, attempts) * 1000;
    this.logger.warn(`Job failed, retrying in ${delay}ms`, { jobId: job.id, error: error.message });
    await job.update({ attempts: attempts + 1 });
    throw new Error(error.message); // Triggers retry
  } else {
    // Move to DLQ
    this.logger.error(`Job exhausted retries, moving to DLQ`, { jobId: job.id, error: error.message });
    await job.moveToFailed(new Error('Max retries exceeded'));
  }
}
```

### Circuit Breaker

```typescript
class CircuitBreaker {
  private failures = 0;
  private lastFailure: Date | null = null;
  private state: 'closed' | 'open' | 'half-open' = 'closed';

  async call<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === 'open') {
      if (Date.now() - this.lastFailure! > 30000) {
        this.state = 'half-open';
      } else {
        throw new CircuitOpenException();
      }
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    this.failures = 0;
    this.state = 'closed';
  }

  private onFailure(): void {
    this.failures++;
    this.lastFailure = new Date();
    if (this.failures >= 5) {
      this.state = 'open';
    }
  }
}
```

---

## Coordination Patterns

### Sequential Processing

For operations requiring strict ordering:

```typescript
// Process steps sequentially (e.g., multi-step verification)
async function processSequential<T>(steps: Step<T>[]): Promise<T> {
  let result: T;

  for (const step of steps) {
    result = await step.execute(result);
  }

  return result;
}
```

### Parallel Processing

For independent operations:

```typescript
// Process multiple messages in parallel
async function processParallel<T>(items: T[], processor: (item: T) => Promise<void>): Promise<void> {
  const chunks = chunk(items, 10); // Process 10 at a time
  for (const chunk of chunks) {
    await Promise.all(chunk.map(processor));
  }
}
```

---

## Related Documents

- `queue-first-design.md`
- `event-driven-runtime.md`
- `dependency-model.md`
- `02-runtime/request-lifecycle.md`