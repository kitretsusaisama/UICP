import { Injectable, CanActivate, ExecutionContext, Inject, ServiceUnavailableException } from '@nestjs/common';
import { QueueAdapter } from '../../../../src/infrastructure/queue/bullmq-queue.adapter';

@Injectable()
export class QueueBackpressureGuard implements CanActivate {
  constructor(@Inject('QUEUE_ADAPTER') private readonly queue: QueueAdapter) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();

    // Check critical queues (e.g. otp-send)
    const otpQueue = this.queue.getQueue('otp-send');
    if (!otpQueue) return true;

    try {
      // Evaluate multi-signal backpressure
      // 1. Queue depth
      const waitingCount = await otpQueue.getWaitingCount();
      // 2. Worker saturation (active count implies workers are busy)
      const activeCount = await otpQueue.getActiveCount();

      // We can also poll latency metrics if they exist in Redis, but waiting + active is a strong proxy for delay
      if (waitingCount > 5000 && activeCount > 50) {
         throw new ServiceUnavailableException({
           code: 'QUEUE_OVERLOADED',
           message: 'System busy, please retry later',
           retryAfter: 5
         });
      }
    } catch (e: any) {
      if (e instanceof ServiceUnavailableException) throw e;
      // If Redis is down for the queue check itself, degrade to fail-open for the HTTP layer
      // (The actual queue addition in the service will fail anyway if Redis is truly down)
      console.warn('QueueBackpressureGuard failed to evaluate metrics', e);
    }

    return true;
  }
}
