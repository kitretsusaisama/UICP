import { Module } from '@nestjs/common';
import { AtomicRateLimiterService } from './atomic-rate-limiter.service';
import { CacheModule } from '../cache/cache.module';

@Module({
  imports: [CacheModule],
  providers: [AtomicRateLimiterService],
  exports: [AtomicRateLimiterService],
})
export class RateLimitModule {}