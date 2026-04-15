import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import * as os from 'os';

/**
 * Monitors server load by sampling CPU, memory, and event loop lag every 5 seconds.
 * Applies Exponential Moving Average (α=0.15) to smooth the composite load score.
 *
 * Composite score: 0.30·cpu + 0.30·mem + 0.40·min(1.0, lag/100)
 *
 * Implements Req 15 (resilience / adaptive tuning).
 */
@Injectable()
export class ServerLoadMonitor implements OnModuleInit, OnModuleDestroy {
  private static readonly ALPHA = 0.15;
  private static readonly SAMPLE_INTERVAL_MS = 5_000;

  private compositeScore = 0;
  private timer: NodeJS.Timeout | null = null;

  onModuleInit(): void {
    this.startSampling();
  }

  onModuleDestroy(): void {
    this.stopSampling();
  }

  getCompositeScore(): number {
    return this.compositeScore;
  }

  private startSampling(): void {
    this.timer = setInterval(() => {
      void this.sample();
    }, ServerLoadMonitor.SAMPLE_INTERVAL_MS);

    // Unref so the timer doesn't prevent process exit
    this.timer.unref();
  }

  private stopSampling(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private async sample(): Promise<void> {
    const cpu = this.measureCpu();
    const mem = this.measureMemory();
    const lag = await this.measureEventLoopLag();

    const raw =
      0.30 * cpu +
      0.30 * mem +
      0.40 * Math.min(1.0, lag / 100);

    // Apply EMA
    this.compositeScore =
      ServerLoadMonitor.ALPHA * raw +
      (1 - ServerLoadMonitor.ALPHA) * this.compositeScore;
  }

  private measureCpu(): number {
    const cpus = os.cpus();
    let totalIdle = 0;
    let totalTick = 0;

    for (const cpu of cpus) {
      const times = cpu.times;
      const total = times.user + times.nice + times.sys + times.idle + times.irq;
      totalIdle += times.idle;
      totalTick += total;
    }

    if (totalTick === 0) return 0;
    return 1 - totalIdle / totalTick;
  }

  private measureMemory(): number {
    const { heapUsed, heapTotal } = process.memoryUsage();
    if (heapTotal === 0) return 0;
    return heapUsed / heapTotal;
  }

  private measureEventLoopLag(): Promise<number> {
    return new Promise((resolve) => {
      const start = process.hrtime.bigint();
      setImmediate(() => {
        const lagNs = process.hrtime.bigint() - start;
        const lagMs = Number(lagNs) / 1_000_000;
        resolve(lagMs);
      });
    });
  }
}
