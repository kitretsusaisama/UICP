import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ICachePort } from '../../ports/driven/i-cache.port';
import { IQueuePort } from '../../ports/driven/i-queue.port';

/** Redis SET key holding all known Tor exit node IPs. */
const TOR_EXIT_NODES_KEY = 'tor-exit-nodes';

/** BullMQ queue name for the Tor list refresh job. */
const TOR_REFRESH_QUEUE = 'tor-refresh';

/** Repeatable job key — deduplicates the cron schedule. */
const TOR_REFRESH_JOB_KEY = 'tor-exit-nodes-refresh';

/** Tor Project bulk exit list URL. */
const TOR_BULK_EXIT_LIST_URL = 'https://check.torproject.org/torbulkexitlist';

/**
 * Checks whether a login IP is a known Tor exit node.
 *
 * Scoring (Section 10.1):
 *   SISMEMBER tor-exit-nodes {ip} → 0.4
 *   Otherwise                     → 0.0
 *
 * The Tor exit node list is refreshed every 6 hours via a BullMQ repeatable job.
 *
 * Implements: Req 11.7
 */
@Injectable()
export class TorExitNodeChecker implements OnModuleInit {
  private readonly logger = new Logger(TorExitNodeChecker.name);

  constructor(
    private readonly cache: ICachePort,
    private readonly queue: IQueuePort,
  ) {}

  async onModuleInit(): Promise<void> {
    // Register the repeatable refresh job (idempotent by jobKey)
    await this.queue
      .enqueueRepeatable(
        TOR_REFRESH_QUEUE,
        { url: TOR_BULK_EXIT_LIST_URL },
        {
          cron: '0 */6 * * *', // every 6 hours
          jobKey: TOR_REFRESH_JOB_KEY,
          maxAttempts: 3,
        },
      )
      .catch((err) =>
        this.logger.warn({ err }, 'Failed to register Tor refresh repeatable job'),
      );
  }

  /**
   * Returns 0.4 if the IP is a known Tor exit node, 0.0 otherwise.
   * Returns 0.0 on cache failure (fail-open for availability).
   */
  async score(ip: string): Promise<number> {
    try {
      const isTor = await this.cache.sismember(TOR_EXIT_NODES_KEY, ip);
      return isTor ? 0.4 : 0.0;
    } catch (err) {
      this.logger.warn({ err }, 'TorExitNodeChecker failed — using 0.0');
      return 0.0;
    }
  }

  /**
   * Replaces the Tor exit node list in Redis.
   * Called by the BullMQ worker after fetching the bulk exit list.
   *
   * @param ips - Array of IP addresses from the Tor bulk exit list
   */
  async refreshList(ips: string[]): Promise<void> {
    if (ips.length === 0) {
      this.logger.warn('Tor exit node list is empty — skipping refresh');
      return;
    }

    // Delete old set and re-populate atomically via pipeline
    // We use del + sadd in sequence (acceptable for a background refresh)
    await this.cache.del(TOR_EXIT_NODES_KEY);

    // SADD in batches of 500 to avoid oversized commands
    const BATCH_SIZE = 500;
    for (let i = 0; i < ips.length; i += BATCH_SIZE) {
      const batch = ips.slice(i, i + BATCH_SIZE);
      await this.cache.sadd(TOR_EXIT_NODES_KEY, ...batch);
    }

    this.logger.log({ count: ips.length }, 'Tor exit node list refreshed');
  }
}
