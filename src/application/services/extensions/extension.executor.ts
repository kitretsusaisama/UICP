import { KmsService } from '../platform/kms.service';
import { Injectable, Inject, UnauthorizedException, BadRequestException, GatewayTimeoutException, ForbiddenException } from '@nestjs/common';
import { ExtensionRegistryService, CommandContext } from './extension.registry';
import { CACHE_ADAPTER } from '../../../../src/domain/repositories/cache.repository.interface';
import { CacheAdapter } from '../../../../src/infrastructure/cache/redis-cache.adapter';
import { IAppRepository } from '../../../../src/domain/repositories/platform/app.repository.interface';
import { PolicyService } from '../governance/policy.service';
import { MetricsService } from '../platform-ops/metrics.service';
import * as crypto from 'crypto';

@Injectable()
export class ExtensionExecutorService {
  constructor(
    private readonly registry: ExtensionRegistryService,
    @Inject(CACHE_ADAPTER) private readonly cache: CacheAdapter,
    @Inject('APP_REPOSITORY') private readonly appRepo: IAppRepository,
    private readonly policyService: PolicyService,
    private readonly metrics: MetricsService,

  ) {}

  public async executeCommand(
    ctx: CommandContext,
    extensionKey: string,
    commandKey: string,
    parsedPayload: any,
    rawPayloadStr: string,
    signature: string,
    timestamp: number,
    nonce: string
  ) {
    const startMs = Date.now();
    try {
      const ext = this.registry.getExtension(extensionKey);
      const cmd = this.registry.getCommandMetadata(extensionKey, commandKey);
      const handler = this.registry.getHandler(extensionKey, commandKey);

      // STEP 1 & 2: Signature and Nonce Validation using raw exact payload string
      if (cmd.requiresSignature) {
         await this.validateSignature(ctx.appId, rawPayloadStr, signature, timestamp, nonce);
      }

      // STEP 3: Schema Validation (Zod Strict)
      const validPayload = cmd.inputSchema.parse(parsedPayload);

      // STEP 4: Rate Limiting (Atomic Redis Lua)
      await this.enforceRateLimit(ctx.tenantId, extensionKey, commandKey, cmd.rateLimitConfig);

      // STEP 5: ABAC/RBAC Check
      await this.enforceAbac(ctx, cmd.requiredPermission, extensionKey);

      // STEP 6: Execution with Timeout Guard (2 seconds)
      const result = await Promise.race([
        handler(ctx, validPayload),
        new Promise((_, reject) => setTimeout(() => reject(new GatewayTimeoutException('Command execution timed out')), 2000))
      ]);

      // STEP 7: Audit Log Output
      const payloadHash = crypto.createHash('sha256').update(rawPayloadStr).digest('hex');
      this.metrics.extensionCommandTotal?.inc();

      return {
         status: 'SUCCESS',
         result,
         audit: {
           event: 'EXTENSION_COMMAND_EXECUTED',
           extensionKey,
           commandKey,
           actorId: ctx.actorId,
           tenantId: ctx.tenantId,
           requestId: ctx.requestId,
           payloadHash
         }
      };
    } catch (error: any) {
      this.metrics.extensionCommandFailed?.inc();
      throw error;
    } finally {
      this.metrics.extensionCommandLatency?.observe(Date.now() - startMs);
    }
  }

  private async validateSignature(appId: string, rawPayloadStr: string, signature: string, timestamp: number, nonce: string) {
    // 1. Timestamp Drift (± 5 minutes)
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestamp) > 300) {
      throw new UnauthorizedException('Signature timestamp drift exceeded 5 minutes');
    }

    // 2. Nonce Replay Protection (Redis SET NX)
    const nonceKey = `nonce:${nonce}`;
    const acquired = await this.cache.setnx(nonceKey, '1', 300);
    if (!acquired) {
      throw new UnauthorizedException('Replay attack detected: Nonce already used');
    }

    // 3. Signature Hash Validation
    const secretEntities = await this.secretRepo.findByAppId(appId);
    if (!secretEntities || secretEntities.length === 0) {
      throw new UnauthorizedException('App secret not found for signature validation');
    }

    const payloadHash = crypto.createHash('sha256').update(rawPayloadStr).digest('hex');
    const signatureBase = `${payloadHash}${timestamp}${nonce}`;

    // In a secure architecture, we retrieve the raw secret from an internal KMS to compute HMAC
    const rawSecret = await this.kmsService.getRawSecret(appId);
    if (!rawSecret) throw new UnauthorizedException('KMS Error: Unable to resolve signing material');

    const expectedSignature = crypto.createHmac('sha256', rawSecret).update(signatureBase).digest('hex');

    if (signature !== expectedSignature) {
      throw new UnauthorizedException('Invalid payload signature');
    }
  }

  private async enforceRateLimit(tenantId: string, ext: string, cmd: string, config: { limit: number, window: number }) {
    const key = `rate:ext:${tenantId}:${ext}:${cmd}`;
    // Fixed: Non-atomic INCR + EXPIRE replaced with Lua script per Phase 10 directives
    const luaScript = `
      local current = redis.call('INCR', KEYS[1])
      if current == 1 then
          redis.call('EXPIRE', KEYS[1], ARGV[1])
      end
      return current
    `;
    const client = (this.cache as any).getClient?.();
    let current = 0;
    if (client && typeof client.eval === 'function') {
       current = await client.eval(luaScript, 1, key, config.window);
    } else {
       // Fallback ONLY if ioredis client access fails
       current = await this.cache.incr(key);
       if (current === 1) await this.cache.expire(key, config.window);
    }
    if (current > config.limit) {
      throw new BadRequestException('Extension rate limit exceeded');
    }
  }

  private async enforceAbac(ctx: CommandContext, requiredPermission: string, resource: string) {
    const hasAccess = await this.policyService.evaluate(ctx.actorId, ctx.tenantId, resource, requiredPermission, { extension: true });
    if (!hasAccess) {
       throw new ForbiddenException(`Lacking permission ${requiredPermission} for resource ${resource}`);
    }
  }
}
