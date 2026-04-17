import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Inject,
  Logger,
  NotFoundException,
  Optional,
  Param,
  Post,
  Put,
  Query,
} from '@nestjs/common';
import { ApiExcludeController } from '@nestjs/swagger';
import { z } from 'zod';
import { AbacCondition } from '../../../domain/value-objects/abac-condition.vo';
import { DomainException } from '../../../domain/exceptions/domain.exception';
import { IAbacPolicyRepository, AbacPolicy } from '../../../application/ports/driven/i-abac-policy.repository';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { AbacPolicyEngine } from '../../../application/services/abac/abac-policy-engine';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';

// ── Zod schemas ───────────────────────────────────────────────────────────────

const createPolicySchema = z.object({
  name: z.string().min(1).max(200),
  effect: z.enum(['ALLOW', 'DENY']),
  priority: z.number().int().min(0).max(10000).default(100),
  subjectCondition: z.string().min(1),
  resourceCondition: z.string().min(1),
  actionCondition: z.string().min(1),
});

const updatePolicySchema = createPolicySchema.partial().extend({
  name: z.string().min(1).max(200).optional(),
});

const evaluateSchema = z.object({
  condition: z.string().min(1),
  context: z.object({
    subject: z.record(z.unknown()).default({}),
    resource: z.record(z.unknown()).default({}),
    action: z.string().default(''),
    env: z.record(z.unknown()).default({}),
  }),
});

const simulateSchema = z.object({
  subject: z.record(z.unknown()).default({}),
  resource: z.record(z.unknown()).default({}),
  action: z.string().default(''),
  env: z.record(z.unknown()).default({}),
});

// ── Controller ────────────────────────────────────────────────────────────────

/**
 * IAM Management API — ABAC policy CRUD + dry-run evaluation.
 *
 * Routes:
 *   GET    /iam/policies                — list all policies for tenant
 *   POST   /iam/policies                — create policy (DSL validated)
 *   GET    /iam/policies/:id            — get single policy
 *   PUT    /iam/policies/:id            — update policy (cache invalidated)
 *   DELETE /iam/policies/:id            — soft-delete policy (cache invalidated)
 *   POST   /iam/policies/evaluate       — dry-run condition evaluation
 *   GET    /iam/policies/simulate       — simulate all policies for a context
 *
 * Implements: Req 9.1–9.11
 */
@ApiExcludeController()
@Controller(['iam', 'v1/iam'])
export class IamController {
  private readonly logger = new Logger(IamController.name);

  constructor(
    @Inject(INJECTION_TOKENS.ABAC_POLICY_REPOSITORY)
    private readonly policyRepository: IAbacPolicyRepository,

    @Optional()
    private readonly policyEngine: AbacPolicyEngine | undefined,
  ) {}

  // ── GET /iam/policies ──────────────────────────────────────────────────────

  @Get('policies')
  async listPolicies(@Headers('x-tenant-id') rawTenantId: string) {
    const tenantId = this.parseTenantId(rawTenantId);
    const policies = await this.policyRepository.findByTenantId(tenantId);
    return { data: policies };
  }

  @Get('capabilities')
  async listCapabilities() {
    return {
      data: [
        'identity.challenge.send',
        'identity.challenge.verify',
        'identity.session.read',
        'identity.session.revoke',
        'tenant.actor.switch',
        'policy.read',
        'policy.simulate',
        'policy.explain',
      ],
    };
  }

  @Get('roles')
  async listRoles() {
    return {
      data: [
        {
          key: 'member',
          capabilities: [
            'identity.session.read',
            'identity.session.revoke',
            'tenant.actor.switch',
          ],
        },
      ],
    };
  }

  // ── POST /iam/policies ─────────────────────────────────────────────────────

  @Post('policies')
  @HttpCode(HttpStatus.CREATED)
  async createPolicy(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body() body: unknown,
  ) {
    const tenantId = this.parseTenantId(rawTenantId);

    const parsed = createPolicySchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        error: { code: 'INVALID_BODY', message: parsed.error.message },
      });
    }

    const dto = parsed.data;

    // Validate all three DSL conditions before persisting (Req 9.11)
    this.validateDsl('subjectCondition', dto.subjectCondition);
    this.validateDsl('resourceCondition', dto.resourceCondition);
    this.validateDsl('actionCondition', dto.actionCondition);

    const policy: AbacPolicy = {
      id: crypto.randomUUID(),
      tenantId: tenantId.toString(),
      name: dto.name,
      effect: dto.effect,
      priority: dto.priority,
      subjectCondition: dto.subjectCondition,
      resourceCondition: dto.resourceCondition,
      actionCondition: dto.actionCondition,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    await this.policyRepository.save(policy);
    this.policyEngine?.invalidateTenantCache(tenantId);

    this.logger.log({ policyId: policy.id, tenantId: tenantId.toString() }, 'ABAC policy created');

    return { data: policy };
  }

  // ── GET /iam/policies/evaluate ─────────────────────────────────────────────
  // NOTE: must be declared before /:id to avoid route conflict

  @Post('policies/evaluate')
  @HttpCode(HttpStatus.OK)
  async evaluateCondition(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body() body: unknown,
  ) {
    this.parseTenantId(rawTenantId); // validate tenant header

    const parsed = evaluateSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        error: { code: 'INVALID_BODY', message: parsed.error.message },
      });
    }

    const { condition, context } = parsed.data;

    // Validate DSL first
    this.validateDsl('condition', condition);

    if (!this.policyEngine) {
      throw new BadRequestException({
        error: { code: 'ENGINE_UNAVAILABLE', message: 'ABAC policy engine is not available' },
      });
    }

    const evalCtx = {
      subject: context.subject,
      resource: context.resource,
      env: context.env,
    };

    const start = Date.now();
    const { result, warnings } = this.policyEngine.evaluateCondition(condition, evalCtx);

    return {
      data: {
        result,
        matchedNodes: [],
        executionTimeMs: Date.now() - start,
        warnings,
      },
    };
  }

  // ── GET /iam/policies/simulate ─────────────────────────────────────────────

  @Get('policies/simulate')
  async simulatePolicies(
    @Headers('x-tenant-id') rawTenantId: string,
    @Query() rawQuery: Record<string, string>,
  ) {
    const tenantId = this.parseTenantId(rawTenantId);

    // Parse context from query params (JSON-encoded)
    let contextBody: unknown;
    try {
      contextBody = rawQuery['context'] ? JSON.parse(rawQuery['context']) : {};
    } catch {
      throw new BadRequestException({
        error: { code: 'INVALID_QUERY', message: 'context must be a valid JSON string' },
      });
    }

    const parsed = simulateSchema.safeParse(contextBody);
    if (!parsed.success) {
      throw new BadRequestException({
        error: { code: 'INVALID_QUERY', message: parsed.error.message },
      });
    }

    if (!this.policyEngine) {
      throw new BadRequestException({
        error: { code: 'ENGINE_UNAVAILABLE', message: 'ABAC policy engine is not available' },
      });
    }

    const ctx = parsed.data;
    const result = await this.policyEngine.simulate(tenantId, {
      subject: ctx.subject,
      resource: ctx.resource,
      action: { name: ctx.action },
      env: ctx.env,
    });

    return { data: result };
  }

  @Post('policies/explain')
  @HttpCode(HttpStatus.OK)
  async explainPolicies(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body() body: unknown,
  ) {
    const tenantId = this.parseTenantId(rawTenantId);
    const parsed = simulateSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        error: { code: 'INVALID_BODY', message: parsed.error.message },
      });
    }

    if (!this.policyEngine) {
      throw new BadRequestException({
        error: { code: 'ENGINE_UNAVAILABLE', message: 'ABAC policy engine is not available' },
      });
    }

    const ctx = parsed.data;
    const result = await this.policyEngine.simulate(tenantId, {
      subject: ctx.subject,
      resource: ctx.resource,
      action: { name: ctx.action },
      env: ctx.env,
    });

    return {
      data: {
        decision: result.decision,
        matchedPolicies: result.matchedPolicies,
        requiredStepUp: false,
        reason: result.matchedPolicies.length > 0 ? 'policy_match' : 'implicit_deny',
      },
    };
  }

  // ── GET /iam/policies/:id ──────────────────────────────────────────────────

  @Get('policies/:id')
  async getPolicy(
    @Param('id') policyId: string,
    @Headers('x-tenant-id') rawTenantId: string,
  ) {
    const tenantId = this.parseTenantId(rawTenantId);
    const policy = await this.policyRepository.findById(policyId, tenantId);

    if (!policy) {
      throw new NotFoundException({
        error: { code: 'POLICY_NOT_FOUND', message: `Policy ${policyId} not found` },
      });
    }

    return { data: policy };
  }

  // ── PUT /iam/policies/:id ──────────────────────────────────────────────────

  @Put('policies/:id')
  @HttpCode(HttpStatus.OK)
  async updatePolicy(
    @Param('id') policyId: string,
    @Headers('x-tenant-id') rawTenantId: string,
    @Body() body: unknown,
  ) {
    const tenantId = this.parseTenantId(rawTenantId);

    const existing = await this.policyRepository.findById(policyId, tenantId);
    if (!existing) {
      throw new NotFoundException({
        error: { code: 'POLICY_NOT_FOUND', message: `Policy ${policyId} not found` },
      });
    }

    const parsed = updatePolicySchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        error: { code: 'INVALID_BODY', message: parsed.error.message },
      });
    }

    const dto = parsed.data;

    // Validate any updated DSL conditions
    if (dto.subjectCondition) this.validateDsl('subjectCondition', dto.subjectCondition);
    if (dto.resourceCondition) this.validateDsl('resourceCondition', dto.resourceCondition);
    if (dto.actionCondition) this.validateDsl('actionCondition', dto.actionCondition);

    const updated: AbacPolicy = {
      ...existing,
      ...dto,
      id: policyId,
      tenantId: tenantId.toString(),
      updatedAt: new Date(),
    };

    await this.policyRepository.save(updated);
    this.policyEngine?.invalidateTenantCache(tenantId);

    this.logger.log({ policyId, tenantId: tenantId.toString() }, 'ABAC policy updated');

    return { data: updated };
  }

  // ── DELETE /iam/policies/:id ───────────────────────────────────────────────

  @Delete('policies/:id')
  @HttpCode(HttpStatus.OK)
  async deletePolicy(
    @Param('id') policyId: string,
    @Headers('x-tenant-id') rawTenantId: string,
  ) {
    const tenantId = this.parseTenantId(rawTenantId);

    const existing = await this.policyRepository.findById(policyId, tenantId);
    if (!existing) {
      throw new NotFoundException({
        error: { code: 'POLICY_NOT_FOUND', message: `Policy ${policyId} not found` },
      });
    }

    await this.policyRepository.delete(policyId, tenantId);
    this.policyEngine?.invalidateTenantCache(tenantId);

    this.logger.log({ policyId, tenantId: tenantId.toString() }, 'ABAC policy deleted');

    return { data: { deleted: true, policyId } };
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private parseTenantId(raw: string): TenantId {
    if (!raw) {
      throw new BadRequestException({
        error: { code: 'MISSING_TENANT_ID', message: 'X-Tenant-ID header is required' },
      });
    }
    try {
      return TenantId.from(raw);
    } catch {
      throw new BadRequestException({
        error: { code: 'INVALID_TENANT_ID', message: `Invalid tenant ID: ${raw}` },
      });
    }
  }

  /**
   * Validate a DSL condition string against the ABAC grammar.
   * Throws HTTP 400 with a descriptive error if invalid (Req 9.11).
   */
  private validateDsl(field: string, dsl: string): void {
    try {
      AbacCondition.parse(dsl);
    } catch (err) {
      const message = err instanceof DomainException
        ? err.message
        : `Invalid DSL in field '${field}'`;
      throw new BadRequestException({
        error: {
          code: 'INVALID_DSL',
          message,
          field,
        },
      });
    }
  }
}
