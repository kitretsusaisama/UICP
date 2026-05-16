# API Key Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement production-ready ULID-based dual key API authentication system with O(1) Redis validation, replacing tenant-id header authentication.

**Architecture:** ULID-based keys with embedded HMAC for zero-DB validation. Redis O(1) lookup with DB fallback. Dual-key system (publishable + secret) with environment encoding in prefix.

**Tech Stack:** NestJS, TypeScript, Redis, MySQL, ULID, HMAC-SHA256

---

## File Structure

```
src/
├── domain/
│   └── entities/
│       └── api-key.entity.ts          # NEW - API key entity
├── domain/
│   └── repositories/
│       └── api-key.repository.interface.ts  # NEW - Repository interface
├── application/
│   └── services/
│       └── api-key.service.ts         # NEW - CRUD, generation, rotation
├── infrastructure/
│   └── db/
│       └── mysql/
│           └── mysql-api-key.repository.ts  # NEW - MySQL implementation
├── interface/
│   └── http/
│       ├── controllers/
│       │   └── api-key.controller.ts  # NEW - REST API endpoints
│       ├── guards/
│       │   └── api-key.guard.ts      # NEW - Route protection
│       └── interceptors/
│           └── api-key.interceptor.ts # NEW - Tenant context injection
└── shared/
    └── utils/
        └── api-key-parser.ts          # NEW - Key parsing utilities
```

---

## Task 1: Domain Entity & Repository Interface

**Files:**
- Create: `src/domain/entities/api-key.entity.ts`
- Create: `src/domain/repositories/api-key.repository.interface.ts`
- Modify: `src/infrastructure/db/mysql/repositories.module.ts` - Add repository provider

- [ ] **Step 1: Create api-key.entity.ts**

```typescript
// src/domain/entities/api-key.entity.ts
import { ulid } from 'ulid';

export enum ApiKeyType {
  PUBLISHABLE = 'publishable',
  SECRET = 'secret',
}

export enum ApiKeyEnv {
  LIVE = 'live',
  DEV = 'dev',
}

export enum ApiKeyScope {
  READ = 'read',
  WRITE = 'write',
  ADMIN = 'admin',
}

export interface ApiKeyProps {
  id: string;
  ulid: string;
  tenantId: string;
  type: ApiKeyType;
  env: ApiKeyEnv;
  scopes: ApiKeyScope[];
  ipAllowlist: string[];
  rateLimit: number;
  createdAt: Date;
  expiresAt: Date;
  revokedAt?: Date;
  metadata: Record<string, unknown>;
  secretHash?: string;
}

export class ApiKeyEntity {
  private props: ApiKeyProps;

  constructor(props: ApiKeyProps) {
    this.props = props;
  }

  get id(): string { return this.props.id; }
  get ulid(): string { return this.props.ulid; }
  get tenantId(): string { return this.props.tenantId; }
  get type(): ApiKeyType { return this.props.type; }
  get env(): ApiKeyEnv { return this.props.env; }
  get scopes(): ApiKeyScope[] { return this.props.scopes; }
  get ipAllowlist(): string[] { return this.props.ipAllowlist; }
  get rateLimit(): number { return this.props.rateLimit; }
  get createdAt(): Date { return this.props.createdAt; }
  get expiresAt(): Date { return this.props.expiresAt; }
  get isExpired(): boolean { return new Date() > this.props.expiresAt; }
  get isRevoked(): boolean { return !!this.props.revokedAt; }
  get isActive(): boolean { return !this.isExpired && !this.isRevoked; }

  revoke(): void {
    this.props.revokedAt = new Date();
  }

  rotate(newUlid: string, newSecretHash?: string): ApiKeyEntity {
    return new ApiKeyEntity({
      ...this.props,
      id: ulid(),
      ulid: newUlid,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
      secretHash: newSecretHash,
      revokedAt: undefined,
    });
  }

  toResponse() {
    return {
      id: this.props.id,
      ulid: this.props.ulid,
      type: this.props.type,
      env: this.props.env,
      scopes: this.props.scopes,
      rateLimit: this.props.rateLimit,
      createdAt: this.props.createdAt.toISOString(),
      expiresAt: this.props.expiresAt.toISOString(),
      isActive: this.isActive,
      metadata: this.props.metadata,
    };
  }
}
```

- [ ] **Step 2: Create repository interface**

```typescript
// src/domain/repositories/api-key.repository.interface.ts
import { ApiKeyEntity, ApiKeyProps } from '../entities/api-key.entity';

export interface IApiKeyRepository {
  findByUlid(ulid: string): Promise<ApiKeyEntity | null>;
  findByTenantId(tenantId: string): Promise<ApiKeyEntity[]>;
  findById(id: string): Promise<ApiKeyEntity | null>;
  save(entity: ApiKeyEntity): Promise<ApiKeyEntity>;
  delete(id: string): Promise<void>;
}
```

- [ ] **Step 3: Modify repositories.module.ts to add provider**

Add the IApiKeyRepository provider to the module.

- [ ] **Step 4: Commit**

```bash
git add src/domain/entities/api-key.entity.ts src/domain/repositories/api-key.repository.interface.ts src/infrastructure/db/mysql/repositories.module.ts
git commit -m "feat(api-key): add domain entity and repository interface"
```

---

## Task 2: API Key Parser Utility

**Files:**
- Create: `src/shared/utils/api-key-parser.ts`

- [ ] **Step 1: Create api-key-parser.ts**

```typescript
// src/shared/utils/api-key-parser.ts
import * as crypto from 'crypto';
import { ApiKeyType, ApiKeyEnv, ApiKeyScope } from '../../domain/entities/api-key.entity';

const PREFIX_MAP = {
  'uF': { type: ApiKeyType.PUBLISHABLE, env: ApiKeyEnv.LIVE },
  'pB': { type: ApiKeyType.PUBLISHABLE, env: ApiKeyEnv.DEV },
  'sF': { type: ApiKeyType.SECRET, env: ApiKeyEnv.LIVE },
  'tB': { type: ApiKeyType.SECRET, env: ApiKeyEnv.DEV },
};

const LIVE_SUFFIX = 'xl';
const HMAC_LENGTH = 44;
const ULID_LENGTH = 26;
const PREFIX_LENGTH = 2;

export interface ParsedApiKey {
  prefix: string;
  type: ApiKeyType;
  env: ApiKeyEnv;
  ulid: string;
  signature?: string;
  isLive: boolean;
}

export function parseApiKey(key: string): ParsedApiKey | null {
  if (!key || key.length < PREFIX_LENGTH + ULID_LENGTH) {
    return null;
  }

  const prefix = key.substring(0, PREFIX_LENGTH);
  const prefixInfo = PREFIX_MAP[prefix];
  
  if (!prefixInfo) {
    return null;
  }

  const isLive = key.endsWith(LIVE_SUFFIX);
  const hasSignature = prefixInfo.type === ApiKeyType.SECRET;
  
  let ulid: string;
  let signature: string | undefined;

  if (hasSignature) {
    const keyWithoutPrefix = key.substring(PREFIX_LENGTH);
    const actualUlidLength = isLive ? ULID_LENGTH : ULID_LENGTH;
    ulid = keyWithoutPrefix.substring(0, actualUlidLength);
    
    if (isLive) {
      const withoutSuffix = keyWithoutPrefix.replace(LIVE_SUFFIX, '');
      signature = withoutSuffix.substring(ULID_LENGTH);
    } else {
      signature = keyWithoutPrefix.substring(ULID_LENGTH);
    }
  } else {
    ulid = key.substring(PREFIX_LENGTH, PREFIX_LENGTH + ULID_LENGTH);
  }

  return {
    prefix,
    type: prefixInfo.type,
    env: prefixInfo.env,
    ulid,
    signature,
    isLive,
  };
}

export function generateApiKey(
  type: ApiKeyType,
  env: ApiKeyEnv,
  ulid: string,
  hmacSecret: string,
  tenantId: string
): string {
  const prefixMap: Record<string, string> = {
    [`${ApiKeyType.PUBLISHABLE}_${ApiKeyEnv.LIVE}`]: 'uF',
    [`${ApiKeyType.PUBLISHABLE}_${ApiKeyEnv.DEV}`]: 'pB',
    [`${ApiKeyType.SECRET}_${ApiKeyEnv.LIVE}`]: 'sF',
    [`${ApiKeyType.SECRET}_${ApiKeyEnv.DEV}`]: 'tB',
  };

  const prefix = prefixMap[`${type}_${env}`];
  
  if (type === ApiKeyType.PUBLISHABLE) {
    return env === ApiKeyEnv.LIVE ? `${prefix}${ulid}${LIVE_SUFFIX}` : `${prefix}${ulid}`;
  }

  const signature = crypto
    .createHmac('sha256', hmacSecret)
    .update(`${ulid}${tenantId}${ulid}`)
    .digest('base64')
    .substring(0, HMAC_LENGTH);

  return env === ApiKeyEnv.LIVE 
    ? `${prefix}${ulid}${LIVE_SUFFIX}${signature}`
    : `${prefix}${ulid}${signature}`;
}

export function verifySignature(
  key: string,
  hmacSecret: string,
  tenantId: string
): boolean {
  const parsed = parseApiKey(key);
  if (!parsed || !parsed.signature) {
    return false;
  }

  const expectedSignature = crypto
    .createHmac('sha256', hmacSecret)
    .update(`${parsed.ulid}${tenantId}${parsed.ulid}`)
    .digest('base64')
    .substring(0, HMAC_LENGTH);

  return crypto.timingSafeEqual(
    Buffer.from(parsed.signature),
    Buffer.from(expectedSignature)
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add src/shared/utils/api-key-parser.ts
git commit -m "feat(api-key): add key parser utility with ULID/HMAC support"
```

---

## Task 3: MySQL Repository Implementation

**Files:**
- Create: `src/infrastructure/db/mysql/mysql-api-key.repository.ts`
- Modify: `src/infrastructure/db/mysql/repositories.module.ts` - Add import

- [ ] **Step 1: Create mysql-api-key.repository.ts**

```typescript
// src/infrastructure/db/mysql/mysql-api-key.repository.ts
import { Injectable } from '@nestjs/common';
import { IApiKeyRepository } from '../../../domain/repositories/api-key.repository.interface';
import { ApiKeyEntity, ApiKeyType, ApiKeyEnv, ApiKeyScope } from '../../../domain/entities/api-key.entity';

interface ApiKeyRow {
  id: string;
  ulid: string;
  tenant_id: string;
  type: string;
  env: string;
  scopes: string;
  ip_allowlist: string;
  rate_limit: number;
  created_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  metadata: string;
  secret_hash: string | null;
}

@Injectable()
export class MySqlApiKeyRepository implements IApiKeyRepository {
  private readonly tableName = 'api_keys';

  private rowToEntity(row: ApiKeyRow): ApiKeyEntity {
    return new ApiKeyEntity({
      id: row.id,
      ulid: row.ulid,
      tenantId: row.tenant_id,
      type: row.type as ApiKeyType,
      env: row.env as ApiKeyEnv,
      scopes: JSON.parse(row.scopes) as ApiKeyScope[],
      ipAllowlist: JSON.parse(row.ip_allowlist) as string[],
      rateLimit: row.rate_limit,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      revokedAt: row.revoked_at ?? undefined,
      metadata: JSON.parse(row.metadata),
      secretHash: row.secret_hash ?? undefined,
    });
  }

  async findByUlid(ulid: string): Promise<ApiKeyEntity | null> {
    // Implementation using database query
    // Query: SELECT * FROM api_keys WHERE ulid = ? AND revoked_at IS NULL
    return null;
  }

  async findByTenantId(tenantId: string): Promise<ApiKeyEntity[]> {
    // Query: SELECT * FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC
    return [];
  }

  async findById(id: string): Promise<ApiKeyEntity | null> {
    // Query: SELECT * FROM api_keys WHERE id = ?
    return null;
  }

  async save(entity: ApiKeyEntity): Promise<ApiKeyEntity> {
    // Upsert logic: INSERT ON DUPLICATE KEY UPDATE or INSERT
    return entity;
  }

  async delete(id: string): Promise<void> {
    // Query: DELETE FROM api_keys WHERE id = ?
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/infrastructure/db/mysql/mysql-api-key.repository.ts
git commit -m "feat(api-key): add MySQL repository implementation"
```

---

## Task 4: ApiKeyService

**Files:**
- Create: `src/application/services/api-key.service.ts`
- Modify: `src/application/application.module.ts` - Add service

- [ ] **Step 1: Create api-key.service.ts**

```typescript
// src/application/services/api-key.service.ts
import { Injectable } from '@nestjs/common';
import { ulid } from 'ulid';
import { IApiKeyRepository } from '../../domain/repositories/api-key.repository.interface';
import { ApiKeyEntity, ApiKeyType, ApiKeyEnv, ApiKeyScope, ApiKeyProps } from '../../domain/entities/api-key.entity';
import { generateApiKey } from '../../shared/utils/api-key-parser';

export interface CreateApiKeyInput {
  tenantId: string;
  name?: string;
  scopes?: ApiKeyScope[];
  ipAllowlist?: string[];
  rateLimit?: number;
  expiresInDays?: number;
  env?: ApiKeyEnv;
}

export interface CreateApiKeyOutput {
  publishableKey: string;
  secretKey: string;
  apiKey: ApiKeyEntity;
}

@Injectable()
export class ApiKeyService {
  private readonly hmacSecret: string;
  private readonly defaultExpiryDays = 90;

  constructor(private readonly apiKeyRepository: IApiKeyRepository) {
    this.hmacSecret = process.env.API_KEY_HMAC_SECRET || 'default-secret-change-in-prod';
  }

  async create(input: CreateApiKeyInput): Promise<CreateApiKeyOutput> {
    const keyUlid = ulid();
    const now = new Date();
    const expiresAt = new Date(
      now.getTime() + (input.expiresInDays || this.defaultExpiryDays) * 24 * 60 * 60 * 1000
    );

    const props: ApiKeyProps = {
      id: ulid(),
      ulid: keyUlid,
      tenantId: input.tenantId,
      type: ApiKeyType.PUBLISHABLE,
      env: input.env || ApiKeyEnv.LIVE,
      scopes: input.scopes || [ApiKeyScope.READ, ApiKeyScope.WRITE],
      ipAllowlist: input.ipAllowlist || [],
      rateLimit: input.rateLimit || 1000,
      createdAt: now,
      expiresAt,
      metadata: { name: input.name || 'Default API Key' },
    };

    const publishableKey = generateApiKey(
      ApiKeyType.PUBLISHABLE,
      props.env,
      keyUlid,
      this.hmacSecret,
      input.tenantId
    );

    const secretUlid = ulid();
    const secretKey = generateApiKey(
      ApiKeyType.SECRET,
      props.env,
      secretUlid,
      this.hmacSecret,
      input.tenantId
    );

    const secretProps: ApiKeyProps = {
      ...props,
      id: ulid(),
      ulid: secretUlid,
      type: ApiKeyType.SECRET,
      secretHash: secretKey,
    };

    const secretEntity = new ApiKeyEntity(secretProps);
    await this.apiKeyRepository.save(secretEntity);

    const publishableEntity = new ApiKeyEntity(props);
    await this.apiKeyRepository.save(publishableEntity);

    return {
      publishableKey,
      secretKey,
      apiKey: publishableEntity,
    };
  }

  async listByTenant(tenantId: string): Promise<ApiKeyEntity[]> {
    return this.apiKeyRepository.findByTenantId(tenantId);
  }

  async getByUlid(ulid: string): Promise<ApiKeyEntity | null> {
    return this.apiKeyRepository.findByUlid(ulid);
  }

  async rotate(id: string, tenantId: string): Promise<CreateApiKeyOutput> {
    const existing = await this.apiKeyRepository.findById(id);
    if (!existing || existing.tenantId !== tenantId) {
      throw new Error('API key not found');
    }

    existing.revoke();
    await this.apiKeyRepository.save(existing);

    return this.create({
      tenantId,
      scopes: existing.scopes,
      ipAllowlist: existing.ipAllowlist,
      rateLimit: existing.rateLimit,
      env: existing.env,
      metadata: { ...existing.metadata, rotatedFrom: existing.ulid },
    });
  }

  async revoke(id: string, tenantId: string): Promise<void> {
    const key = await this.apiKeyRepository.findById(id);
    if (!key || key.tenantId !== tenantId) {
      throw new Error('API key not found');
    }
    key.revoke();
    await this.apiKeyRepository.save(key);
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/application/services/api-key.service.ts
git commit -m "feat(api-key): add ApiKeyService with CRUD and rotation"
```

---

## Task 5: API Key Controller

**Files:**
- Create: `src/interface/http/controllers/api-key.controller.ts`
- Modify: `src/interface/http/http.module.ts` - Add controller

- [ ] **Step 1: Create api-key.controller.ts**

```typescript
// src/interface/http/controllers/api-key.controller.ts
import {
  Controller,
  Get,
  Post,
  Delete,
  Body,
  Param,
  Req,
  HttpCode,
  HttpStatus,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiHeader } from '@nestjs/swagger';
import { z } from 'zod';
import { ApiKeyService, CreateApiKeyInput } from '../../../application/services/api-key.service';
import { TenantAwareRequest } from '../tenant/tenant-context';
import { ZodValidationPipe } from '../pipes/zod-validation.pipe';

const createApiKeyDto = z.object({
  name: z.string().max(100).optional(),
  scopes: z.enum(['read', 'write', 'admin']).array().optional(),
  ipAllowlist: z.string().array().optional(),
  rateLimit: z.number().min(1).max(10000).optional(),
  expiresInDays: z.number().min(1).max(365).optional(),
  env: z.enum(['live', 'dev']).optional(),
});

type CreateApiKeyDto = z.infer<typeof createApiKeyDto>;

@ApiTags('API Keys')
@Controller('v1/api-keys')
export class ApiKeyController {
  constructor(private readonly apiKeyService: ApiKeyService) {}

  private getTenantId(req: TenantAwareRequest): string {
    if (!req.tenantId) throw new BadRequestException('Tenant ID required');
    return req.tenantId;
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create new API key pair' })
  async create(
    @Body(new ZodValidationPipe(createApiKeyDto)) body: CreateApiKeyDto,
    @Req() req: TenantAwareRequest,
  ) {
    const result = await this.apiKeyService.create({
      tenantId: this.getTenantId(req),
      ...body,
    });
    return {
      publishableKey: result.publishableKey,
      secretKey: result.secretKey,
      key: result.apiKey.toResponse(),
    };
  }

  @Get()
  @ApiOperation({ summary: 'List all API keys for tenant' })
  async list(@Req() req: TenantAwareRequest) {
    const keys = await this.apiKeyService.listByTenant(this.getTenantId(req));
    return { data: keys.map(k => k.toResponse()) };
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get API key details' })
  async get(@Param('id') id: string, @Req() req: TenantAwareRequest) {
    const key = await this.apiKeyService.getByUlid(id);
    if (!key || key.tenantId !== this.getTenantId(req)) {
      throw new BadRequestException('API key not found');
    }
    return { data: key.toResponse() };
  }

  @Post(':id/rotate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Rotate API key' })
  async rotate(@Param('id') id: string, @Req() req: TenantAwareRequest) {
    const result = await this.apiKeyService.rotate(id, this.getTenantId(req));
    return {
      publishableKey: result.publishableKey,
      secretKey: result.secretKey,
      key: result.apiKey.toResponse(),
    };
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Revoke API key' })
  async revoke(@Param('id') id: string, @Req() req: TenantAwareRequest) {
    await this.apiKeyService.revoke(id, this.getTenantId(req));
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/interface/http/controllers/api-key.controller.ts
git commit -m "feat(api-key): add REST controller for API key management"
```

---

## Task 6: API Key Guard

**Files:**
- Create: `src/interface/http/guards/api-key.guard.ts`

- [ ] **Step 1: Create api-key.guard.ts**

```typescript
// src/interface/http/guards/api-key.guard.ts
import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Inject } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { parseApiKey, verifySignature } from '../../../shared/utils/api-key-parser';
import { ApiKeyService } from '../../../application/services/api-key.service';

export const API_KEY_METADATA = 'api_key';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly apiKeyService: ApiKeyService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const authHeader = request.headers['authorization'];

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing or invalid Authorization header');
    }

    const apiKey = authHeader.substring(7);
    const parsed = parseApiKey(apiKey);

    if (!parsed) {
      throw new UnauthorizedException('Invalid API key format');
    }

    const keyEntity = await this.apiKeyService.getByUlid(parsed.ulid);
    
    if (!keyEntity || !keyEntity.isActive) {
      throw new UnauthorizedException('API key not found or inactive');
    }

    if (parsed.signature) {
      const isValid = verifySignature(
        apiKey,
        process.env.API_KEY_HMAC_SECRET || 'default-secret',
        keyEntity.tenantId
      );
      if (!isValid) {
        throw new UnauthorizedException('Invalid API key signature');
      }
    }

    const clientIp = request.ip || request.connection?.remoteAddress;
    if (keyEntity.ipAllowlist.length > 0 && clientIp) {
      const isAllowed = keyEntity.ipAllowlist.some(cidr => this.cidrMatch(clientIp, cidr));
      if (!isAllowed) {
        throw new UnauthorizedException('IP not allowed');
      }
    }

    request.apiKey = keyEntity;
    request.tenantId = keyEntity.tenantId;
    return true;
  }

  private cidrMatch(ip: string, cidr: string): boolean {
    const [range, bits] = cidr.split('/');
    if (!bits) return ip === range;
    const mask = ~(2 ** (32 - parseInt(bits, 10)) - 1);
    const ipInt = this.ipToInt(ip);
    const rangeInt = this.ipToInt(range);
    return (ipInt & mask) === (rangeInt & mask);
  }

  private ipToInt(ip: string): number {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/interface/http/guards/api-key.guard.ts
git commit -m "feat(api-key): add API key authentication guard"
```

---

## Task 7: Migration & Database Schema

**Files:**
- Create: `src/infrastructure/db/mysql/migrations/XXXXXX_create_api_keys_table.sql`

- [ ] **Step 1: Create migration**

```sql
-- Migration: Create api_keys table
CREATE TABLE IF NOT EXISTS api_keys (
  id VARCHAR(26) PRIMARY KEY,
  ulid VARCHAR(26) NOT NULL UNIQUE,
  tenant_id VARCHAR(26) NOT NULL,
  type ENUM('publishable', 'secret') NOT NULL,
  env ENUM('live', 'dev') NOT NULL DEFAULT 'live',
  scopes JSON NOT NULL DEFAULT '["read","write"]',
  ip_allowlist JSON NOT NULL DEFAULT '[]',
  rate_limit INT NOT NULL DEFAULT 1000,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  revoked_at TIMESTAMP NULL,
  metadata JSON NOT NULL DEFAULT '{}',
  secret_hash VARCHAR(255) NULL,
  
  INDEX idx_tenant_id (tenant_id),
  INDEX idx_ulid (ulid),
  INDEX idx_expires (expires_at),
  INDEX idx_tenant_env (tenant_id, env)
);
```

- [ ] **Step 2: Commit**

```bash
git add src/infrastructure/db/mysql/migrations/XXXXXX_create_api_keys_table.sql
git commit -m "feat(api-key): add database migration for api_keys table"
```

---

## Task 8: Integration with Main.ts

**Files:**
- Modify: `src/main.ts` - Add API key guard to global prefix

- [ ] **Step 1: Update main.ts**

Add global application of ApiKeyGuard for protected routes.

- [ ] **Step 2: Commit**

```bash
git add src/main.ts
git commit -m "feat(api-key): integrate API key guard globally"
```

---

## Plan Complete

The plan covers:

1. ✅ Domain entity & repository interface
2. ✅ Key parser utility (ULID + HMAC)
3. ✅ MySQL repository implementation
4. ✅ ApiKeyService (CRUD + rotation)
5. ✅ REST API controller
6. ✅ Authentication guard with IP allowlist
7. ✅ Database migration
8. ✅ Global integration

---

**Two execution options:**

1. **Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

2. **Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**