# UICP P0 Security Hardening Plan

  My Recommendation

  Approach A (Layered Security-First) — This prioritizes the P0 security fixes before any new      
  features, which aligns with your requirement. The Big Bang rewrite of core systems (ABAC, rate   
  limiter) can happen in Phase 0, then enterprise features build on that secure foundation.        

  ---
  Question: Does this approach align with your vision? If so, I'll present the detailed design     
  sections covering architecture, components, data flow, and implementation order.

✻ Crunched for 6m 6s

❯ ok                                                                                               

● Let me present the design in sections. I'll start with the overall architecture.

  ---
  Section 1: Architecture Overview

  System Context  
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                              CLIENTS                                        │
  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
  │  │   Web App   │  │ Mobile App  │  │  SDK (TS)   │  │   Python    │        │
  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘        │
  └─────────┼────────────────┼────────────────┼────────────────┼───────────────┘
            │                │                │                │
            ▼                ▼                ▼                ▼
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                         API GATEWAY (Envoy/Cloudflare)                     │
  │              Rate Limiting │ WAF │ Geo-fencing │ JWT Validation            │
  └─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                        UICP NESTJS APPLICATION                             │
  │  ┌─────────────────────────────────────────────────────────────────────┐   │
  │  │                    SECURITY LAYER (P0)                              │   │
  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │   │
  │  │  │ABAC AST      │  │OTP Cost      │  │Atomic Rate  │               │   │
  │  │  │Interpreter   │  │Controller    │  │Limiter (Lua) │               │   │
  │  │  └──────────────┘  └──────────────┘  └──────────────┘               │   │
  │  └─────────────────────────────────────────────────────────────────────┘   │
  │  ┌─────────────────────────────────────────────────────────────────────┐   │
  │  │                    CONTRACT LAYER                                    │   │
  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │   │
  │  │  │OpenAPI 3.1   │  │Zod DTOs      │  │Versioning    │               │   │
  │  │  └──────────────┘  └──────────────┘  └──────────────┘               │   │
  │  └─────────────────────────────────────────────────────────────────────┘   │
  │  ┌─────────────────────────────────────────────────────────────────────┐   │
  │  │                    QUERY/MUTATION LAYER                              │   │
  │  │  ┌──────────────┐  ┌──────────────┐                                 │   │
  │  │  │  GraphQL    │  │   REST API   │                                 │   │
  │  │  │ (Dashboard) │  │  (Mutations) │                                 │   │
  │  │  └──────────────┘  └──────────────┘                                 │   │
  │  └─────────────────────────────────────────────────────────────────────┘   │
  │  ┌─────────────────────────────────────────────────────────────────────┐   │
  │  │                    DOMAIN CORE (Hexagonal)                          │   │
  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │   │
  │  │  │  Identity   │  │  Sessions    │  │  Extensions  │               │   │
  │  │  └──────────────┘  └──────────────┘  └──────────────┘               │   │
  │  └─────────────────────────────────────────────────────────────────────┘   │
  └─────────────────────────────────────────────────────────────────────────────┘
                                      │
            ┌─────────────────────────┼─────────────────────────┐
            ▼                         ▼                         ▼
  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
  │   MySQL         │    │   Redis         │    │   Kafka         │
  │   (Primary)     │    │   (Sessions/    │    │   (Audit Log    │
  │                 │    │    Rate Limit)  │    │    Stream)      │
  └─────────────────┘    └─────────────────┘    └─────────────────┘

  Module Boundaries

  1. Security Layer — Zero-trust, fails-closed, no dynamic code execution
  2. Contract Layer — OpenAPI-first, Zod validation, semantic versioning
  3. Query/Mutation Layer — GraphQL for reads, REST for writes
  4. Domain Core — Pure business logic, no framework dependencies

 Section 2: P0 Security Hardening

  2.1 ABAC Engine Replacement

  Current Issue: AbacJitCompiler uses new Function to compile tenant policies → RCE vulnerability. 

  Solution: Replace with AST-based interpreter (no code generation).

  // src/domain/policy/interpreter/abac-ast-interpreter.ts
  interface AbacNode {
    type: 'condition' | 'action' | 'resource' | 'logical'
    operator?: 'eq' | 'in' | 'regex' | 'greaterThan' | 'lessThan'
    left?: string  // path like "ctx.subject.role"
    right?: unknown
    children?: AbacNode[]
  }

  // Evaluation: traverse AST, never execute arbitrary code
  evaluate(node: AbacNode, context: PolicyContext): boolean {
    switch (node.type) {
      case 'logical':
        if (node.operator === 'and') {
          return node.children.every(c => this.evaluate(c, context))
        }
        // ... other operators
      case 'condition':
        return this.evalCondition(node, context)
    }
  }

  File Changes:
  - Delete: src/infrastructure/governance/policy/abac-jit-compiler.ts
  - Create: src/domain/policy/interpreter/abac-ast-interpreter.ts
  - Create: src/domain/policy/parser/abac-policy-parser.ts (parses JSON/Rego → AST)

  ---
  2.2 Atomic Rate Limiting

  Current Issue: Redis INCR + EXPIRE is non-atomic → permanent DoS on crash.

  Solution: Lua script for atomic increment + expiry.

  -- src/infrastructure/rate-limit/sliding-window.lua
  local key = KEYS[1]
  local window = tonumber(ARGV[1])
  local limit = tonumber(ARGV[2])

  local current = redis.call('GET', key)
  if current and tonumber(current) >= limit then
    return -1
  end

  local count = redis.call('INCR', key)
  if count == 1 then
    redis.call('EXPIRE', key, window)
  end
  return count

  File Changes:
  - Create: src/infrastructure/rate-limit/sliding-window.lua
  - Create: src/infrastructure/rate-limit/atomic-rate-limiter.service.ts
  - Modify: Replace all RateLimiterMiddleware usages

  ---
  2.3 OTP Cost Controller

  Current Issue: No spend limits → unlimited SMS cost explosion.

  Solution: Token bucket with circuit breaker per tenant.

  // src/application/services/otp/otp-cost-controller.service.ts
  interface OtpSpendQuota {
    tenantId: string
    dailyLimit: number        // e.g., ₹10,000
    spentToday: number
    windowStart: Date
    circuitState: 'closed' | 'open' | 'half-open'
  }

  async sendOtp(tenantId: string, phone: string): Promise<OtpResult> {
    const quota = await this.getQuota(tenantId)

    if (quota.circuitState === 'open') {
      throw new OtpSpendLimitExceededError(tenantId)
    }

    if (quota.spentToday >= quota.dailyLimit) {
      await this.openCircuit(tenantId)
      throw new OtpSpendLimitExceededError(tenantId)
    }

    const result = await this.gateway.send(phone)
    await this.incrementSpend(tenantId, result.cost)

    if (quota.spentToday + result.cost > quota.dailyLimit * 0.9) {
      await this.notifySlack(`⚠️ ${tenantId} at 90% OTP budget`)
    }

    return result
  }

  File Changes:
  - Create: src/application/services/otp/otp-cost-controller.service.ts
  - Create: src/infrastructure/otp/gateway-composite.service.ts (Firebase + Twilio fallback)       
  - Create: src/application/guards/otp-spend-limit.guard.ts

  ---
  2.4 Deployment Order

  ┌──────┬──────────────────────┬────────────────────────────────────────────┐
  │ Step │      Component       │                    Risk                    │
  ├──────┼──────────────────────┼────────────────────────────────────────────┤
  │ 1    │ ABAC AST Interpreter │ Low — new component, no existing deps      │
  ├──────┼──────────────────────┼────────────────────────────────────────────┤
  │ 2    │ Lua Rate Limiter     │ Medium — swaps implementation              │
  ├──────┼──────────────────────┼────────────────────────────────────────────┤
  │ 3    │ OTP Cost Controller  │ High — adds enforcement, may block traffic │
  └──────┴──────────────────────┴────────────────────────────────────────────┘

  Rollback: Each component has feature flag. If P0 fix fails, flip flag to revert to old behavior. 

Section 3: Contract-First API & DTO Layer

  3.1 OpenAPI 3.1 Specification Structure                                                          

  Current Issue: API contracts are generated from code (reverse-engineered), not defined upfront.  

  Solution: Define contracts first, then generate DTOs and validate implementation against spec.

  src/
  ├── docs/
  │   └── openapi/
  │       ├── v1/
  │       │   ├── auth.yaml
  │       │   ├── user.yaml
  │       │   ├── session.yaml
  │       │   └── admin.yaml
  │       └── v2/
  │           └── ...
  └── interface/http/
      └── dto/
          └── (generated from OpenAPI)

  Example: auth.yaml

  openapi: 3.1.0
  info:
    title: UICP Auth API
    version: 1.0.0
  servers:
    - url: https://api.uicp.io/v1
  paths:
    /auth/signup/email:
      post:
        summary: Email signup
        operationId: signupEmail
        requestBody:
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SignupEmailRequest'
        responses:
          '201':
            description: User created
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/SignupEmailResponse'
          '400':
            $ref: '#/components/responses/ValidationError'
  components:
    schemas:
      SignupEmailRequest:
        type: object
        required:
          - email
          - password
          - tenantId
        properties:
          email:
            type: string
            format: email
            maxLength: 255
          password:
            type: string
            minLength: 8
            maxLength: 128
            format: password
          tenantId:
            $ref: '#/components/schemas/Uuid'
      SignupEmailResponse:
        type: object
        properties:
          userId:
            $ref: '#/components/schemas/Uuid'
          email:
            type: string
          createdAt:
            type: string
            format: date-time
    responses:
      ValidationError:
        description: Invalid request
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ErrorResponse'

  ---
  3.2 Zod DTO Generation

  Strategy: Use openapi-zod-client to generate Zod schemas from OpenAPI specs.

  // src/interface/http/dto/index.ts (auto-generated)
  // This file is GENERATED, not edited manually
  import { z } from 'zod'

  export const SignupEmailRequestSchema = z.object({
    email: z.string().email().max(255),
    password: z.string().min(8).max(128),
    tenantId: UuidSchema,
  })

  export type SignupEmailRequest = z.infer<typeof SignupEmailRequestSchema>

  Workflow:
  1. Edit docs/openapi/v1/auth.yaml
  2. Run npm run generate:dto → generates .ts files
  3. Controller imports from generated DTO

  ---
  3.3 API Versioning Strategy

  Approach: URL-based versioning with deprecation headers.

  GET /v1/auth/login
  GET /v2/auth/login  ← new format

  // src/interface/http/versioning.ts
  export const API_VERSIONS = {
    V1: '1.0.0',
    V2: '2.0.0',
  } as const

  export const DEPRECATION_HEADERS = {
    'Sunset': 'Sat, 31 Dec 2026 23:59:59 GMT',
    'Link': '<https://api.uicp.io/v2/auth/login>; rel="successor-version"',
  }

  Deprecation Interceptor:

  // src/interface/http/interceptors/deprecation.interceptor.ts
  @Injectable()
  export class DeprecationInterceptor implements NestInterceptor {
    intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
      const version = context.switchToHttp().getRequest().route?.path

      if (this.isDeprecated(version)) {
        const response = context.switchToHttp().getResponse()
        response.set('Deprecation', 'true')
        response.set('Sunset', 'Sat, 31 Dec 2026 23:59:59 GMT')
      }

      return next.handle()
    }
  }

  ---
  3.4 Error Response Consistency

  Standard Error Response:

  // src/interface/http/dto/common/error.response.dto.ts
  export const ErrorResponseSchema = z.object({
    code: z.string(),           // e.g., "VALIDATION_ERROR"
    message: z.string(),
    details: z.array(z.object({
      field: z.string(),
      message: z.string(),
    })).optional(),
    requestId: z.string(),
    timestamp: z.string().datetime(),
  })

  export type ErrorResponse = z.infer<typeof ErrorResponseSchema>

  Error Mapping:

  ┌─────────────────────┬─────────────┬──────────────────────────┐
  │     Domain Code     │ HTTP Status │        Error Code        │
  ├─────────────────────┼─────────────┼──────────────────────────┤
  │ INVALID_CREDENTIALS │ 401         │ AUTH_INVALID_CREDENTIALS │
  ├─────────────────────┼─────────────┼──────────────────────────┤
  │ TOKEN_EXPIRED       │ 401         │ AUTH_TOKEN_EXPIRED       │
  ├─────────────────────┼─────────────┼──────────────────────────┤
  │ RATE_LIMIT_EXCEEDED │ 429         │ RATE_LIMIT_EXCEEDED      │
  ├─────────────────────┼─────────────┼──────────────────────────┤
  │ TENANT_NOT_FOUND    │ 404         │ TENANT_NOT_FOUND         │
  └─────────────────────┴─────────────┴──────────────────────────┘

  ---
  File Checklist

  ┌────────────────────────────────────────────────────────────┬──────────┐
  │                            File                            │  Action  │
  ├────────────────────────────────────────────────────────────┼──────────┤
  │ docs/openapi/v1/auth.yaml                                  │ CREATE   │
  ├────────────────────────────────────────────────────────────┼──────────┤
  │ docs/openapi/v1/user.yaml                                  │ CREATE   │
  ├────────────────────────────────────────────────────────────┼──────────┤
  │ docs/openapi/v1/session.yaml                               │ CREATE   │
  ├────────────────────────────────────────────────────────────┼──────────┤
  │ docs/openapi/v1/admin.yaml                                 │ CREATE   │
  ├────────────────────────────────────────────────────────────┼──────────┤
  │ src/interface/http/dto/auth/*.dto.ts                       │ GENERATE │
  ├────────────────────────────────────────────────────────────┼──────────┤
  │ src/interface/http/versioning.ts                           │ CREATE   │
  ├────────────────────────────────────────────────────────────┼──────────┤
  │ src/interface/http/interceptors/deprecation.interceptor.ts │ CREATE   │
  ├────────────────────────────────────────────────────────────┼──────────┤
  │ src/interface/http/dto/common/error.response.dto.ts        │ CREATE   │
  └────────────────────────────────────────────────────────────┴──────────┘

  
   Section 4: SDK Generation & GraphQL

  4.1 TypeScript SDK (Already Designed)

  Per the approved spec (2026-05-13-uicp-sdk-design.md), the TS SDK uses:

  ┌──────────────┬───────────────────────────────────────────────┐
  │  Component   │                Implementation                 │
  ├──────────────┼───────────────────────────────────────────────┤
  │ Package      │ @uicp/sdk via tsup (ESM + CJS)                │
  ├──────────────┼───────────────────────────────────────────────┤
  │ Client       │ UICPClient.create() / builder()               │
  ├──────────────┼───────────────────────────────────────────────┤
  │ Token Vault  │ Auto-refresh, auto-clear on logout            │
  ├──────────────┼───────────────────────────────────────────────┤
  │ Interceptors │ Auth, tenant, idempotency, retry, rate-limit  │
  ├──────────────┼───────────────────────────────────────────────┤
  │ Storage      │ MemoryAdapter (default), LocalStorage, Cookie │
  └──────────────┴───────────────────────────────────────────────┘

  Implementation Order (from spec):
  1. Types & Errors
  2. Token Vault
  3. Event Bus
  4. Storage Adapters
  5. HTTP Layer
  6. Module Clients (8 sub-clients)
  7. UICPClient
  8. Package exports

  ---
  4.2 Multi-Language SDK Generation

  Strategy: Use OpenAPI spec as single source of truth → generate SDKs automatically.

  ┌────────────┬───────────────────────┬──────────────────────────────────────────┐
  │  Language  │       Generator       │              Output Package              │
  ├────────────┼───────────────────────┼──────────────────────────────────────────┤
  │ TypeScript │ openapi-generator     │ @uicp/sdk (manual impl for full control) │
  ├────────────┼───────────────────────┼──────────────────────────────────────────┤
  │ Python     │ openapi-python-client │ @uicp/sdk-python                         │
  ├────────────┼───────────────────────┼──────────────────────────────────────────┤
  │ Go         │ openapi-generator     │ github.com/uicp/sdk-go                   │
  ├────────────┼───────────────────────┼──────────────────────────────────────────┤
  │ Java       │ openapi-generator     │ com.uicp:sdk-java                        │
  └────────────┴───────────────────────┴──────────────────────────────────────────┘

  Workflow:
  docs/openapi/v1/auth.yaml
           │
           ├─→ openapi-generator → @uicp/sdk-python
           ├─→ openapi-generator → sdk-go
           └─→ openapi-python-client → @uicp/sdk-python

  Python SDK Example:

  from uicp import UICPClient

  client = UICPClient(
      base_url="https://api.uicp.io",
      tenant_id="00000000-0000-0000-0000-000000000000",
  )

  # Token auto-refresh handled
  user = client.user.get_current()

  Go SDK Example:

  package uicp

  import "github.com/uicp/sdk-go"

  func main() {
      client := uicp.NewClient(
          uicp.WithBaseURL("https://api.uicp.io"),
          uicp.WithTenantID("00000000-0000-0000-0000-000000000000"),
      )

      user, err := client.User.GetCurrent()
  }

  ---
  4.3 GraphQL Layer (Dashboard/Analytics)

  Approach: GraphQL for read-heavy queries, REST for mutations.

  // src/interface/graphql/schema.ts
  export const typeDefs = gql`
    type User {
      id: UUID!
      email: String
      phone: String
      roles: [Role!]!
      createdAt: DateTime!
      lastLoginAt: DateTime
    }

    type Session {
      id: UUID!
      userId: UUID!
      deviceFingerprint: String
      ipAddress: String
      createdAt: DateTime!
      expiresAt: DateTime!
    }

    type Query {
      me: User
      user(id: UUID!): User
      users(filter: UserFilter, pagination: Pagination): UserConnection!
      sessions(userId: UUID!): [Session!]!
      analytics: AnalyticsDashboard
    }

    type Mutation {
      createUser(input: CreateUserInput!): User!
      updateUser(id: UUID!, input: UpdateUserInput!): User!
      deleteUser(id: UUID!): Boolean!
      revokeSession(sessionId: UUID!): Boolean!
    }
  `

  Resolver Implementation:

  // src/interface/graphql/resolvers/user.resolver.ts
  @Resolver(() => User)
  export class UserResolver {
    constructor(
      private readonly userQueryHandler: GetUserQueryHandler,
      private readonly listUsersHandler: ListUsersQueryHandler,
    ) {}

    @Query(() => User, { nullable: true })
    async user(@Args('id') id: string): Promise<User | null> {
      return this.userQueryHandler.execute({ id })
    }

    @Query(() => UserConnection)
    async users(
      @Args() filter: UserFilter,
      @Args() pagination: Pagination,
    ): Promise<UserConnection> {
      return this.listUsersHandler.execute({ filter, pagination })
    }
  }

  ---
  4.4 Apollo Federation (Multi-Service)

  For future multi-service decomposition:

  // src/interface/graphql/federation.ts
  import { ApolloServer } from '@apollo/server'

  const server = new ApolloServer({
    typeDefs: [uicpTypeDefs, identityTypeDefs, billingTypeDefs],
    resolvers: [uicpResolvers, identityResolvers, billingResolvers],
  })

  // Services can run independently:
  // - identity-service: User, Role, Permission
  // - billing-service: Tenant, Subscription
  // - uicp-service: Auth, Sessions, Extensions

  ---
  File Checklist

  ┌──────────────────────────────────────┬─────────────────────────────┐
  │                 File                 │           Action            │
  ├──────────────────────────────────────┼─────────────────────────────┤
  │ packages/sdk/                        │ CREATE (from approved spec) │
  ├──────────────────────────────────────┼─────────────────────────────┤
  │ packages/sdk-python/                 │ CREATE (auto-generated)     │
  ├──────────────────────────────────────┼─────────────────────────────┤
  │ packages/sdk-go/                     │ CREATE (auto-generated)     │
  ├──────────────────────────────────────┼─────────────────────────────┤
  │ src/interface/graphql/schema.ts      │ CREATE                      │
  ├──────────────────────────────────────┼─────────────────────────────┤
  │ src/interface/graphql/resolvers/*.ts │ CREATE                      │
  ├──────────────────────────────────────┼─────────────────────────────┤
  │ src/interface/graphql/module.ts      │ CREATE                      │
  └──────────────────────────────────────┴─────────────────────────────┘

● ---
  Section 5: API Governance & Observability

  5.1 Rate Limiting (Tenant & API Level)

  Strategy: Tiered rate limiting at API Gateway + Application level.

  ┌────────────┬──────────────┬───────┬─────────────┐
  │    Tier    │ Requests/min │ Burst │  Use Case   │
  ├────────────┼──────────────┼───────┼─────────────┤
  │ Free       │ 60           │ 10    │ Development │
  ├────────────┼──────────────┼───────┼─────────────┤
  │ Pro        │ 600          │ 100   │ Production  │
  ├────────────┼──────────────┼───────┼─────────────┤
  │ Enterprise │ 6000         │ 1000  │ High-volume │
  └────────────┴──────────────┴───────┴─────────────┘

  Implementation:

  // src/application/services/rate-limit/tenant-rate-limit.service.ts
  interface TenantRateLimit {
    tier: 'free' | 'pro' | 'enterprise'
    requestsPerMinute: number
    burst: number
    currentUsage: number
    windowStart: Date
  }

  async function checkRateLimit(tenantId: string, endpoint: string): Promise<boolean> {
    const tier = await getTenantTier(tenantId)
    const limits = RATE_LIMIT_TIERS[tier]

    // Redis atomic check
    const remaining = await redis.incr(`ratelimit:${tenantId}:${endpoint}`)
    if (remaining === 1) {
      await redis.expire(`ratelimit:${tenantId}:${endpoint}`, 60)
    }

    return remaining <= limits.requestsPerMinute
  }

  Response Headers:
  X-RateLimit-Limit: 600
  X-RateLimit-Remaining: 599
  X-RateLimit-Reset: 1715628000

  ---
  5.2 Idempotency

  Strategy: Client-generated idempotency keys with 24h TTL.

  // Idempotency interceptor
  @Injectable()
  export class IdempotencyInterceptor implements NestInterceptor {
    async intercept(context: ExecutionContext, next: CallHandler): Promise<Observable<any>> {      
      const request = context.switchToHttp().getRequest()
      const idempotencyKey = request.headers['idempotency-key']

      if (!idempotencyKey) {
        throw new IdempotencyKeyRequiredError()
      }

      const cached = await this.cache.get(`idem:${idempotencyKey}`)
      if (cached) {
        return of(JSON.parse(cached))
      }

      const response = await next.handle()
      const responseData = await lastValueFrom(response)

      await this.cache.set(
        `idem:${idempotencyKey}`,
        JSON.stringify(responseData),
        { ttl: 86400 } // 24h
      )

      return of(responseData)
    }
  }

  Endpoints Requiring Idempotency:
  - POST /auth/signup
  - POST /auth/login (if creating session)
  - POST /v1/extensions/bind
  - POST /v1/extensions/execute

  ---
  5.3 Contract Testing (Pact.js)

  Strategy: Consumer-driven contracts between SDK and API.

  // sdk/__tests__/pact/auth.pact.ts
  import { Pact } from '@pact-foundation/pact'

  describe('Auth API', () => {
    const provider = new Pact({
      consumer: '@uicp/sdk',
      provider: 'UICP API',
    })

    beforeAll(() => provider.setup())
    afterAll(() => provider.finalize())

    describe('POST /auth/login', () => {
      it('returns user with tokens on valid credentials', () => {
        provider
          .given('user exists')
          .uponReceiving('a login request')
          .withRequest({
            method: 'POST',
            path: '/v1/auth/login',
            body: { email: 'test@example.com', password: 'password123' },
          })
          .willRespondWith({
            status: 200,
            body: like({
              userId: '00000000-0000-0000-0000-000000000001',
              accessToken: like('eyJ...'),
              refreshToken: like('eyJ...'),
            }),
          })
      })
    })
  })

  CI Integration:
  # .github/workflows/contract-test.yml
  - name: Run Pact Tests
    run: npm run test:pact
  - name: Publish Contract
    run: npm run pact:publish
    if: github.ref == 'refs/heads/main'

  ---
  5.4 Observability

  Metrics:

  ┌──────────────────────────┬───────────┬──────────────────────────────────┐
  │          Metric          │   Type    │              Labels              │
  ├──────────────────────────┼───────────┼──────────────────────────────────┤
  │ http_requests_total      │ Counter   │ method, endpoint, status, tenant │
  ├──────────────────────────┼───────────┼──────────────────────────────────┤
  │ http_request_duration_ms │ Histogram │ method, endpoint                 │
  ├──────────────────────────┼───────────┼──────────────────────────────────┤
  │ auth_login_success       │ Counter   │ tenant, method                   │
  ├──────────────────────────┼───────────┼──────────────────────────────────┤
  │ auth_login_failure       │ Counter   │ tenant, reason                   │
  ├──────────────────────────┼───────────┼──────────────────────────────────┤
  │ otp_sms_sent             │ Counter   │ tenant, provider                 │
  ├──────────────────────────┼───────────┼──────────────────────────────────┤
  │ otp_sms_cost             │ Gauge     │ tenant                           │
  ├──────────────────────────┼───────────┼──────────────────────────────────┤
  │ rate_limit_exceeded      │ Counter   │ tenant, endpoint                 │
  └──────────────────────────┴───────────┴──────────────────────────────────┘

  Tracing (OpenTelemetry):

  // Distributed trace example
  @Injectable()
  export class TracingInterceptor implements NestInterceptor {
    intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
      const span = tracer.startSpan(`HTTP ${context.switchToHttp().getRequest().method}`)
      span.setAttribute('http.url', context.switchToHttp().getRequest().url)
      span.setAttribute('tenant.id', context.switchToHttp().getRequest().headers['x-tenant-id'])   

      return next.handle().pipe(
        tap(() => span.end()),
        catchError(err => {
          span.setAttribute('error', true)
          span.end()
          throw err
        })
      )
    }
  }

  Logging:

  // Structured JSON logging
  logger.log({
    level: 'info',
    message: 'API request',
    tenantId: 'tenant-123',
    userId: 'user-456',
    endpoint: 'POST /v1/auth/login',
    duration: 45,
    status: 200,
  })

  ---
  File Checklist

  File: src/application/services/rate-limit/tenant-rate-limit.service.ts
  Action: CREATE
  ────────────────────────────────────────
  File: src/interface/http/interceptors/idempotency.interceptor.ts
  Action: CREATE
  ────────────────────────────────────────
  File: src/interface/http/interceptors/tracing.interceptor.ts
  Action: CREATE
  ────────────────────────────────────────
  File: sdk/__tests__/pact/*.pact.ts
  Action: CREATE
  ────────────────────────────────────────
  File: docker-compose.metrics.yml
  Action: CREATE (Prometheus + Grafana)


> **Phase 0** — Critical vulnerability fixes before any enterprise features.

**Goal:** Eliminate RCE vectors, fix race conditions, and implement cost controls.

---

## 2.1 ABAC Engine Replacement

### Issue
`AbacJitCompiler` uses `new Function` to compile tenant policies → Remote Code Execution vulnerability.

### Solution
Replace with AST-based interpreter (no code generation).

### Files
- **DELETE:** `src/infrastructure/governance/policy/abac-jit-compiler.ts`
- **CREATE:** `src/domain/policy/interpreter/abac-ast-interpreter.ts`
- **CREATE:** `src/domain/policy/parser/abac-policy-parser.ts`

### Implementation

```typescript
// src/domain/policy/interpreter/abac-ast-interpreter.ts
interface AbacNode {
  type: 'condition' | 'action' | 'resource' | 'logical'
  operator?: 'eq' | 'in' | 'regex' | 'greaterThan' | 'lessThan'
  left?: string  // path like "ctx.subject.role"
  right?: unknown
  children?: AbacNode[]
}

// Evaluation: traverse AST, never execute arbitrary code
evaluate(node: AbacNode, context: PolicyContext): boolean {
  switch (node.type) {
    case 'logical':
      if (node.operator === 'and') {
        return node.children.every(c => this.evaluate(c, context))
      }
      // ... other operators
    case 'condition':
      return this.evalCondition(node, context)
  }
}
```

### Checklist
- [ ] Create AST interpreter interface
- [ ] Implement condition evaluation (eq, in, regex, gt, lt)
- [ ] Implement logical operators (and, or, not)
- [ ] Add path resolution for context fields
- [ ] Write unit tests for all operators
- [ ] Integration test with existing policy service
- [ ] Delete old JIT compiler
- [ ] Deploy with feature flag

---

## 2.2 Atomic Rate Limiting

### Issue
Redis `INCR` + `EXPIRE` is non-atomic → permanent DoS on crash between operations.

### Solution
Lua script for atomic increment + expiry.

### Files
- **CREATE:** `src/infrastructure/rate-limit/sliding-window.lua`
- **CREATE:** `src/infrastructure/rate-limit/atomic-rate-limiter.service.ts`
- **MODIFY:** `src/interface/http/middleware/rate-limiter.middleware.ts`

### Implementation

```lua
-- src/infrastructure/rate-limit/sliding-window.lua
local key = KEYS[1]
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])

local current = redis.call('GET', key)
if current and tonumber(current) >= limit then
  return -1
end

local count = redis.call('INCR', key)
if count == 1 then
  redis.call('EXPIRE', key, window)
end
return count
```

### Checklist
- [ ] Create Lua script file
- [ ] Implement AtomicRateLimiterService
- [ ] Replace existing RateLimiterMiddleware usage
- [ ] Add configuration (window size, limit per endpoint)
- [ ] Write unit tests with Redis mock
- [ ] Integration test on staging
- [ ] Deploy with gradual rollout

---

## 2.3 OTP Cost Controller

### Issue
No spend limits → unlimited SMS cost explosion (₹10L+ attack possible).

### Solution
Token bucket with circuit breaker per tenant.

### Files
- **CREATE:** `src/application/services/otp/otp-cost-controller.service.ts`
- **CREATE:** `src/infrastructure/otp/gateway-composite.service.ts`
- **CREATE:** `src/application/guards/otp-spend-limit.guard.ts`
- **MODIFY:** `src/application/handlers/auth/otp/send-otp.handler.ts`

### Implementation

```typescript
// src/application/services/otp/otp-cost-controller.service.ts
interface OtpSpendQuota {
  tenantId: string
  dailyLimit: number        // e.g., ₹10,000
  spentToday: number
  windowStart: Date
  circuitState: 'closed' | 'open' | 'half-open'
}

async sendOtp(tenantId: string, phone: string): Promise<OtpResult> {
  const quota = await this.getQuota(tenantId)

  if (quota.circuitState === 'open') {
    throw new OtpSpendLimitExceededError(tenantId)
  }

  if (quota.spentToday >= quota.dailyLimit) {
    await this.openCircuit(tenantId)
    throw new OtpSpendLimitExceededError(tenantId)
  }

  const result = await this.gateway.send(phone)
  await this.incrementSpend(tenantId, result.cost)

  if (quota.spentToday + result.cost > quota.dailyLimit * 0.9) {
    await this.notifySlack(`⚠️ ${tenantId} at 90% OTP budget`)
  }

  return result
}
```

### Checklist
- [ ] Define OtpSpendQuota interface
- [ ] Implement cost tracking in Redis
- [ ] Implement circuit breaker (closed/open/half-open)
- [ ] Add daily limit configuration per tenant
- [ ] Create Slack/alert notification for 90% threshold
- [ ] Implement fallback (email instead of SMS) when circuit opens
- [ ] Add phone number pre-validation (libphonenumber-js)
- [ ] Block virtual/VoIP numbers
- [ ] Write unit tests
- [ ] Integration test with Firebase/Twilio
- [ ] Deploy with feature flag

---

## 2.4 Deployment Order & Rollback

| Step | Component | Risk Level | Rollback |
|------|-----------|------------|----------|
| 1 | ABAC AST Interpreter | Low | Feature flag |
| 2 | Lua Rate Limiter | Medium | Feature flag |
| 3 | OTP Cost Controller | High | Feature flag + old behavior |

### Rollback Strategy
- Each component wrapped with `FeatureFlagService`
- If issue detected: flip flag to revert to old behavior
- Monitor metrics for 24h before removing flag

---

## Security Validation Checklist

- [ ] Attacker cannot achieve RCE via ABAC policy
- [ ] Rate limit keys cannot persist forever
- [ ] OTP spend capped at tenant daily limit
- [ ] Circuit breaker prevents cascade failures
- [ ] All changes pass security review

---

## Timeline

| Day | Deliverable |
|-----|-------------|
| Day 1-2 | ABAC AST Interpreter |
| Day 3-4 | Lua Rate Limiter |
| Day 5-7 | OTP Cost Controller |
| Day 8 | Security validation |