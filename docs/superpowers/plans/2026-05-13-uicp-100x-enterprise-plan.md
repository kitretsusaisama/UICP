# UICP Enterprise-Grade Refactoring Plan: 100x MNC Architecture

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform UICP into enterprise-grade platform with contract-first API design, multi-language SDK generation, GraphQL for complex queries, API governance (rate limiting, idempotency), and contract testing — supporting 20+ developers with clear module ownership.

**Architecture:** Three-pronged approach: (1) Complete 10x10 refactor for DTOs/versioning, (2) Contract-first with SDK generation, (3) GraphQL layer for dashboard/analytics queries with REST for mutations.

**Tech Stack:** NestJS, Zod, Swagger/OpenAPI, GraphQL (Apollo), Apollo Federation, Pact.js, ts-openapi-generator

---

## Phase 1: Complete Existing 10x10 Refactor

### Task 1.1: DTO Layer Creation

**Files:**
- Create: `src/interface/http/dto/auth/signup-email.input.dto.ts`
- Create: `src/interface/http/dto/auth/login.input.dto.ts`
- Create: `src/interface/http/dto/auth/otp-send.input.dto.ts`
- Create: `src/interface/http/dto/auth/otp-verify.input.dto.ts`
- Create: `src/interface/http/dto/auth/password-change.input.dto.ts`
- Create: `src/interface/http/dto/auth/password-reset.input.dto.ts`
- Create: `src/interface/http/dto/user/user.input.dto.ts`
- Create: `src/interface/http/dto/tenant/tenant.input.dto.ts`
- Modify: `src/interface/http/controllers/auth/auth.controller.ts` (use DTOs)
- Test: `src/interface/http/dto/**/*.spec.ts`

- [ ] **Step 1: Create DTO directory structure**

- [ ] **Step 2: Create auth/signup-email.input.dto.ts**

- [ ] **Step 3: Create auth/login.input.dto.ts**

- [ ] **Step 4: Create remaining DTO files**

- [ ] **Step 5: Create index.ts barrel files**

- [ ] **Step 6: Update controllers to use DTOs**

- [ ] **Step 7: Write unit tests**

- [ ] **Step 8: Commit**

---

### Task 1.2: Centralized UUID-Buffer Utilities

**Files:**
- Create: `src/infrastructure/db/mysql/utils/uuid-buffer.ts`
- Modify: Repositories to use centralized utility

- [ ] **Step 1: Create uuid-buffer.ts**

- [ ] **Step 2: Update repositories**

- [ ] **Step 3: Write tests**

- [ ] **Step 4: Commit**

---

### Task 1.3: API Versioning Strategy

**Files:**
- Create: `src/interface/http/versioning.ts`
- Create: `src/interface/http/interceptors/deprecation.interceptor.ts`

- [ ] **Step 1: Create versioning constants**

- [ ] **Step 2: Create deprecation interceptor**

- [ ] **Step 3: Update module**

- [ ] **Step 4: Commit**

---

### Task 1.4: Error Response Consistency

**Files:**
- Modify: `src/domain/exceptions/domain.exception.ts`

- [ ] **Step 1: Add toHttpStatus method**

- [ ] **Step 2: Update GlobalExceptionFilter**

- [ ] **Step 3: Commit**

---

## Phase 2: Contract-First API with SDK Generation

### Task 2.1: Enhanced OpenAPI Specification

- [ ] **Step 1: Enhance Swagger config**

- [ ] **Step 2: Commit**

---

### Task 2.2: TypeScript SDK Auto-Generation Pipeline

- [ ] **Step 1: Install dependencies**

- [ ] **Step 2: Create generate-sdk.ts script**

- [ ] **Step 3: Commit**

---

### Task 2.3: typescript SDK Scaffolding

- [ ] **Step 1: Create Typescript SDK**

- [ ] **Step 2: Commit**

---

## Phase 3: GraphQL for Complex Queries

### Task 3.1: GraphQL Module Setup

- [ ] **Step 1: Install GraphQL dependencies**

- [ ] **Step 2: Create GraphQL module and resolver**

- [ ] **Step 3: Commit**

---

### Task 3.2: Apollo Federation Setup

- [ ] **Step 1: Enable federation**

- [ ] **Step 2: Commit**

---

## Phase 4: API Governance

### Task 4.1: Rate Limiting Implementation

- [ ] **Step 1: Create rate limit guard**

- [ ] **Step 2: Apply to controllers**

- [ ] **Step 3: Commit**

---

### Task 4.2: Idempotency Implementation

- [ ] **Step 1: Create idempotency interceptor**

- [ ] **Step 2: Apply to mutations**

- [ ] **Step 3: Commit**

---

## Phase 5: Contract Testing

### Task 5.1: Pact.js Consumer Tests

- [ ] **Step 1: Install Pact**

- [ ] **Step 2: Create consumer tests**

- [ ] **Step 3: Commit**

---

## Phase 6: Enterprise Features

### Task 6.1: SAML/SSO Integration Scaffold

- [ ] **Step 1: Create SAML module**

- [ ] **Step 2: Commit**

---

### Task 6.2: Audit Trail with Compliance Export

- [ ] **Step 1: Enhance audit service**

- [ ] **Step 2: Commit**

---

## Phase 7: Final Verification

### Task 7.1: Full Integration Tests

- [ ] **Step 1: Create integration tests**

- [ ] **Step 2: Run CI**

- [ ] **Step 3: Commit**

---

### Task 7.2: Update Documentation

- [ ] **Step 1: Create architecture doc**

- [ ] **Step 2: Commit**

---

## Execution Summary

| Phase | Tasks |
|-------|-------|
| 1: 10x10 Complete | 4 tasks |
| 2: Contract-First SDK | 3 tasks |
| 3: GraphQL | 2 tasks |
| 4: API Governance | 2 tasks |
| 5: Contract Testing | 1 task |
| 6: Enterprise | 2 tasks |
| 7: Verification | 2 tasks |

**Total: 16 tasks**