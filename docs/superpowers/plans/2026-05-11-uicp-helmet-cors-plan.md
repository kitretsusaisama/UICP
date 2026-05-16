# P0 Task 1: Add Helmet/CORS to main.ts

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Helmet.js security headers and CORS configuration to the NestJS application bootstrap in main.ts

**Architecture:** Install helmet package, import it in main.ts, add helmet() middleware early in bootstrap chain, then configure CORS using NestJS enableCors() with environment variable support for origin allowlist

**Tech Stack:** NestJS, Helmet.js, Express CORS

---

### Task 1: Install Helmet package

**Files:**
- Modify: `package.json` (dependencies section)

- [ ] **Step 1: Add helmet to dependencies**

Run: `npm install helmet`
This adds helmet to node_modules and updates package.json.

- [ ] **Step 2: Verify helmet installed**

Run: `npm list helmet`
Expected: helmet version displayed (e.g., "helmet@7.x.x")

- [ ] **Step 3: Commit**

```bash
git add package.json package-lock.json
git commit -m "P0: add helmet security dependency"
```

---

### Task 2: Add Helmet middleware to main.ts

**Files:**
- Modify: `src/main.ts`

- [ ] **Step 1: Import helmet at top of main.ts**

Add this line after the existing imports (around line 9):
```typescript
import helmet from 'helmet';
```

- [ ] **Step 2: Add helmet middleware after app creation, before Swagger**

Add after line 90 (after `bufferLogs: true` and before the logger setup):
```typescript
  // Security: Helmet sets HTTP security headers
  app.use(helmet());
```

The order should be:
1. app created (line 87-90)
2. helmet() - NEW
3. logger setup (line 92-94)
4. Swagger (line 96-125)

- [ ] **Step 3: Run build to verify no errors**

Run: `npm run build`
Expected: Build succeeds with no errors

- [ ] **Step 4: Commit**

```bash
git add src/main.ts
git commit -m "P0: add helmet middleware for security headers"
```

---

### Task 3: Add CORS configuration

**Files:**
- Modify: `src/main.ts`

- [ ] **Step 1: Add CORS configuration after helmet**

Replace the placeholder comment or add after helmet middleware:
```typescript
  // Security: CORS configuration
  app.enableCors({
    origin: process.env['CORS_ORIGINS']?.split(',') ?? true,
    credentials: true,
    exposedHeaders: ['Content-Range', 'X-Total-Count', 'X-Total-Pages'],
    maxAge: 86400, // 24 hours - preflight cache
  });
```

- [ ] **Step 2: Verify build still passes**

Run: `npm run build`
Expected: Build succeeds

- [ ] **Step 3: Commit**

```bash
git add src/main.ts
git commit -m "P0: add CORS configuration with env var support"
```

---

### Task 4: Verify the implementation

**Files:**
- Test: Manual verification

- [ ] **Step 1: Start the application**

Run: `npm run start:dev`
Let it start for a few seconds, then stop with Ctrl+C

- [ ] **Step 2: Check startup logs for any CORS-related warnings**

Expected: No errors related to helmet or CORS

- [ ] **Step 3: Commit final**

```bash
git add docs/superpowers/plans/2026-05-11-uicp-helmet-cors-plan.md
git commit -m "P0: complete helmet/CORS implementation"
```

---

**Plan complete.** The application now has Helmet security headers and CORS configured with environment variable support for the origins allowlist.