#!/bin/bash
set -e

echo "🔒 RUNNING UICP RELEASE GATE PIPELINE"

# Layer 1: Static Enforcement (AST)
npx ts-node scripts/enforce-release-gates.ts

# Generate OpenAPI
npx ts-node scripts/generate-openapi.ts

# Layer 2: Contract Enforcement (OPA)
npx ts-node scripts/enforce-opa-policies.ts

# Unit / Integration Tests
npm run test

# Layer 3: Chaos and E2E Tests
npm run test:e2e

echo "✅ ALL RELEASE GATES PASSED. SAFE TO DEPLOY."
