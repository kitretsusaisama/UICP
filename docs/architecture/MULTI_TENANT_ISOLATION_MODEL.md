# UICP Architecture: Multi-Tenant Isolation Model

## System Classification
Multi-Tenant Isolation Specialist

## Multi-Tenant Isolation Strategy
1. **Logical Isolation:** Every database table must have `tenant_id`.
2. **Context Propagation:** `ClsContextInterceptor` pulls `X-Tenant-ID` and injects it into CLS.
3. **Repository Enforcement:** The ORM or Repositories MUST implicitly append `WHERE tenant_id = ?` to every query based on the CLS context.

## Governance Implications
Data spillage is the ultimate failure. Formal verification via static analysis (e.g., AST checkers) should enforce that no repository method can execute without tenant scope.

## Failure Containment Strategy
If tenant context is lost in the async execution chain, the system MUST throw a fatal error (Fail-Closed) and refuse to execute queries.