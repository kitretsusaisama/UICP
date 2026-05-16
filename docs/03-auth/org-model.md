# Organization and Tenant Model

## Metadata
```yaml
title: Organization and Tenant Model
domain: identity
owner: identity-team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: LOW
provider-impact: LOW
tenant-impact: TENANT_ISOLATED
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - auth-overview.md
  - session-management.md
  - jwt-claims.md
related-docs:
  - login-flow.md
  - token-model.md
  - auth-security.md
related-queues:
  - org-events
  - membership-events
related-services:
  - OrganizationService
  - MembershipService
  - TenantService
related-runtime-states:
  - TENANT_ACTIVE
  - ORG_MEMBER_ADDED
  - ORG_ROLE_CHANGED
```

---

## Tenant Model

### Tenant Entity

Tenants represent top-level isolation boundaries. Each tenant has its own configuration, users, and resources. The `tid` claim in all tokens enforces tenant isolation.

```typescript
interface Tenant {
  id: string; // ULID
  name: string;
  slug: string; // URL-friendly identifier
  status: 'active' | 'suspended' | 'deleted';
  settings: TenantSettings;
  createdAt: Date;
}
```

### Tenant Settings

| Setting | Description | Default |
|---------|-------------|---------|
| maxUsers | Maximum users per tenant | 1000 |
| mfaRequired | Require MFA for all users | false |
| sessionTimeout | Session TTL in seconds | 86400 |
| ipWhitelist | Allowed IP ranges | [] |

---

## Organization Model

### Organization Hierarchy

Organizations exist within tenants and represent business units. Users may belong to multiple organizations within a tenant.

```
Tenant (tid)
  └── Organization A (oid)
        └── Organization B (nested)
              └── Team
```

### Organization Entity

```typescript
interface Organization {
  id: string; // ULID
  tenantId: string;
  parentId: string | null; // Hierarchical org support
  name: string;
  slug: string;
  settings: OrgSettings;
}
```

---

## Membership Model

### User Membership

Users join organizations through membership records. Each membership has a role defining permissions within that organization.

```typescript
interface Membership {
  id: string;
  userId: string;
  organizationId: string;
  role: string; // e.g., 'member', 'admin', 'owner'
  status: 'active' | 'pending' | 'suspended';
  createdAt: Date;
}
```

### Role Hierarchy

```
Owner: Full control, can delete organization, manage billing
Admin: Manage members, configure settings, cannot delete
Member: Access resources based on permissions
Guest: Read-only access to specific resources
```

---

## Token Claims for Organization

### Membership Claims

The access token includes membership and organization information for authorization:

```json
{
  "sub": "ulid-user-123",
  "tid": "ulid-tenant-456",
  "membership": {
    "orgId": "ulid-org-789",
    "role": "admin",
    "permissions": ["resource:read", "resource:write"]
  }
}
```

### Multi-Organization Access

Users with multiple memberships receive tokens scoped to the requested organization. API requests include `X-Organization-ID` header to specify target organization.

---

## Cross-Tenant Isolation

### Hard Isolation

All authentication tokens include `tid` claim. The API gateway validates `tid` matches requested resource's tenant. Cross-tenant requests reject regardless of valid signature.

```
Valid: Token tid=tenant-A accessing resource in tenant-A
Invalid: Token tid=tenant-A accessing resource in tenant-B
```

### Data Isolation

Database queries always include tenant filter. Repository implementations inject tenant context from authenticated session, preventing accidental cross-tenant data access.

---

## Related Documents

- `auth-overview.md` - Authentication overview
- `jwt-claims.md` - Token claims
- `auth-security.md` - Security controls