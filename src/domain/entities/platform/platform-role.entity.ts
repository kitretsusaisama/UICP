export enum PlatformRoleType {
  PLATFORM_OWNER = 'platform-owner',
  PLATFORM_ADMINISTRATOR = 'platform-administrator',
  IDENTITY_ADMINISTRATOR = 'identity-administrator',
  USER_ADMINISTRATOR = 'user-administrator',
  SECURITY_ADMINISTRATOR = 'security-administrator',
  PRIVILEGED_ROLE_ADMINISTRATOR = 'privileged-role-administrator',
  SECURITY_OPERATOR = 'security-operator',
  COMPLIANCE_ADMINISTRATOR = 'compliance-administrator',
  NETWORK_ADMINISTRATOR = 'network-administrator',
  CLOUD_APPLICATION_ADMINISTRATOR = 'cloud-application-administrator',
  DEVICE_ADMINISTRATOR = 'device-administrator',
  TENANT_MANAGER = 'tenant-manager',
  TENANT_CREATOR = 'tenant-creator',
  TENANT_OPERATOR = 'tenant-operator',
  TENANT_AUDITOR = 'tenant-auditor',
  SUPPORT_ADMINISTRATOR = 'support-administrator',
  SUPPORT_TIER1 = 'support-tier-1',
  SUPPORT_TIER2 = 'support-tier-2',
  OBSERVABILITY_ADMINISTRATOR = 'observability-administrator',
  METRICS_VIEWER = 'metrics-viewer',
  LOG_VIEWER = 'log-viewer',
  ALERT_MANAGER = 'alert-manager',
  BILLING_ADMINISTRATOR = 'billing-administrator',
  SUBSCRIPTION_MANAGER = 'subscription-manager',
  AUDITOR = 'auditor',
  AUDIT_LOG_VIEWER = 'audit-log-viewer',
  COMPLIANCE_REPORTER = 'compliance-reporter',
}

export enum PlatformRoleAssignmentType {
  PERMANENT = 'permanent',
  ELIGIBLE = 'eligible',
  DELEGATED = 'delegated',
}

export interface PlatformRoleProps {
  id: string;
  type: PlatformRoleType;
  name: string;
  description: string;
  assignmentType: PlatformRoleAssignmentType;
  isSystem: boolean;
  canAssign: boolean;
  canDelegate: boolean;
  inheritanceLevel: number;
  parentRoleId?: string;
  permissions: string[];
  createdAt?: Date;
  updatedAt?: Date;
}

export class PlatformRole {
  readonly id: string;
  readonly type: PlatformRoleType;
  readonly name: string;
  readonly description: string;
  readonly assignmentType: PlatformRoleAssignmentType;
  readonly isSystem: boolean;
  readonly canAssign: boolean;
  readonly canDelegate: boolean;
  readonly inheritanceLevel: number;
  readonly parentRoleId: string | null;
  private _permissions: string[];
  readonly createdAt: Date;
  private _updatedAt: Date;

  constructor(props: PlatformRoleProps) {
    this.id = props.id;
    this.type = props.type;
    this.name = props.name;
    this.description = props.description;
    this.assignmentType = props.assignmentType;
    this.isSystem = props.isSystem;
    this.canAssign = props.canAssign;
    this.canDelegate = props.canDelegate;
    this.inheritanceLevel = props.inheritanceLevel;
    this.parentRoleId = props.parentRoleId ?? null;
    this._permissions = [...props.permissions];
    this.createdAt = props.createdAt ?? new Date();
    this._updatedAt = props.updatedAt ?? new Date();
  }

  get permissions(): string[] {
    return [...this._permissions];
  }

  get updatedAt(): Date {
    return this._updatedAt;
  }

  get isRoot(): boolean {
    return this.type === PlatformRoleType.PLATFORM_OWNER;
  }

  get requiresJit(): boolean {
    return this.assignmentType === PlatformRoleAssignmentType.ELIGIBLE;
  }

  hasPermission(permission: string): boolean {
    return this._permissions.includes(permission);
  }

  canPerformAction(action: string): boolean {
    const actionPrefix = action.split(':')[0] || '';
    return this._permissions.some(p => p === action || p === '*' || (actionPrefix && p.startsWith(actionPrefix)));
  }

  toResponse() {
    return {
      id: this.id,
      type: this.type,
      name: this.name,
      description: this.description,
      assignmentType: this.assignmentType,
      isSystem: this.isSystem,
      canAssign: this.canAssign,
      canDelegate: this.canDelegate,
      inheritanceLevel: this.inheritanceLevel,
      permissions: this._permissions,
    };
  }

  static SYSTEM_ROLES: PlatformRoleProps[] = [
    {
      id: 'role-platform-owner',
      type: PlatformRoleType.PLATFORM_OWNER,
      name: 'Platform Owner',
      description: 'Root superadmin with full platform access. Cannot be restricted or delegated.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: true,
      canDelegate: true,
      inheritanceLevel: 0,
      permissions: ['*'],
    },
    {
      id: 'role-platform-administrator',
      type: PlatformRoleType.PLATFORM_ADMINISTRATOR,
      name: 'Platform Administrator',
      description: 'Full administrative access to platform services, excluding restricted operations.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: true,
      canDelegate: true,
      inheritanceLevel: 1,
      parentRoleId: 'role-platform-owner',
      permissions: [
        'platform:read', 'platform:write', 'platform:delete',
        'tenant:read', 'tenant:write', 'tenant:delete',
        'identity:read', 'identity:write',
        'config:read', 'config:write',
        'audit:read', 'signin:read',
        'announcement:read', 'announcement:write', 'announcement:delete',
      ],
    },
    {
      id: 'role-identity-administrator',
      type: PlatformRoleType.IDENTITY_ADMINISTRATOR,
      name: 'Identity Administrator',
      description: 'Manages platform identities and authentication settings.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: true,
      canDelegate: false,
      inheritanceLevel: 2,
      parentRoleId: 'role-platform-administrator',
      permissions: [
        'identity:read', 'identity:write', 'identity:delete',
        'mfa:manage', 'password:reset',
        'did:read', 'did:write', 'vc:issue', 'vc:revoke',
      ],
    },
    {
      id: 'role-user-administrator',
      type: PlatformRoleType.USER_ADMINISTRATOR,
      name: 'User Administrator',
      description: 'Manages platform user accounts and basic settings.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: true,
      canDelegate: false,
      inheritanceLevel: 3,
      parentRoleId: 'role-identity-administrator',
      permissions: ['identity:read', 'identity:write', 'mfa:manage'],
    },
    {
      id: 'role-security-administrator',
      type: PlatformRoleType.SECURITY_ADMINISTRATOR,
      name: 'Security Administrator',
      description: 'Manages security policies, threat detection, and incident response.',
      assignmentType: PlatformRoleAssignmentType.ELIGIBLE,
      isSystem: true,
      canAssign: true,
      canDelegate: true,
      inheritanceLevel: 2,
      parentRoleId: 'role-platform-administrator',
      permissions: [
        'security:read', 'security:write',
        'ca-policy:read', 'ca-policy:write', 'ca-policy:delete',
        'zt-policy:read', 'zt-policy:write',
        'threat-intel:read',
        'risk-score:read', 'anomaly:read',
        'soc:manage', 'incident:manage',
      ],
    },
    {
      id: 'role-privileged-role-administrator',
      type: PlatformRoleType.PRIVILEGED_ROLE_ADMINISTRATOR,
      name: 'Privileged Role Administrator',
      description: 'Manages role assignments, eligible roles, and JIT activation workflows.',
      assignmentType: PlatformRoleAssignmentType.ELIGIBLE,
      isSystem: true,
      canAssign: true,
      canDelegate: false,
      inheritanceLevel: 3,
      parentRoleId: 'role-security-administrator',
      permissions: [
        'role:read', 'role:write', 'role:assign', 'role:eligible',
        'jit:activate', 'jit:deactivate', 'jit:approve',
        'delegation:read', 'delegation:write',
      ],
    },
    {
      id: 'role-security-operator',
      type: PlatformRoleType.SECURITY_OPERATOR,
      name: 'Security Operator',
      description: 'Day-to-day security operations and monitoring.',
      assignmentType: PlatformRoleAssignmentType.ELIGIBLE,
      isSystem: true,
      canAssign: false,
      canDelegate: false,
      inheritanceLevel: 4,
      parentRoleId: 'role-privileged-role-administrator',
      permissions: [
        'security:read', 'threat-intel:read',
        'incident:read', 'incident:update',
        'soc:read', 'soc:update',
      ],
    },
    {
      id: 'role-compliance-administrator',
      type: PlatformRoleType.COMPLIANCE_ADMINISTRATOR,
      name: 'Compliance Administrator',
      description: 'Manages compliance policies, audits, and regulatory reporting.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: true,
      canDelegate: false,
      inheritanceLevel: 3,
      parentRoleId: 'role-security-administrator',
      permissions: [
        'compliance:read', 'compliance:write',
        'audit:read', 'audit:export',
        'consent:read', 'consent:manage',
        'dsar:read', 'dsar:manage', 'dsar:complete',
        'retention:read', 'retention:write',
        'report:generate',
      ],
    },
    {
      id: 'role-network-administrator',
      type: PlatformRoleType.NETWORK_ADMINISTRATOR,
      name: 'Network Administrator',
      description: 'Manages network policies, mTLS configuration, and micro-segmentation.',
      assignmentType: PlatformRoleAssignmentType.ELIGIBLE,
      isSystem: true,
      canAssign: false,
      canDelegate: false,
      inheritanceLevel: 2,
      parentRoleId: 'role-platform-administrator',
      permissions: [
        'network:read', 'network:write',
        'mtls:manage', 'zt-policy:read', 'zt-policy:write',
        'device-posture:read', 'device-posture:write',
      ],
    },
    {
      id: 'role-cloud-application-administrator',
      type: PlatformRoleType.CLOUD_APPLICATION_ADMINISTRATOR,
      name: 'Cloud Application Administrator',
      description: 'Manages cloud applications, extensions, and integrations.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: false,
      canDelegate: false,
      inheritanceLevel: 2,
      parentRoleId: 'role-platform-administrator',
      permissions: [
        'app:read', 'app:write', 'app:delete',
        'extension:read', 'extension:write', 'extension:execute',
        'webhook:read', 'webhook:write', 'webhook:delete',
        'oauth:manage',
      ],
    },
    {
      id: 'role-device-administrator',
      type: PlatformRoleType.DEVICE_ADMINISTRATOR,
      name: 'Device Administrator',
      description: 'Manages device registry, posture policies, and MDM integration.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: false,
      canDelegate: false,
      inheritanceLevel: 2,
      parentRoleId: 'role-platform-administrator',
      permissions: [
        'device:read', 'device:write', 'device:delete',
        'device-posture:read', 'device-posture:write',
        'mdm:manage',
      ],
    },
    {
      id: 'role-tenant-manager',
      type: PlatformRoleType.TENANT_MANAGER,
      name: 'Tenant Manager',
      description: 'Manages tenant lifecycle, quotas, and cross-tenant operations.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: true,
      canDelegate: true,
      inheritanceLevel: 1,
      parentRoleId: 'role-platform-administrator',
      permissions: [
        'tenant:read', 'tenant:write', 'tenant:delete',
        'tenant:create', 'tenant:suspend', 'tenant:reactivate',
        'tenant:migrate', 'tenant:clone',
        'quota:read', 'quota:write',
        'usage:read',
      ],
    },
    {
      id: 'role-tenant-creator',
      type: PlatformRoleType.TENANT_CREATOR,
      name: 'Tenant Creator',
      description: 'Creates new tenant accounts and initial configuration.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: false,
      canDelegate: false,
      inheritanceLevel: 2,
      parentRoleId: 'role-tenant-manager',
      permissions: ['tenant:create', 'tenant:read'],
    },
    {
      id: 'role-tenant-operator',
      type: PlatformRoleType.TENANT_OPERATOR,
      name: 'Tenant Operator',
      description: 'Operates and maintains existing tenant accounts.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: false,
      canDelegate: false,
      inheritanceLevel: 2,
      parentRoleId: 'role-tenant-manager',
      permissions: [
        'tenant:read', 'tenant:write', 'tenant:suspend', 'tenant:reactivate',
        'usage:read', 'quota:read',
      ],
    },
    {
      id: 'role-tenant-auditor',
      type: PlatformRoleType.TENANT_AUDITOR,
      name: 'Tenant Auditor',
      description: 'Audits tenant operations and compliance.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: false,
      canDelegate: false,
      inheritanceLevel: 2,
      parentRoleId: 'role-tenant-manager',
      permissions: ['tenant:read', 'usage:read', 'audit:read'],
    },
    {
      id: 'role-support-administrator',
      type: PlatformRoleType.SUPPORT_ADMINISTRATOR,
      name: 'Support Administrator',
      description: 'Manages support operations and customer escalations.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: true,
      canDelegate: true,
      inheritanceLevel: 1,
      parentRoleId: 'role-platform-administrator',
      permissions: [
        'support:read', 'support:write',
        'impersonate:request',
        'approval:read', 'approval:request',
      ],
    },
    {
      id: 'role-support-tier-1',
      type: PlatformRoleType.SUPPORT_TIER1,
      name: 'Support Tier 1',
      description: 'Basic support operations: password reset, basic queries.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: false,
      canDelegate: false,
      inheritanceLevel: 2,
      parentRoleId: 'role-support-administrator',
      permissions: [
        'identity:read',
        'password:reset',
        'support:read',
      ],
    },
    {
      id: 'role-support-tier-2',
      type: PlatformRoleType.SUPPORT_TIER2,
      name: 'Support Tier 2',
      description: 'Advanced support: troubleshooting, impersonation access.',
      assignmentType: PlatformRoleAssignmentType.ELIGIBLE,
      isSystem: true,
      canAssign: false,
      canDelegate: false,
      inheritanceLevel: 2,
      parentRoleId: 'role-support-administrator',
      permissions: [
        'identity:read', 'identity:write',
        'password:reset',
        'impersonate:request',
        'support:read', 'support:write',
      ],
    },
    {
      id: 'role-observability-administrator',
      type: PlatformRoleType.OBSERVABILITY_ADMINISTRATOR,
      name: 'Observability Administrator',
      description: 'Manages monitoring, metrics, and alerting.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: true,
      canDelegate: true,
      inheritanceLevel: 1,
      parentRoleId: 'role-platform-administrator',
      permissions: [
        'metrics:read', 'metrics:write',
        'log:read', 'log:write',
        'alert:read', 'alert:write', 'alert:manage',
      ],
    },
    {
      id: 'role-metrics-viewer',
      type: PlatformRoleType.METRICS_VIEWER,
      name: 'Metrics Viewer',
      description: 'View platform metrics and dashboards.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: false,
      canDelegate: false,
      inheritanceLevel: 2,
      parentRoleId: 'role-observability-administrator',
      permissions: ['metrics:read'],
    },
    {
      id: 'role-log-viewer',
      type: PlatformRoleType.LOG_VIEWER,
      name: 'Log Viewer',
      description: 'View platform logs and diagnostics.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: false,
      canDelegate: false,
      inheritanceLevel: 2,
      parentRoleId: 'role-observability-administrator',
      permissions: ['log:read'],
    },
    {
      id: 'role-alert-manager',
      type: PlatformRoleType.ALERT_MANAGER,
      name: 'Alert Manager',
      description: 'Manage alert rules and notifications.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: false,
      canDelegate: false,
      inheritanceLevel: 2,
      parentRoleId: 'role-observability-administrator',
      permissions: ['alert:read', 'alert:write', 'alert:manage'],
    },
    {
      id: 'role-billing-administrator',
      type: PlatformRoleType.BILLING_ADMINISTRATOR,
      name: 'Billing Administrator',
      description: 'Manages billing, subscriptions, and financial operations.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: true,
      canDelegate: true,
      inheritanceLevel: 1,
      parentRoleId: 'role-platform-administrator',
      permissions: [
        'billing:read', 'billing:write',
        'subscription:read', 'subscription:write',
        'invoice:read',
      ],
    },
    {
      id: 'role-subscription-manager',
      type: PlatformRoleType.SUBSCRIPTION_MANAGER,
      name: 'Subscription Manager',
      description: 'Manages tenant subscriptions and plans.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: false,
      canDelegate: false,
      inheritanceLevel: 2,
      parentRoleId: 'role-billing-administrator',
      permissions: ['subscription:read', 'subscription:write', 'invoice:read'],
    },
    {
      id: 'role-auditor',
      type: PlatformRoleType.AUDITOR,
      name: 'Auditor',
      description: 'Read-only access to all platform audit logs and compliance reports.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: false,
      canDelegate: false,
      inheritanceLevel: 1,
      parentRoleId: 'role-platform-administrator',
      permissions: [
        'audit:read', 'signin:read',
        'compliance:read', 'report:read',
        'tenant:read', 'identity:read',
      ],
    },
    {
      id: 'role-audit-log-viewer',
      type: PlatformRoleType.AUDIT_LOG_VIEWER,
      name: 'Audit Log Viewer',
      description: 'View audit logs and security events.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: false,
      canDelegate: false,
      inheritanceLevel: 2,
      parentRoleId: 'role-auditor',
      permissions: ['audit:read', 'signin:read'],
    },
    {
      id: 'role-compliance-reporter',
      type: PlatformRoleType.COMPLIANCE_REPORTER,
      name: 'Compliance Reporter',
      description: 'Generate and view compliance reports.',
      assignmentType: PlatformRoleAssignmentType.PERMANENT,
      isSystem: true,
      canAssign: false,
      canDelegate: false,
      inheritanceLevel: 2,
      parentRoleId: 'role-auditor',
      permissions: ['compliance:read', 'report:read', 'report:generate'],
    },
  ];
}