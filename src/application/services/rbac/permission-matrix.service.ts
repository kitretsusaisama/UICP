/**
 * Permission Matrix Service
 *
 * Provides resource-level permission grants and matrix management.
 * Enables fine-grained access control per resource and action.
 */

import { Injectable, Logger } from '@nestjs/common';
import { RoleHierarchyService, RoleLevel } from './role-hierarchy.service';

export interface PermissionGrant {
  role: string;
  resource: string;
  allow: boolean;
}

export interface PermissionCheckResult {
  allowed: boolean;
  reason?: string;
}

export interface PermissionMatrix {
  grants: PermissionGrant[];
  roleLevel: RoleLevel;
}

@Injectable()
export class PermissionMatrixService {
  private readonly logger = new Logger(PermissionMatrixService.name);

  constructor(private readonly roleHierarchy: RoleHierarchyService) {}

  checkPermission(roleName: string, resource: string, action: string): PermissionCheckResult {
    const hierarchy = this.roleHierarchy.getEffectivePermissions(roleName);

    if (hierarchy.allPermissions.includes('*')) {
      return { allowed: true };
    }

    const exactPermission = `${resource}:${action}`;
    if (hierarchy.allPermissions.includes(exactPermission)) {
      return { allowed: true };
    }

    const hasResourceWildcard = hierarchy.allPermissions.includes(`${resource}:*`);
    const hasActionWildcard = hierarchy.allPermissions.includes(`*:${action}`);

    if (hasResourceWildcard || hasActionWildcard) {
      return { allowed: true };
    }

    return { allowed: false, reason: `No permission for ${resource}:${action}` };
  }

  getPermissionMatrix(roleName: string): PermissionMatrix {
    const hierarchy = this.roleHierarchy.getEffectivePermissions(roleName);
    const grants: PermissionGrant[] = [];

    for (const perm of hierarchy.allPermissions) {
      if (perm === '*') {
        grants.push({ role: roleName, resource: '*', allow: true });
        continue;
      }
      const parts = perm.split(':');
      const resource = parts[0] ?? '';
      grants.push({ role: roleName, resource, allow: true });
    }

    return { grants, roleLevel: hierarchy.effectiveLevel };
  }

  filterAccessibleResources(roleName: string, resources: string[]): string[] {
    return resources.filter((resource) => this.checkPermission(roleName, resource, 'read').allowed);
  }

  getPermissionSummary(roleName: string): Record<string, string[]> {
    const hierarchy = this.roleHierarchy.getEffectivePermissions(roleName);
    const summary: Record<string, string[]> = {};

    for (const perm of hierarchy.allPermissions) {
      if (perm === '*') continue;
      const parts = perm.split(':');
      const resource = parts[0] ?? '';
      const action = parts[1] ?? 'read';
      if (!summary[resource]) summary[resource] = [];
      summary[resource].push(action);
    }

    return summary;
  }

  canAccessPath(roleName: string, path: string): boolean {
    const parts = path.split('/').filter(Boolean);
    if (parts.length === 0) return false;
    const resource = parts[0] ?? '';
    const action = parts[1] ?? 'read';
    return this.checkPermission(roleName, resource, action).allowed;
  }
}