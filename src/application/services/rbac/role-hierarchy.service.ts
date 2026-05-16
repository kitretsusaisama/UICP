/**
 * Role Hierarchy Service
 *
 * Manages hierarchical role definitions (admin > manager > user).
 * Provides inheritance-based permission resolution.
 */

import { Injectable, Logger } from '@nestjs/common';

export type RoleLevel = 'admin' | 'manager' | 'user' | 'viewer';

export interface RoleDefinition {
  name: string;
  level: RoleLevel;
  inheritsFrom?: string;
  permissions: string[];
}

export interface RoleHierarchyResult {
  directPermissions: string[];
  inheritedPermissions: string[];
  allPermissions: string[];
  effectiveLevel: RoleLevel;
}

@Injectable()
export class RoleHierarchyService {
  private readonly logger = new Logger(RoleHierarchyService.name);

  private readonly defaultRoles: Record<string, RoleDefinition> = {
    admin: { name: 'Admin', level: 'admin', permissions: ['*'] },
    manager: { name: 'Manager', level: 'manager', inheritsFrom: 'user', permissions: ['users:write', 'reports:read', 'reports:write'] },
    user: { name: 'User', level: 'user', inheritsFrom: 'viewer', permissions: ['profile:write', 'sessions:read', 'sessions:delete'] },
    viewer: { name: 'Viewer', level: 'viewer', permissions: ['profile:read'] },
  };

  getEffectivePermissions(roleName: string): RoleHierarchyResult {
    const role = this.defaultRoles[roleName];
    if (!role) {
      return { directPermissions: [], inheritedPermissions: [], allPermissions: [], effectiveLevel: 'viewer' };
    }

    const directPermissions = [...role.permissions];
    const inheritedPermissions: string[] = [];
    const visited = new Set<string>();
    this.collectInheritedPermissions(roleName, inheritedPermissions, visited);

    const allPermissions = [...directPermissions, ...inheritedPermissions.filter((p) => !directPermissions.includes(p))];
    const effectivePermissions = role.level === 'admin' ? ['*'] : allPermissions;

    return { directPermissions, inheritedPermissions, allPermissions: effectivePermissions, effectiveLevel: role.level };
  }

  hasPermission(roleName: string, permission: string): boolean {
    const result = this.getEffectivePermissions(roleName);
    if (result.allPermissions.includes('*')) return true;
    if (result.allPermissions.includes(permission)) return true;
    return result.allPermissions.some((p) => p.endsWith(':*') && permission.startsWith(p.slice(0, -1)));
  }

  isHigherOrEqual(roleA: string, roleB: string): boolean {
    const levelOrder: Record<RoleLevel, number> = { admin: 4, manager: 3, user: 2, viewer: 1 };
    const resultA = this.getEffectivePermissions(roleA);
    const resultB = this.getEffectivePermissions(roleB);
    return levelOrder[resultA.effectiveLevel] >= levelOrder[resultB.effectiveLevel];
  }

  getAllRoles(): RoleDefinition[] {
    return Object.values(this.defaultRoles);
  }

  isValidRole(roleName: string): boolean {
    return roleName in this.defaultRoles;
  }

  private collectInheritedPermissions(roleName: string, collected: string[], visited: Set<string>): void {
    if (visited.has(roleName)) return;
    visited.add(roleName);
    const role = this.defaultRoles[roleName];
    if (!role || !role.inheritsFrom) return;
    const parent = this.defaultRoles[role.inheritsFrom];
    if (parent) {
      collected.push(...parent.permissions.filter((p) => !collected.includes(p)));
      this.collectInheritedPermissions(role.inheritsFrom, collected, visited);
    }
  }
}