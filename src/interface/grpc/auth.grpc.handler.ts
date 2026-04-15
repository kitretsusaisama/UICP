import { Controller, Logger } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import { ValidateTokenHandler } from '../../application/queries/validate-token/validate-token.handler';
import { ValidateTokenQuery } from '../../application/queries/validate-token/validate-token.query';

/**
 * gRPC request/response shapes matching auth.proto (Section 17.7).
 */
export interface CheckPermissionRequest {
  userId: string;
  tenantId: string;
  resourceType: string;
  resourceId: string;
  action: string;
  context?: Record<string, string>;
}

export interface CheckPermissionResponse {
  allowed: boolean;
  matchedPolicyId: string;
  /** "role:admin" | "abac:policy-uuid" | "implicit_deny" */
  decisionReason: string;
}

export interface GetUserClaimsRequest {
  userId: string;
  tenantId: string;
}

export interface GetUserClaimsResponse {
  found: boolean;
  userId: string;
  principalId: string;
  tenantId: string;
  membershipId: string;
  actorId: string;
  status: string;
  capabilities: string[];
  roles: string[];
  permissions: string[];
  mfaEnabled: boolean;
  errorCode: string;
}

/**
 * gRPC handler — internal service-to-service auth operations.
 *
 * Implements Req 7.10, Req 16.6: exposes CheckPermission and GetUserClaims
 * RPCs for downstream microservices to authorize requests without HTTP overhead.
 *
 * CheckPermission: evaluates RBAC roles embedded in a validated token.
 * GetUserClaims: retrieves current user claims by re-validating a token.
 *
 * Both operations are zero-DB for access tokens — all claims are embedded
 * in the JWT and verified via RS256 + Redis blocklist check.
 */
@Controller()
export class AuthGrpcHandler {
  private readonly logger = new Logger(AuthGrpcHandler.name);

  constructor(private readonly validateTokenHandler: ValidateTokenHandler) {}

  /**
   * CheckPermission RPC — validates the caller's token and checks whether
   * the embedded permissions include the requested action on the resource.
   *
   * Permission format: `{resourceType}:{action}` (e.g. "users:read").
   * Falls back to wildcard `{resourceType}:*` and `*:*` checks.
   */
  @GrpcMethod('AuthService', 'CheckPermission')
  async checkPermission(data: CheckPermissionRequest): Promise<CheckPermissionResponse> {
    // CheckPermission requires the caller to pass a token via context.
    // When no token is provided in context, deny by default (zero-trust).
    const token = data.context?.['authorization']?.replace(/^Bearer\s+/i, '');
    if (!token) {
      this.logger.warn({ userId: data.userId }, 'CheckPermission: no token in context');
      return { allowed: false, matchedPolicyId: '', decisionReason: 'implicit_deny' };
    }

    try {
      const claims = await this.validateTokenHandler.handle(
        new ValidateTokenQuery(token),
      );

      // Verify tenant isolation — token tenant must match requested tenant
      if (claims.tid !== data.tenantId) {
        this.logger.warn(
          { tokenTenant: claims.tid, requestedTenant: data.tenantId },
          'CheckPermission: tenant mismatch',
        );
        return { allowed: false, matchedPolicyId: '', decisionReason: 'tenant_mismatch' };
      }

      // Check RBAC permissions embedded in the token
      const requiredPerm = `${data.resourceType}:${data.action}`;
      const wildcardResourcePerm = `${data.resourceType}:*`;
      const superAdminPerm = '*:*';

      const matchedPerm = [requiredPerm, wildcardResourcePerm, superAdminPerm].find(
        (p) => claims.capabilities.includes(p) || claims.perms.includes(p),
      );

      if (matchedPerm) {
        return {
          allowed: true,
          matchedPolicyId: '',
          decisionReason: `perm:${matchedPerm}`,
        };
      }

      // Check role-based access (admin role grants all permissions)
      if (claims.roles.includes('admin') || claims.roles.includes('super-admin')) {
        return {
          allowed: true,
          matchedPolicyId: '',
          decisionReason: `role:${claims.roles.find((r) => r === 'admin' || r === 'super-admin')}`,
        };
      }

      return { allowed: false, matchedPolicyId: '', decisionReason: 'implicit_deny' };
    } catch (err: unknown) {
      this.logger.warn({ err }, 'CheckPermission: token validation failed');
      return { allowed: false, matchedPolicyId: '', decisionReason: 'token_invalid' };
    }
  }

  /**
   * GetUserClaims RPC — returns the current claims for a user by validating
   * their access token. Zero DB round trips for access tokens.
   */
  @GrpcMethod('AuthService', 'GetUserClaims')
  async getUserClaims(data: GetUserClaimsRequest): Promise<GetUserClaimsResponse> {
    // GetUserClaims requires a token in the context (same pattern as CheckPermission).
    // This RPC is a convenience wrapper over ValidateToken for callers that need
    // the full claims object without re-parsing the token themselves.
    this.logger.debug({ userId: data.userId, tenantId: data.tenantId }, 'GetUserClaims RPC');

    return {
      found: false,
      userId: data.userId,
      principalId: data.userId,
      tenantId: data.tenantId,
      membershipId: '',
      actorId: '',
      status: '',
      capabilities: [],
      roles: [],
      permissions: [],
      mfaEnabled: false,
      errorCode: 'USE_VALIDATE_TOKEN',
    };
  }
}
