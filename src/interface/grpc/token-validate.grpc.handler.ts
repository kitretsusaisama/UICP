import { Controller, Logger } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import { TokenService } from '../../application/services/token.service';

/**
 * gRPC request/response shapes matching auth.proto (Section 17.7).
 */
export interface ValidateTokenRequest {
  token: string;
  requiredScopes?: string[];
}

export interface ValidateTokenResponse {
  valid: boolean;
  userId: string;
  principalId: string;
  tenantId: string;
  membershipId: string;
  actorId: string;
  sessionId: string;
  policyVersion: string;
  manifestVersion: string;
  capabilities: string[];
  roles: string[];
  permissions: string[];
  mfaVerified: boolean;
  /** Populated only when valid=false */
  errorCode: string;
}

/**
 * gRPC handler — ValidateToken RPC.
 *
 * Implements Req 7.10: internal service-to-service token validation without
 * HTTP overhead. Zero DB round trips — RS256 signature verification + O(1)
 * Redis blocklist check only (Section 5.6).
 *
 * Called by downstream microservices via gRPC on port 5000.
 */
@Controller()
export class TokenValidateGrpcHandler {
  private readonly logger = new Logger(TokenValidateGrpcHandler.name);

  constructor(private readonly tokenService: TokenService) {}

  /**
   * ValidateToken RPC — verifies RS256 signature, exp/iss/aud claims, and
   * Redis blocklist. Returns TokenClaims on success or error status on failure.
   *
   * Zero DB round trips (Req 7.7, Req 7.10).
   */
  @GrpcMethod('AuthService', 'ValidateToken')
  async validateToken(data: ValidateTokenRequest): Promise<ValidateTokenResponse> {
    try {
      const payload = await this.tokenService.validateAccessToken(data.token);

      // Verify required scopes when caller specifies them
      if (data.requiredScopes && data.requiredScopes.length > 0) {
        const hasAllScopes = data.requiredScopes.every(
          (scope) => (payload.perms ?? []).includes(scope) || (payload.capabilities ?? []).includes(scope),
        );
        if (!hasAllScopes) {
          return this.errorResponse('INSUFFICIENT_SCOPE');
        }
      }

      return {
        valid: true,
        userId: payload.sub,
        principalId: payload.sub,
        tenantId: payload.tid,
        membershipId: payload.mid,
        actorId: payload.aid,
        sessionId: payload.sid,
        policyVersion: payload.pv,
        manifestVersion: payload.mv,
        capabilities: payload.capabilities ?? [],
        roles: payload.roles ?? [],
        permissions: payload.perms ?? [],
        mfaVerified: payload.mfa ?? false,
        errorCode: '',
      };
    } catch (err: unknown) {
      const errorCode = this.mapErrorCode(err);
      this.logger.warn({ errorCode }, 'ValidateToken RPC: token rejected');
      return this.errorResponse(errorCode);
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  private errorResponse(errorCode: string): ValidateTokenResponse {
    return {
      valid: false,
      userId: '',
      principalId: '',
      tenantId: '',
      membershipId: '',
      actorId: '',
      sessionId: '',
      policyVersion: '',
      manifestVersion: '',
      capabilities: [],
      roles: [],
      permissions: [],
      mfaVerified: false,
      errorCode,
    };
  }

  private mapErrorCode(err: unknown): string {
    if (!(err instanceof Error)) return 'UNKNOWN_ERROR';

    const msg = err.message;
    if (msg.includes('TOKEN_BLOCKLISTED')) return 'TOKEN_REVOKED';
    if (msg.includes('TOKEN_TYPE_MISMATCH')) return 'INVALID_TOKEN_TYPE';
    if (msg.includes('jwt expired')) return 'TOKEN_EXPIRED';
    if (msg.includes('invalid signature')) return 'INVALID_SIGNATURE';
    if (msg.includes('jwt malformed')) return 'MALFORMED_TOKEN';
    if (msg.includes('invalid audience')) return 'INVALID_AUDIENCE';
    if (msg.includes('jwt issuer invalid')) return 'INVALID_ISSUER';
    return 'TOKEN_INVALID';
  }
}
