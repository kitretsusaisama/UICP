import { Injectable } from '@nestjs/common';
import { createPublicKey } from 'crypto';
import { TokenService } from '../../services/token.service';

/** A single JSON Web Key (RFC 7517). */
export interface JsonWebKey {
  kty: string;
  use: string;
  alg: string;
  kid: string;
  n: string;
  e: string;
}

/** JSON Web Key Set (RFC 7517). */
export interface JsonWebKeySet {
  keys: JsonWebKey[];
}

/**
 * Query handler — return all active and deprecated RSA public keys as a JWK Set.
 *
 * Implements: Req 7.6 (JWKS endpoint with active + deprecated keys),
 *             Req 7.8 (7-day overlap window during key rotation)
 *
 * Cache-Control: public, max-age=3600 is set at the controller layer.
 */
@Injectable()
export class GetJwksHandler {
  constructor(private readonly tokenService: TokenService) {}

  handle(): JsonWebKeySet {
    const keys: JsonWebKey[] = [];

    // Primary active key
    const activeKey = this._pemToJwk(
      this.tokenService.getPublicKey(),
      this.tokenService.getKid(),
    );
    if (activeKey) {
      keys.push(activeKey);
    }

    // Deprecated keys (served during the 7-day overlap window after rotation)
    const deprecatedKeys = this.tokenService.getDeprecatedPublicKeys?.() ?? [];
    for (const { publicKey, kid } of deprecatedKeys) {
      const jwk = this._pemToJwk(publicKey, kid);
      if (jwk) {
        keys.push(jwk);
      }
    }

    return { keys };
  }

  /**
   * Convert an RSA PEM public key to a JWK object.
   * Extracts the modulus (n) and exponent (e) from the key material.
   */
  private _pemToJwk(publicKeyPem: string, kid: string): JsonWebKey | null {
    try {
      const keyObj = createPublicKey(publicKeyPem);
      const exported = keyObj.export({ format: 'jwk' }) as {
        kty: string;
        n: string;
        e: string;
      };

      return {
        kty: exported.kty,
        use: 'sig',
        alg: 'RS256',
        kid,
        n: exported.n,
        e: exported.e,
      };
    } catch {
      return null;
    }
  }
}
