import { timingSafeEqual as cryptoTimingSafeEqual } from 'crypto';

/**
 * Performs a constant-time string comparison to prevent timing attacks.
 * Both strings are encoded to UTF-8 buffers before comparison.
 * If lengths differ, returns false without leaking length information
 * via a dummy comparison of equal-length buffers.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  if (bufA.length !== bufB.length) {
    // Perform a dummy comparison to avoid leaking length via timing
    cryptoTimingSafeEqual(bufA, bufA);
    return false;
  }

  return cryptoTimingSafeEqual(bufA, bufB);
}
