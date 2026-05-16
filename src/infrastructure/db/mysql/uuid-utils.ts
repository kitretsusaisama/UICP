/**
 * UUID utilities for MySQL binary storage.
 * All UUIDs are stored as BINARY(16) in MySQL for efficient indexing.
 */

/**
 * Converts a UUID string to a 16-byte Buffer for MySQL BINARY(16) column storage.
 * @param uuid - UUID string in standard format (e.g., "123e4567-e89b-42d3-a456-426614174000")
 * @returns 16-byte Buffer suitable for MySQL BINARY(16) columns
 */
export function uuidToBuffer(uuid: string): Buffer {
  // Remove dashes and convert hex string to buffer
  return Buffer.from(uuid.replace(/-/g, ''), 'hex');
}

/**
 * Converts a 16-byte Buffer from MySQL BINARY(16) back to UUID string format.
 * @param buf - 16-byte Buffer or hex string from MySQL
 * @returns UUID string in standard format
 */
export function bufferToUuid(buf: Buffer | string): string {
  const hex = Buffer.isBuffer(buf) ? buf.toString('hex') : buf;
  if (hex.length !== 32) {
    throw new Error('Invalid hex length for UUID conversion');
  }
  // Insert dashes to format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}