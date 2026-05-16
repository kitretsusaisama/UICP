/**
 * ABAC Policy Parser
 *
 * Provides a clean interface for parsing ABAC policy DSL strings into AST nodes.
 * Wraps the existing AbacCondition value object from value-objects module.
 */

import {
  AbacCondition,
  ConditionNode,
} from '../../value-objects/abac-condition.vo';
import { DomainException } from '../../exceptions/domain.exception';
import { DomainErrorCode } from '../../exceptions/domain-error-codes';

// ── Parser Interface ─────────────────────────────────────────────────────────

export interface ParsedCondition {
  readonly ast: ConditionNode;
  readonly raw: string;
}

/**
 * Parses an ABAC policy DSL string into a structured condition.
 *
 * @param dsl The policy condition in DSL format (e.g., "subject.role == 'admin'")
 * @returns Parsed condition with AST and raw string
 * @throws DomainException if the DSL is invalid
 */
export function parseCondition(dsl: string): ParsedCondition {
  if (typeof dsl !== 'string' || dsl.trim().length === 0) {
    throw new DomainException(
      DomainErrorCode.INVALID_ABAC_CONDITION,
      'ABAC condition DSL must be a non-empty string',
    );
  }

  try {
    const condition = AbacCondition.parse(dsl);
    // Access the internal AST via the toJSON method
    const json = condition.toJSON() as ConditionNode;
    return {
      ast: json,
      raw: dsl,
    };
  } catch (err) {
    if (err instanceof DomainException) throw err;
    throw new DomainException(
      DomainErrorCode.INVALID_ABAC_CONDITION,
      `Failed to parse ABAC condition: ${(err as Error).message}`,
    );
  }
}

/**
 * Validates a condition DSL string without fully parsing it.
 * Useful for quick validation before full parsing.
 */
export function validateCondition(dsl: string): { valid: boolean; error?: string } {
  if (typeof dsl !== 'string') {
    return { valid: false, error: 'Condition must be a string' };
  }

  if (dsl.trim().length === 0) {
    return { valid: false, error: 'Condition cannot be empty' };
  }

  // Basic DSL validation - check for dangerous patterns
  const dangerousPatterns = [
    /eval\s*\(/i,
    /Function\s*\(/i,
    /new\s+Function/i,
    /\`.*\$\{/, // Template literals with interpolation
  ];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(dsl)) {
      return { valid: false, error: 'Condition contains potentially dangerous patterns' };
    }
  }

  try {
    AbacCondition.parse(dsl);
    return { valid: true };
  } catch (err) {
    return { valid: false, error: (err as Error).message };
  }
}

// ── Condition Builder ─────────────────────────────────────────────────────────

/**
 * Builder for constructing conditions programmatically.
 * Useful for testing or dynamic policy creation.
 */
export class ConditionBuilder {
  private parts: string[] = [];

  /**
   * Add an attribute comparison.
   */
  compare(attribute: string, operator: string, value: string | number | boolean): this {
    this.parts.push(`${attribute} ${operator} ${this.formatValue(value)}`);
    return this;
  }

  /**
   * Add AND logic.
   */
  and(): this {
    this.parts.push('AND');
    return this;
  }

  /**
   * Add OR logic.
   */
  or(): this {
    this.parts.push('OR');
    return this;
  }

  /**
   * Add NOT logic.
   */
  not(): this {
    this.parts.push('NOT');
    return this;
  }

  /**
   * Build the DSL string.
   */
  build(): string {
    return this.parts.join(' ');
  }

  /**
   * Parse and return the AST.
   */
  parse(): ParsedCondition {
    return parseCondition(this.build());
  }

  private formatValue(value: string | number | boolean): string {
    if (typeof value === 'string') {
      return `'${value}'`;
    }
    return String(value);
  }
}

// ── Export AbacCondition for compatibility ───────────────────────────────────

export { AbacCondition } from '../../value-objects/abac-condition.vo';