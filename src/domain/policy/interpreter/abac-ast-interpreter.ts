/**
 * ABAC AST Interpreter
 *
 * Provides safe evaluation of ABAC policy conditions without any code execution.
 * This replaces any previous JIT compilation approaches that used `new Function()`.
 *
 * Design: No dynamic code execution - only pure JavaScript evaluation of a fixed AST.
 */

import {
  ConditionNode,
  EvaluationContext,
  AttributeNode,
  LiteralNode,
  Operator,
} from '../../value-objects/abac-condition.vo';

// ── Attribute Resolution ───────────────────────────────────────────────────────

/**
 * Resolves an attribute node to its value from the evaluation context.
 * Supports nested paths like `subject.address.city`.
 *
 * @param node The attribute node to resolve
 * @param ctx The evaluation context
 * @returns The resolved value or undefined
 */
export function resolveAttribute(node: AttributeNode, ctx: EvaluationContext): unknown {
  const root = ctx[node.prefix] as Record<string, unknown>;
  if (!root || typeof root !== 'object') return undefined;

  const parts = node.path.split('.');
  let current: unknown = root;

  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== 'object') {
      return undefined;
    }
    current = (current as Record<string, unknown>)[part];
  }

  return current;
}

/**
 * Resolves a value node (literal or attribute) to its actual value.
 */
function resolveValue(node: LiteralNode | AttributeNode, ctx: EvaluationContext): unknown {
  if (node.kind === 'literal') return node.value;
  return resolveAttribute(node, ctx);
}

// ── Comparison Operations ───────────────────────────────────────────────────────

/**
 * Performs comparison between two values using the specified operator.
 * All comparisons are type-safe and never execute dynamic code.
 */
function compare(left: unknown, op: Operator, right: unknown): boolean {
  switch (op) {
    case '==':
      return left === right;
    case '!=':
      return left !== right;
    case '<':
      return typeof left === 'number' && typeof right === 'number' && left < right;
    case '<=':
      return typeof left === 'number' && typeof right === 'number' && left <= right;
    case '>':
      return typeof left === 'number' && typeof right === 'number' && left > right;
    case '>=':
      return typeof left === 'number' && typeof right === 'number' && left >= right;
    case 'IN': {
      if (!Array.isArray(right)) return false;
      return right.includes(left);
    }
    case 'NOT IN': {
      if (!Array.isArray(right)) return true;
      return !right.includes(left);
    }
    case 'CONTAINS': {
      if (typeof left === 'string' && typeof right === 'string') {
        return left.includes(right);
      }
      if (Array.isArray(left)) {
        return left.includes(right);
      }
      return false;
    }
    default:
      return false;
  }
}

// ── AST Interpreter ───────────────────────────────────────────────────────────

/**
 * Interprets a condition AST node against an evaluation context.
 * This is a pure function with no side effects and no code execution.
 *
 * @param node The AST node to evaluate
 * @param ctx The evaluation context (subject, resource, env)
 * @returns Boolean result of the evaluation
 */
export function interpret(node: ConditionNode, ctx: EvaluationContext): boolean {
  switch (node.kind) {
    case 'comparison': {
      const leftVal = resolveAttribute(node.left, ctx);
      const rightVal = resolveValue(node.right, ctx);
      return compare(leftVal, node.operator, rightVal);
    }
    case 'logical': {
      if (node.op === 'AND') {
        return interpret(node.left, ctx) && interpret(node.right, ctx);
      }
      return interpret(node.left, ctx) || interpret(node.right, ctx);
    }
    case 'not':
      return !interpret(node.operand, ctx);
  }
}

// ── Cached Interpreter ───────────────────────────────────────────────────────

/**
 * Creates a memoized interpreter function for a specific AST.
 * Useful for hot paths where the same condition is evaluated many times.
 *
 * @param ast The condition AST to interpret
 * @returns A function that takes context and returns boolean
 */
export function createInterpretedFn(ast: ConditionNode): (ctx: EvaluationContext) => boolean {
  // Pre-validate the AST structure for early failure
  if (!ast || typeof ast !== 'object') {
    throw new Error('Invalid AST: must be a non-null object');
  }

  return (ctx: EvaluationContext) => interpret(ast, ctx);
}

// ── Validation ───────────────────────────────────────────────────────────────

/**
 * Validates that an AST node is well-formed.
 * Useful for debugging and testing.
 */
export function validateAst(node: ConditionNode): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  function visit(n: ConditionNode, path: string): void {
    if (!n || typeof n !== 'object') {
      errors.push(`${path}: expected object, got ${typeof n}`);
      return;
    }

    switch (n.kind) {
      case 'comparison':
        if (!n.left || n.left.kind !== 'attribute') {
          errors.push(`${path}: missing valid left attribute`);
        }
        if (!n.operator) {
          errors.push(`${path}: missing operator`);
        }
        if (!n.right) {
          errors.push(`${path}: missing right value`);
        }
        break;
      case 'logical':
        if (!n.left || !n.right) {
          errors.push(`${path}: logical node missing children`);
        } else {
          visit(n.left, `${path}.left`);
          visit(n.right, `${path}.right`);
        }
        break;
      case 'not':
        if (!n.operand) {
          errors.push(`${path}: not node missing operand`);
        } else {
          visit(n.operand, `${path}.operand`);
        }
        break;
      default:
        errors.push(`${path}: unknown node kind`);
    }
  }

  visit(node, 'root');
  return { valid: errors.length === 0, errors };
}