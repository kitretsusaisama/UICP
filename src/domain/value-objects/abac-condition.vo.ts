import { DomainException } from '../exceptions/domain.exception';
import { DomainErrorCode } from '../exceptions/domain-error-codes';

// ── AST Node Types ────────────────────────────────────────────────────────────

export type Operator = '==' | '!=' | '<' | '<=' | '>' | '>=' | 'IN' | 'NOT IN' | 'CONTAINS';
export type AttributePrefix = 'subject' | 'resource' | 'env';

export interface AttributeNode {
  kind: 'attribute';
  prefix: AttributePrefix;
  path: string; // e.g. "role", "tenantId", "time"
}

export type LiteralValue = string | number | boolean | LiteralValue[];

export interface LiteralNode {
  kind: 'literal';
  value: LiteralValue;
}

export interface ComparisonNode {
  kind: 'comparison';
  left: AttributeNode;
  operator: Operator;
  right: LiteralNode | AttributeNode;
}

export interface LogicalNode {
  kind: 'logical';
  op: 'AND' | 'OR';
  left: ConditionNode;
  right: ConditionNode;
}

export interface NotNode {
  kind: 'not';
  operand: ConditionNode;
}

export type ConditionNode = ComparisonNode | LogicalNode | NotNode;

// ── Evaluation Context ────────────────────────────────────────────────────────

export interface EvaluationContext {
  subject: Record<string, unknown>;
  resource: Record<string, unknown>;
  env: Record<string, unknown>;
}

// ── Tokenizer ─────────────────────────────────────────────────────────────────

type TokenType =
  | 'IDENT'
  | 'STRING'
  | 'NUMBER'
  | 'BOOLEAN'
  | 'LPAREN'
  | 'RPAREN'
  | 'LBRACKET'
  | 'RBRACKET'
  | 'COMMA'
  | 'DOT'
  | 'OP'
  | 'AND'
  | 'OR'
  | 'NOT'
  | 'IN'
  | 'NOT_IN'
  | 'CONTAINS'
  | 'EOF';

interface Token {
  type: TokenType;
  value: string;
  pos: number;
}

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;

  while (i < input.length) {
    // Skip whitespace
    if (/\s/.test(input[i]!)) {
      i++;
      continue;
    }

    const pos = i;

    // String literal
    if (input[i] === '"') {
      let str = '';
      i++; // skip opening quote
      while (i < input.length && input[i] !== '"') {
        if (input[i] === '\\' && i + 1 < input.length) {
          i++;
          str += input[i];
        } else {
          str += input[i];
        }
        i++;
      }
      if (i >= input.length) {
        throw new DomainException(DomainErrorCode.INVALID_ABAC_CONDITION, 'Unterminated string literal');
      }
      i++; // skip closing quote
      tokens.push({ type: 'STRING', value: str, pos });
      continue;
    }

    // Number literal
    if (/[0-9]/.test(input[i]!)) {
      let num = '';
      while (i < input.length && /[0-9.]/.test(input[i]!)) {
        num += input[i];
        i++;
      }
      tokens.push({ type: 'NUMBER', value: num, pos });
      continue;
    }

    // Operators: <=, >=, !=, ==, <, >
    if (input[i] === '<' || input[i] === '>' || input[i] === '!' || input[i] === '=') {
      const two = input.slice(i, i + 2);
      if (['<=', '>=', '!=', '=='].includes(two)) {
        tokens.push({ type: 'OP', value: two, pos });
        i += 2;
      } else if (input[i] === '<' || input[i] === '>') {
        tokens.push({ type: 'OP', value: input[i]!, pos });
        i++;
      } else {
        throw new DomainException(
          DomainErrorCode.INVALID_ABAC_CONDITION,
          `Unexpected character '${input[i]}' at position ${i}`,
        );
      }
      continue;
    }

    // Punctuation
    if (input[i] === '(') { tokens.push({ type: 'LPAREN', value: '(', pos }); i++; continue; }
    if (input[i] === ')') { tokens.push({ type: 'RPAREN', value: ')', pos }); i++; continue; }
    if (input[i] === '[') { tokens.push({ type: 'LBRACKET', value: '[', pos }); i++; continue; }
    if (input[i] === ']') { tokens.push({ type: 'RBRACKET', value: ']', pos }); i++; continue; }
    if (input[i] === ',') { tokens.push({ type: 'COMMA', value: ',', pos }); i++; continue; }
    if (input[i] === '.') { tokens.push({ type: 'DOT', value: '.', pos }); i++; continue; }

    // Identifiers and keywords
    if (/[a-zA-Z_]/.test(input[i]!)) {
      let ident = '';
      while (i < input.length && /[a-zA-Z0-9_]/.test(input[i]!)) {
        ident += input[i];
        i++;
      }

      // Check for "NOT IN" (two-token keyword)
      if (ident === 'NOT') {
        // Peek ahead for 'IN'
        let j = i;
        while (j < input.length && /\s/.test(input[j]!)) j++;
        if (input.slice(j, j + 2) === 'IN' && (j + 2 >= input.length || !/[a-zA-Z0-9_]/.test(input[j + 2]!))) {
          i = j + 2;
          tokens.push({ type: 'NOT_IN', value: 'NOT IN', pos });
          continue;
        }
        tokens.push({ type: 'NOT', value: 'NOT', pos });
        continue;
      }

      const upper = ident.toUpperCase();
      if (upper === 'AND') { tokens.push({ type: 'AND', value: 'AND', pos }); continue; }
      if (upper === 'OR') { tokens.push({ type: 'OR', value: 'OR', pos }); continue; }
      if (upper === 'IN') { tokens.push({ type: 'IN', value: 'IN', pos }); continue; }
      if (upper === 'CONTAINS') { tokens.push({ type: 'CONTAINS', value: 'CONTAINS', pos }); continue; }
      if (ident === 'true' || ident === 'false') {
        tokens.push({ type: 'BOOLEAN', value: ident, pos });
        continue;
      }

      tokens.push({ type: 'IDENT', value: ident, pos });
      continue;
    }

    throw new DomainException(
      DomainErrorCode.INVALID_ABAC_CONDITION,
      `Unexpected character '${input[i]}' at position ${i}`,
    );
  }

  tokens.push({ type: 'EOF', value: '', pos: i });
  return tokens;
}

// ── Recursive Descent Parser ──────────────────────────────────────────────────

class Parser {
  private pos = 0;

  constructor(private readonly tokens: Token[]) {}

  private peek(): Token {
    return this.tokens[this.pos]!;
  }

  private consume(): Token {
    return this.tokens[this.pos++]!;
  }

  private expect(type: TokenType): Token {
    const tok = this.peek();
    if (tok.type !== type) {
      throw new DomainException(
        DomainErrorCode.INVALID_ABAC_CONDITION,
        `Expected ${type} but got ${tok.type} ('${tok.value}') at position ${tok.pos}`,
      );
    }
    return this.consume();
  }

  parse(): ConditionNode {
    const node = this.parseExpr();
    if (this.peek().type !== 'EOF') {
      const tok = this.peek();
      throw new DomainException(
        DomainErrorCode.INVALID_ABAC_CONDITION,
        `Unexpected token '${tok.value}' at position ${tok.pos}`,
      );
    }
    return node;
  }

  // expr ::= term (('AND' | 'OR') term)*
  private parseExpr(): ConditionNode {
    let left = this.parseTerm();

    while (this.peek().type === 'AND' || this.peek().type === 'OR') {
      const op = this.consume().type as 'AND' | 'OR';
      const right = this.parseTerm();
      left = { kind: 'logical', op, left, right } satisfies LogicalNode;
    }

    return left;
  }

  // term ::= 'NOT' term | '(' expr ')' | comparison
  private parseTerm(): ConditionNode {
    if (this.peek().type === 'NOT') {
      this.consume();
      const operand = this.parseTerm();
      return { kind: 'not', operand } satisfies NotNode;
    }

    if (this.peek().type === 'LPAREN') {
      this.consume();
      const node = this.parseExpr();
      this.expect('RPAREN');
      return node;
    }

    return this.parseComparison();
  }

  // comparison ::= attribute operator value
  private parseComparison(): ComparisonNode {
    const left = this.parseAttribute();
    const operator = this.parseOperator();
    const right = this.parseValue();
    return { kind: 'comparison', left, operator, right } satisfies ComparisonNode;
  }

  // attribute ::= ('subject' | 'resource' | 'env') '.' IDENT ('.' IDENT)*
  private parseAttribute(): AttributeNode {
    const prefixTok = this.expect('IDENT');
    const prefix = prefixTok.value;

    if (prefix !== 'subject' && prefix !== 'resource' && prefix !== 'env') {
      throw new DomainException(
        DomainErrorCode.INVALID_ABAC_CONDITION,
        `Attribute prefix must be 'subject', 'resource', or 'env', got '${prefix}'`,
      );
    }

    this.expect('DOT');
    let path = this.expect('IDENT').value;

    // Support nested paths like subject.address.city
    while (this.peek().type === 'DOT') {
      this.consume();
      path += '.' + this.expect('IDENT').value;
    }

    return { kind: 'attribute', prefix: prefix as AttributePrefix, path };
  }

  // operator ::= '==' | '!=' | '<' | '<=' | '>' | '>=' | 'IN' | 'NOT IN' | 'CONTAINS'
  private parseOperator(): Operator {
    const tok = this.peek();

    if (tok.type === 'OP') {
      this.consume();
      return tok.value as Operator;
    }
    if (tok.type === 'IN') {
      this.consume();
      return 'IN';
    }
    if (tok.type === 'NOT_IN') {
      this.consume();
      return 'NOT IN';
    }
    if (tok.type === 'CONTAINS') {
      this.consume();
      return 'CONTAINS';
    }

    throw new DomainException(
      DomainErrorCode.INVALID_ABAC_CONDITION,
      `Expected operator but got '${tok.value}' at position ${tok.pos}`,
    );
  }

  // value ::= STRING | NUMBER | BOOLEAN | '[' value (',' value)* ']' | attribute
  private parseValue(): LiteralNode | AttributeNode {
    const tok = this.peek();

    if (tok.type === 'STRING') {
      this.consume();
      return { kind: 'literal', value: tok.value };
    }

    if (tok.type === 'NUMBER') {
      this.consume();
      return { kind: 'literal', value: parseFloat(tok.value) };
    }

    if (tok.type === 'BOOLEAN') {
      this.consume();
      return { kind: 'literal', value: tok.value === 'true' };
    }

    if (tok.type === 'LBRACKET') {
      this.consume();
      const items: LiteralValue[] = [];

      if (this.peek().type !== 'RBRACKET') {
        items.push(this.parseLiteralValue());
        while (this.peek().type === 'COMMA') {
          this.consume();
          items.push(this.parseLiteralValue());
        }
      }

      this.expect('RBRACKET');
      return { kind: 'literal', value: items };
    }

    // Could be an attribute reference on the right-hand side
    if (tok.type === 'IDENT' && (tok.value === 'subject' || tok.value === 'resource' || tok.value === 'env')) {
      return this.parseAttribute();
    }

    throw new DomainException(
      DomainErrorCode.INVALID_ABAC_CONDITION,
      `Expected value but got '${tok.value}' at position ${tok.pos}`,
    );
  }

  private parseLiteralValue(): LiteralValue {
    const node = this.parseValue();
    if (node.kind !== 'literal') {
      throw new DomainException(
        DomainErrorCode.INVALID_ABAC_CONDITION,
        'Array elements must be literal values',
      );
    }
    return node.value;
  }
}

// ── Evaluator ─────────────────────────────────────────────────────────────────

function resolveAttribute(node: AttributeNode, ctx: EvaluationContext): unknown {
  const root = ctx[node.prefix] as Record<string, unknown>;
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

function resolveValue(node: LiteralNode | AttributeNode, ctx: EvaluationContext): unknown {
  if (node.kind === 'literal') return node.value;
  return resolveAttribute(node, ctx);
}

function compare(left: unknown, op: Operator, right: unknown): boolean {
  switch (op) {
    case '==':
      return left === right;
    case '!=':
      return left !== right;
    case '<':
      return (left as number) < (right as number);
    case '<=':
      return (left as number) <= (right as number);
    case '>':
      return (left as number) > (right as number);
    case '>=':
      return (left as number) >= (right as number);
    case 'IN': {
      if (!Array.isArray(right)) return false;
      return (right as unknown[]).includes(left);
    }
    case 'NOT IN': {
      if (!Array.isArray(right)) return true;
      return !(right as unknown[]).includes(left);
    }
    case 'CONTAINS': {
      if (typeof left === 'string' && typeof right === 'string') {
        return left.includes(right);
      }
      if (Array.isArray(left)) {
        return (left as unknown[]).includes(right);
      }
      return false;
    }
    default:
      return false;
  }
}

function evaluateNode(node: ConditionNode, ctx: EvaluationContext): boolean {
  switch (node.kind) {
    case 'comparison': {
      const leftVal = resolveAttribute(node.left, ctx);
      const rightVal = resolveValue(node.right, ctx);
      return compare(leftVal, node.operator, rightVal);
    }
    case 'logical': {
      if (node.op === 'AND') {
        return evaluateNode(node.left, ctx) && evaluateNode(node.right, ctx);
      }
      return evaluateNode(node.left, ctx) || evaluateNode(node.right, ctx);
    }
    case 'not':
      return !evaluateNode(node.operand, ctx);
  }
}

// ── Value Object ──────────────────────────────────────────────────────────────

export class AbacCondition {
  private constructor(private readonly ast: ConditionNode) {}

  /**
   * Parse a DSL condition string into an AbacCondition value object.
   * Throws DomainException(INVALID_ABAC_CONDITION) if the DSL is invalid.
   */
  static parse(dsl: string): AbacCondition {
    if (typeof dsl !== 'string' || dsl.trim().length === 0) {
      throw new DomainException(
        DomainErrorCode.INVALID_ABAC_CONDITION,
        'ABAC condition DSL must be a non-empty string',
      );
    }

    try {
      const tokens = tokenize(dsl);
      const parser = new Parser(tokens);
      const ast = parser.parse();
      return new AbacCondition(ast);
    } catch (err) {
      if (err instanceof DomainException) throw err;
      throw new DomainException(
        DomainErrorCode.INVALID_ABAC_CONDITION,
        `Failed to parse ABAC condition: ${(err as Error).message}`,
      );
    }
  }

  /**
   * Evaluate the condition against the given context.
   * Returns true if the condition matches, false otherwise.
   */
  evaluate(context: EvaluationContext): boolean {
    return evaluateNode(this.ast, context);
  }

  /** Serialize the AST to a plain JSON-serializable object. */
  toJSON(): object {
    return this.ast as unknown as object;
  }
}
