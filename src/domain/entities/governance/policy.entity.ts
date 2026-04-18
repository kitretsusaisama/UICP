export type PolicyEffect = 'allow' | 'deny';
export type PolicyStatus = 'active' | 'inactive';

export interface PolicyCondition {
  field: string;
  op: 'eq' | 'neq' | 'in' | 'gt' | 'lt';
  value: any;
}

export interface PolicyRules {
  effect: PolicyEffect;
  conditions: PolicyCondition[];
}

export interface PolicyProps {
  id: string;
  tenantId: string;
  name: string;
  description?: string;
  rules: PolicyRules;
  status?: PolicyStatus;
  version?: number;
  createdAt?: Date;
  updatedAt?: Date;
}

export class Policy {
  readonly id: string;
  readonly tenantId: string;
  readonly name: string;
  readonly description: string | null;
  private _rules: PolicyRules;
  private _status: PolicyStatus;
  private _version: number;
  readonly createdAt: Date;
  private _updatedAt: Date;

  constructor(props: PolicyProps) {
    this.id = props.id;
    this.tenantId = props.tenantId;
    this.name = props.name;
    this.description = props.description ?? null;
    this._rules = props.rules;
    this._status = props.status ?? 'active';
    this._version = props.version ?? 1;
    this.createdAt = props.createdAt ?? new Date();
    this._updatedAt = props.updatedAt ?? new Date();

    this.validateRules(this._rules);
  }

  get rules(): PolicyRules {
    return JSON.parse(JSON.stringify(this._rules)); // Return copy
  }

  get status(): PolicyStatus {
    return this._status;
  }

  get version(): number {
    return this._version;
  }

  get updatedAt(): Date {
    return this._updatedAt;
  }

  /**
   * Safe AST validation. Rejects deep nesting, huge payloads, or unsupported ops.
   */
  private validateRules(rules: PolicyRules): void {
    if (rules.effect !== 'allow' && rules.effect !== 'deny') {
      throw new Error(`Invalid effect: ${rules.effect}`);
    }

    // Ensure size does not exceed 5KB.
    const ruleString = JSON.stringify(rules);
    if (ruleString.length > 5120) {
      throw new Error('Policy payload too large (max 5KB)');
    }

    // Ensure nesting (if we allow `and/or` nested conditions in future) is not deeper than 10.
    const getDepth = (obj: any): number => {
      if (typeof obj !== 'object' || obj === null) return 1;
      return 1 + Math.max(0, ...Object.values(obj).map(v => getDepth(v)));
    };

    if (getDepth(rules) > 10) {
      throw new Error('Policy conditions exceed maximum nesting depth of 10');
    }

    // Basic operator validation
    const validOps = ['eq', 'neq', 'in', 'gt', 'lt'];
    for (const condition of rules.conditions) {
      if (!validOps.includes(condition.op)) {
        throw new Error(`Unsupported operator: ${condition.op}`);
      }
    }
  }

  updateRules(newRules: PolicyRules): void {
    this.validateRules(newRules);
    this._rules = newRules;
    this._version += 1;
    this._updatedAt = new Date();
  }

  deactivate(): void {
    this._status = 'inactive';
    this._version += 1;
    this._updatedAt = new Date();
  }
}
