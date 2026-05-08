export interface RoleProps {
  id: string;
  tenantId: string;
  name: string;
  description?: string;
  version?: number;
  permissions: string[];
  createdAt?: Date;
  updatedAt?: Date;
}

export class Role {
  readonly id: string;
  readonly tenantId: string;
  readonly name: string;
  readonly description: string | null;
  private _version: number;
  private _permissions: string[];
  readonly createdAt: Date;
  private _updatedAt: Date;

  constructor(props: RoleProps) {
    this.id = props.id;
    this.tenantId = props.tenantId;
    this.name = props.name;
    this.description = props.description ?? null;
    this._version = props.version ?? 1;
    this._permissions = Array.from(new Set(props.permissions)); // Deduplicate
    this.createdAt = props.createdAt ?? new Date();
    this._updatedAt = props.updatedAt ?? new Date();
  }

  get version(): number {
    return this._version;
  }

  get permissions(): string[] {
    return [...this._permissions];
  }

  get updatedAt(): Date {
    return this._updatedAt;
  }

  updatePermissions(newPermissions: string[]): void {
    this._permissions = Array.from(new Set(newPermissions));
    this._version += 1;
    this._updatedAt = new Date();
  }

  hasPermission(permission: string): boolean {
    return this._permissions.includes(permission);
  }
}
