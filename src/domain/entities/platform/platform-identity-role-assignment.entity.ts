import { PlatformRoleType, PlatformRoleAssignmentType } from './platform-role.entity';

export interface PlatformIdentityRoleAssignmentProps {
  id: string;
  platformIdentityId: string;
  roleId: string;
  roleType: PlatformRoleType;
  assignmentType: PlatformRoleAssignmentType;
  assignedBy: string;
  assignedAt: Date;
  activatedAt?: Date;
  expiresAt?: Date;
  justification?: string;
  deactivatedAt?: Date;
  deactivationReason?: string;
}

export class PlatformIdentityRoleAssignment {
  readonly id: string;
  readonly platformIdentityId: string;
  readonly roleId: string;
  readonly roleType: PlatformRoleType;
  readonly assignmentType: PlatformRoleAssignmentType;
  readonly assignedBy: string;
  readonly assignedAt: Date;
  private _activatedAt: Date | null;
  private _expiresAt: Date | null;
  private _justification: string | null;
  private _deactivatedAt: Date | null;
  private _deactivationReason: string | null;

  constructor(props: PlatformIdentityRoleAssignmentProps) {
    this.id = props.id;
    this.platformIdentityId = props.platformIdentityId;
    this.roleId = props.roleId;
    this.roleType = props.roleType;
    this.assignmentType = props.assignmentType;
    this.assignedBy = props.assignedBy;
    this.assignedAt = props.assignedAt;
    this._activatedAt = props.activatedAt ?? null;
    this._expiresAt = props.expiresAt ?? null;
    this._justification = props.justification ?? null;
    this._deactivatedAt = props.deactivatedAt ?? null;
    this._deactivationReason = props.deactivationReason ?? null;
  }

  get activatedAt(): Date | null { return this._activatedAt; }
  get expiresAt(): Date | null { return this._expiresAt; }
  get justification(): string | null { return this._justification; }
  get deactivatedAt(): Date | null { return this._deactivatedAt; }
  get deactivationReason(): string | null { return this._deactivationReason; }

  get isActive(): boolean {
    if (this._deactivatedAt) return false;
    if (this._expiresAt && new Date() > this._expiresAt) return false;
    return true;
  }

  get isEligible(): boolean {
    return this.assignmentType === PlatformRoleAssignmentType.ELIGIBLE;
  }

  get isActivated(): boolean {
    return this._activatedAt !== null;
  }

  get isExpired(): boolean {
    return this._expiresAt !== null && new Date() > this._expiresAt;
  }

  get requiresJitActivation(): boolean {
    return this.isEligible && !this.isActivated;
  }

  activate(until?: Date): void {
    if (!this.isEligible) {
      throw new Error('Only eligible assignments can be activated');
    }
    this._activatedAt = new Date();
    this._expiresAt = until ?? new Date(Date.now() + 8 * 60 * 60 * 1000);
  }

  deactivate(reason: string): void {
    this._deactivatedAt = new Date();
    this._deactivationReason = reason;
  }

  toResponse() {
    return {
      id: this.id,
      platformIdentityId: this.platformIdentityId,
      roleId: this.roleId,
      roleType: this.roleType,
      assignmentType: this.assignmentType,
      assignedBy: this.assignedBy,
      assignedAt: this.assignedAt.toISOString(),
      activatedAt: this._activatedAt?.toISOString() ?? null,
      expiresAt: this._expiresAt?.toISOString() ?? null,
      isActive: this.isActive,
      isActivated: this.isActivated,
      justification: this._justification,
    };
  }

  static create(props: {
    platformIdentityId: string;
    roleId: string;
    roleType: PlatformRoleType;
    assignmentType: PlatformRoleAssignmentType;
    assignedBy: string;
    justification?: string;
    expiresAt?: Date;
  }): PlatformIdentityRoleAssignment {
    return new PlatformIdentityRoleAssignment({
      id: crypto.randomUUID(),
      platformIdentityId: props.platformIdentityId,
      roleId: props.roleId,
      roleType: props.roleType,
      assignmentType: props.assignmentType,
      assignedBy: props.assignedBy,
      assignedAt: new Date(),
      activatedAt: props.assignmentType === PlatformRoleAssignmentType.PERMANENT ? new Date() : undefined,
      expiresAt: props.expiresAt,
      justification: props.justification,
    });
  }
}