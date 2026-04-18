export interface RoleAssignmentProps {
  id: string;
  tenantId: string;
  userId: string;
  roleId: string;
  assignedBy: string;
  createdAt?: Date;
  expiresAt?: Date | null;
}

export class RoleAssignment {
  readonly id: string;
  readonly tenantId: string;
  readonly userId: string;
  readonly roleId: string;
  readonly assignedBy: string;
  readonly createdAt: Date;
  readonly expiresAt: Date | null;

  constructor(props: RoleAssignmentProps) {
    this.id = props.id;
    this.tenantId = props.tenantId;
    this.userId = props.userId;
    this.roleId = props.roleId;
    this.assignedBy = props.assignedBy;
    this.createdAt = props.createdAt ?? new Date();
    this.expiresAt = props.expiresAt ?? null;
  }

  isActive(): boolean {
    if (this.expiresAt && this.expiresAt < new Date()) {
      return false;
    }
    return true;
  }
}
