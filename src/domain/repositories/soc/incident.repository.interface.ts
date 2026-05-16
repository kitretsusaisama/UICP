export const INCIDENT_REPOSITORY = 'INCIDENT_REPOSITORY';

export interface IIncidentRepository {
  create(input: Record<string, unknown>): Promise<void>;
}
