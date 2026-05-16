import { Injectable, NotFoundException, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { ulid } from 'ulid';

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy'; components: Record<string, any>;
  lastChecked: Date; uptime: number; version: string;
}

export interface ResilienceIncident {
  id: string; title: string; description: string; severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'investigating' | 'identified' | 'monitoring' | 'resolved';
  components: string[]; startedAt: Date; resolvedAt: Date | null;
  updates: { status: string; message: string; timestamp: Date }[];
}

export interface CircuitBreaker {
  id: string; service: string; state: 'closed' | 'open' | 'half_open';
  failureCount: number; lastFailureAt: Date | null; threshold: number;
  timeout: number; createdAt: Date; updatedAt: Date;
}

export interface ChaosExperiment {
  id: string; name: string; description: string; type: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  targetServices: string[]; parameters: Record<string, any>;
  startedAt: Date | null; completedAt: Date | null; createdBy: string;
}

@Injectable()
export class PlatformResilienceService {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async getHealth(): Promise<HealthStatus> {
    const [rows]: any = await this.pool.execute('SELECT * FROM health_checks ORDER BY checked_at DESC LIMIT 1');
    const now = new Date();

    if (rows.length > 0) {
      return {
        status: rows[0].status,
        components: typeof rows[0].components === 'string' ? JSON.parse(rows[0].components) : {},
        lastChecked: new Date(rows[0].checked_at),
        uptime: rows[0].uptime || 0,
        version: rows[0].version || '1.0.0'
      };
    }

    return { status: 'healthy', components: {}, lastChecked: now, uptime: 0, version: '1.0.0' };
  }

  async checkComponentHealth(component: string): Promise<{ component: string; status: string; latency: number }> {
    const start = Date.now();
    let status = 'healthy';
    let latency = 0;

    try {
      const [checkRows]: any = await this.pool.execute('SELECT 1');
      latency = Date.now() - start;
      if (latency > 500) status = 'degraded';
    } catch {
      status = 'unhealthy';
      latency = Date.now() - start;
    }

    return { component, status, latency };
  }

  async createIncident(input: { title: string; description: string; severity: 'low' | 'medium' | 'high' | 'critical'; components: string[]; createdBy: string }): Promise<ResilienceIncident> {
    const id = ulid();
    const now = new Date();

    await this.pool.execute(
      `INSERT INTO resilience_incidents (id, title, description, severity, status, components, started_at, created_by) VALUES (?, ?, ?, ?, 'open', ?, ?, ?)`,
      [id, input.title, input.description, input.severity, JSON.stringify(input.components), now, input.createdBy]
    );

    return this.getIncidentById(id);
  }

  async getIncidentById(id: string): Promise<ResilienceIncident> {
    const [rows]: any = await this.pool.execute('SELECT * FROM resilience_incidents WHERE id = ?', [id]);
    if (rows.length === 0) throw new NotFoundException('Incident not found');
    return this.mapIncidentRow(rows[0]);
  }

  async listIncidents(options: { status?: string; severity?: string; limit?: number; offset?: number } = {}): Promise<{ incidents: ResilienceIncident[]; total: number }> {
    const { status, severity, limit = 50, offset = 0 } = options;
    let where = '1=1';
    const params: any[] = [];

    if (status) { where += ' AND status = ?'; params.push(status); }
    if (severity) { where += ' AND severity = ?'; params.push(severity); }

    const [count]: any = await this.pool.execute(`SELECT COUNT(*) as total FROM resilience_incidents WHERE ${where}`, params);
    const [rows]: any = await this.pool.execute(
      `SELECT * FROM resilience_incidents WHERE ${where} ORDER BY started_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    return { incidents: rows.map((r: any) => this.mapIncidentRow(r)), total: count[0].total };
  }

  async updateIncidentStatus(id: string, status: string, message: string): Promise<ResilienceIncident> {
    const incident = await this.getIncidentById(id);
    const now = new Date();

    const updates = typeof incident.updates === 'string' ? JSON.parse(incident.updates) : incident.updates;
    updates.push({ status, message, timestamp: now });

    const resolvedAt = status === 'resolved' ? now : null;
    await this.pool.execute(
      `UPDATE resilience_incidents SET status = ?, updates = ?, resolved_at = ? WHERE id = ?`,
      [status, JSON.stringify(updates), resolvedAt, id]
    );

    return this.getIncidentById(id);
  }

  async listCircuitBreakers(): Promise<CircuitBreaker[]> {
    const [rows]: any = await this.pool.execute('SELECT * FROM circuit_breakers ORDER BY service');
    return rows.map((r: any) => this.mapCircuitBreakerRow(r));
  }

  async getCircuitBreaker(service: string): Promise<CircuitBreaker | null> {
    const [rows]: any = await this.pool.execute('SELECT * FROM circuit_breakers WHERE service = ?', [service]);
    return rows.length > 0 ? this.mapCircuitBreakerRow(rows[0]) : null;
  }

  async updateCircuitBreakerState(service: string, state: 'closed' | 'open' | 'half_open', failureCount?: number): Promise<CircuitBreaker> {
    const now = new Date();
    const existing = await this.getCircuitBreaker(service);

    if (!existing) {
      const id = ulid();
      await this.pool.execute(
        `INSERT INTO circuit_breakers (id, service, state, failure_count, last_failure_at, threshold, timeout, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 5, 30, ?, ?)`,
        [id, service, state, failureCount || 0, state === 'open' ? now : null, now, now]
      );
    } else {
      await this.pool.execute(
        `UPDATE circuit_breakers SET state = ?, failure_count = ?, last_failure_at = ?, updated_at = ? WHERE service = ?`,
        [state, failureCount || existing.failureCount, state === 'open' ? now : existing.lastFailureAt, now, service]
      );
    }

    return (await this.getCircuitBreaker(service))!;
  }

  async runChaosExperiment(input: { name: string; description: string; type: string; targetServices: string[]; parameters: Record<string, any>; createdBy: string }): Promise<ChaosExperiment> {
    const id = ulid();
    const now = new Date();

    await this.pool.execute(
      `INSERT INTO chaos_experiments (id, name, description, type, status, target_services, parameters, created_by, started_at) VALUES (?, ?, ?, ?, 'running', ?, ?, ?, ?)`,
      [id, input.name, input.description, input.type, JSON.stringify(input.targetServices), JSON.stringify(input.parameters), input.createdBy, now]
    );

    return this.getChaosExperimentById(id);
  }

  async getChaosExperimentById(id: string): Promise<ChaosExperiment> {
    const [rows]: any = await this.pool.execute('SELECT * FROM chaos_experiments WHERE id = ?', [id]);
    if (rows.length === 0) throw new NotFoundException('Experiment not found');
    return this.mapChaosRow(rows[0]);
  }

  async listChaosExperiments(options: { status?: string; limit?: number; offset?: number } = {}): Promise<{ experiments: ChaosExperiment[]; total: number }> {
    const { status, limit = 50, offset = 0 } = options;
    let where = '1=1';
    const params: any[] = [];

    if (status) { where += ' AND status = ?'; params.push(status); }

    const [count]: any = await this.pool.execute(`SELECT COUNT(*) as total FROM chaos_experiments WHERE ${where}`, params);
    const [rows]: any = await this.pool.execute(
      `SELECT * FROM chaos_experiments WHERE ${where} ORDER BY started_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    return { experiments: rows.map((r: any) => this.mapChaosRow(r)), total: count[0].total };
  }

  async completeChaosExperiment(id: string, status: 'completed' | 'failed'): Promise<ChaosExperiment> {
    const now = new Date();
    await this.pool.execute(
      `UPDATE chaos_experiments SET status = ?, completed_at = ? WHERE id = ?`,
      [status, now, id]
    );
    return this.getChaosExperimentById(id);
  }

  private mapIncidentRow(r: any): ResilienceIncident {
    return {
      id: r.id, title: r.title, description: r.description, severity: r.severity,
      status: r.status, components: typeof r.components === 'string' ? JSON.parse(r.components) : [],
      startedAt: new Date(r.started_at), resolvedAt: r.resolved_at ? new Date(r.resolved_at) : null,
      updates: typeof r.updates === 'string' ? JSON.parse(r.updates) : []
    };
  }

  private mapCircuitBreakerRow(r: any): CircuitBreaker {
    return {
      id: r.id, service: r.service, state: r.state, failureCount: r.failure_count,
      lastFailureAt: r.last_failure_at ? new Date(r.last_failure_at) : null,
      threshold: r.threshold, timeout: r.timeout,
      createdAt: new Date(r.created_at), updatedAt: new Date(r.updated_at)
    };
  }

  private mapChaosRow(r: any): ChaosExperiment {
    return {
      id: r.id, name: r.name, description: r.description, type: r.type, status: r.status,
      targetServices: typeof r.target_services === 'string' ? JSON.parse(r.target_services) : [],
      parameters: typeof r.parameters === 'string' ? JSON.parse(r.parameters) : {},
      startedAt: r.started_at ? new Date(r.started_at) : null,
      completedAt: r.completed_at ? new Date(r.completed_at) : null, createdBy: r.created_by
    };
  }
}