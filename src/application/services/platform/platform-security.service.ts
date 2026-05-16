import { Injectable, NotFoundException, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { ulid } from 'ulid';

export interface SecurityIncident {
  id: string; tenantId: string | null; severity: 'low' | 'medium' | 'high' | 'critical';
  type: string; title: string; description: string; status: 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';
  source: string; ipAddress: string | null; userAgent: string | null;
  affectedResources: string[]; indicators: Record<string, any>; mitigation: string | null;
  createdAt: Date; updatedAt: Date; resolvedAt: Date | null; resolvedBy: string | null;
}

export interface ThreatIntelligence {
  id: string; indicator: string; type: 'ip' | 'domain' | 'hash' | 'url';
  threatLevel: 'low' | 'medium' | 'high' | 'critical'; source: string;
  description: string; firstSeen: Date; lastSeen: Date; tags: string[];
  metadata: Record<string, any>;
}

export interface CreateIncidentInput {
  tenantId?: string; severity: 'low' | 'medium' | 'high' | 'critical';
  type: string; title: string; description: string; source: string;
  ipAddress?: string; userAgent?: string; affectedResources?: string[];
  indicators?: Record<string, any>;
}

export interface CreateThreatInput {
  indicator: string; type: 'ip' | 'domain' | 'hash' | 'url';
  threatLevel: 'low' | 'medium' | 'high' | 'critical'; source: string;
  description: string; tags?: string[]; metadata?: Record<string, any>;
}

@Injectable()
export class PlatformSecurityService {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async createIncident(input: CreateIncidentInput): Promise<SecurityIncident> {
    const id = ulid();
    const now = new Date();

    await this.pool.execute(
      `INSERT INTO security_incidents (id, tenant_id, severity, type, title, description, status, source, ip_address, user_agent, affected_resources, indicators, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, input.tenantId || null, input.severity, input.type, input.title, input.description, 'open', input.source, input.ipAddress || null, input.userAgent || null, JSON.stringify(input.affectedResources || []), JSON.stringify(input.indicators || {}), now, now]
    );

    if (input.severity === 'critical' || input.severity === 'high') {
      await this.triggerSecurityAlert(id, input);
    }

    return this.getIncidentById(id);
  }

  async updateIncidentStatus(id: string, status: string, mitigation?: string, resolvedBy?: string): Promise<SecurityIncident> {
    const incident = await this.getIncidentById(id);
    const now = new Date();

    await this.pool.execute(
      `UPDATE security_incidents SET status = ?, mitigation = ?, updated_at = ?, resolved_at = ?, resolved_by = ? WHERE id = ?`,
      [status, mitigation || incident.mitigation, now, status === 'resolved' || status === 'closed' ? now : null, resolvedBy || null, id]
    );

    await this.logAudit('incident_updated', { incidentId: id, status, mitigation });
    return this.getIncidentById(id);
  }

  async getIncidentById(id: string): Promise<SecurityIncident> {
    const [rows]: any = await this.pool.execute('SELECT * FROM security_incidents WHERE id = ?', [id]);
    if (rows.length === 0) throw new NotFoundException('Incident not found');
    return this.mapIncidentRow(rows[0]);
  }

  async listIncidents(options: { tenantId?: string; status?: string; severity?: string; limit?: number; offset?: number } = {}): Promise<{ incidents: SecurityIncident[]; total: number }> {
    const { tenantId, status, severity, limit = 50, offset = 0 } = options;
    let where = '1=1';
    const params: any[] = [];

    if (tenantId) { where += ' AND tenant_id = ?'; params.push(tenantId); }
    if (status) { where += ' AND status = ?'; params.push(status); }
    if (severity) { where += ' AND severity = ?'; params.push(severity); }

    const [count]: any = await this.pool.execute(`SELECT COUNT(*) as total FROM security_incidents WHERE ${where}`, params);
    const [rows]: any = await this.pool.execute(
      `SELECT * FROM security_incidents WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    return { incidents: rows.map((r: any) => this.mapIncidentRow(r)), total: count[0].total };
  }

  async addThreatIndicator(input: CreateThreatInput): Promise<ThreatIntelligence> {
    const id = ulid();
    const now = new Date();

    const existing: any = await this.pool.execute('SELECT id FROM threat_intelligence WHERE indicator = ? AND type = ?', [input.indicator, input.type]);
    if (existing[0].length > 0) {
      await this.pool.execute(
        `UPDATE threat_intelligence SET threat_level = ?, last_seen = ?, metadata = JSON_MERGE_PATCH(COALESCE(metadata, '{}'), ?) WHERE id = ?`,
        [input.threatLevel, now, JSON.stringify(input.metadata || {}), existing[0][0].id]
      );
      return this.getThreatById(existing[0][0].id);
    }

    await this.pool.execute(
      `INSERT INTO threat_intelligence (id, indicator, type, threat_level, source, description, first_seen, last_seen, tags, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, input.indicator, input.type, input.threatLevel, input.source, input.description, now, now, JSON.stringify(input.tags || []), JSON.stringify(input.metadata || {})]
    );

    return this.getThreatById(id);
  }

  async getThreatById(id: string): Promise<ThreatIntelligence> {
    const [rows]: any = await this.pool.execute('SELECT * FROM threat_intelligence WHERE id = ?', [id]);
    if (rows.length === 0) throw new NotFoundException('Threat indicator not found');
    return this.mapThreatRow(rows[0]);
  }

  async checkThreat(indicator: string, type: string): Promise<ThreatIntelligence | null> {
    const [rows]: any = await this.pool.execute('SELECT * FROM threat_intelligence WHERE indicator = ? AND type = ?', [indicator, type]);
    return rows.length > 0 ? this.mapThreatRow(rows[0]) : null;
  }

  async listThreats(options: { type?: string; threatLevel?: string; tags?: string; limit?: number; offset?: number } = {}): Promise<{ threats: ThreatIntelligence[]; total: number }> {
    const { type, threatLevel, tags, limit = 50, offset = 0 } = options;
    let where = '1=1';
    const params: any[] = [];

    if (type) { where += ' AND type = ?'; params.push(type); }
    if (threatLevel) { where += ' AND threat_level = ?'; params.push(threatLevel); }
    if (tags) { where += ' AND JSON_CONTAINS(tags, ?)'; params.push(JSON.stringify(tags)); }

    const [count]: any = await this.pool.execute(`SELECT COUNT(*) as total FROM threat_intelligence WHERE ${where}`, params);
    const [rows]: any = await this.pool.execute(
      `SELECT * FROM threat_intelligence WHERE ${where} ORDER BY threat_level DESC, last_seen DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    return { threats: rows.map((r: any) => this.mapThreatRow(r)), total: count[0].total };
  }

  async runVulnerabilityScan(tenantId: string): Promise<{ scanId: string; status: string }> {
    const scanId = ulid();
    await this.pool.execute(
      `INSERT INTO vulnerability_scans (id, tenant_id, status, started_at) VALUES (?, ?, 'running', NOW())`,
      [scanId, tenantId]
    );
    return { scanId, status: 'running' };
  }

  async getVulnerabilityScanResults(scanId: string): Promise<any> {
    const [rows]: any = await this.pool.execute('SELECT * FROM vulnerability_scans WHERE id = ?', [scanId]);
    if (rows.length === 0) throw new NotFoundException('Scan not found');
    return { scanId: rows[0].id, status: rows[0].status, results: rows[0].results ? JSON.parse(rows[0].results) : [] };
  }

  async analyzeRisk(tenantId: string): Promise<{ analysisId: string; riskScore: number; factors: any }> {
    const analysisId = ulid();
    const incidents = await this.listIncidents({ tenantId, severity: 'critical', limit: 100 });
    const threats = await this.listThreats({ threatLevel: 'critical', limit: 100 });

    let riskScore = 0;
    const factors: any = { criticalIncidents: incidents.total, criticalThreats: threats.total };

    if (incidents.total > 0) riskScore += 30;
    if (threats.total > 0) riskScore += 40;
    riskScore = Math.min(riskScore, 100);

    await this.logAudit('risk_analysis_completed', { analysisId, tenantId, riskScore });
    return { analysisId, riskScore, factors };
  }

  async getAnomalies(tenantId: string): Promise<any[]> {
    const [rows]: any = await this.pool.execute(
      `SELECT * FROM security_anomalies WHERE tenant_id = ? AND detected_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) ORDER BY detected_at DESC`,
      [tenantId]
    );
    return rows;
  }

  private async triggerSecurityAlert(incidentId: string, input: CreateIncidentInput): Promise<void> {
    await this.logAudit('security_alert_triggered', { incidentId, severity: input.severity, type: input.type });
  }

  private async logAudit(action: string, metadata: Record<string, any>): Promise<void> {
    await this.pool.execute(
      `INSERT INTO platform_audit_logs (id, action, resource_type, resource_id, metadata, created_at) VALUES (?, ?, ?, ?, ?, NOW())`,
      [ulid(), action, 'security', 'platform', JSON.stringify(metadata)]
    );
  }

  private mapIncidentRow(r: any): SecurityIncident {
    return {
      id: r.id, tenantId: r.tenant_id, severity: r.severity, type: r.type, title: r.title,
      description: r.description, status: r.status, source: r.source, ipAddress: r.ip_address,
      userAgent: r.user_agent, affectedResources: typeof r.affected_resources === 'string' ? JSON.parse(r.affected_resources) : [],
      indicators: typeof r.indicators === 'string' ? JSON.parse(r.indicators) : {},
      mitigation: r.mitigation, createdAt: new Date(r.created_at), updatedAt: new Date(r.updated_at),
      resolvedAt: r.resolved_at ? new Date(r.resolved_at) : null, resolvedBy: r.resolved_by
    };
  }

  private mapThreatRow(r: any): ThreatIntelligence {
    return {
      id: r.id, indicator: r.indicator, type: r.type, threatLevel: r.threat_level,
      source: r.source, description: r.description, firstSeen: new Date(r.first_seen),
      lastSeen: new Date(r.last_seen), tags: typeof r.tags === 'string' ? JSON.parse(r.tags) : [],
      metadata: typeof r.metadata === 'string' ? JSON.parse(r.metadata) : {}
    };
  }
}