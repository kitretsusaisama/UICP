export interface ApiMetricEntry {
  tenantId: string;
  userId?: string;
  principalId?: string;
  method: string;
  path: string;
  pathTemplate?: string;
  statusCode: number;
  latencyMs: number;
  dbQueryCount: number;
  dbQueryTimeMs: number;
  cacheHit: boolean;
  externalApiCalls: number;
  externalApiTimeMs: number;
  requestSizeBytes?: number;
  responseSizeBytes?: number;
  userAgent?: string;
  ipHash?: string;
  correlationId?: string;
  errorType?: string;
  errorMessage?: string;
  createdAt: Date;
}

export interface IApiMetricsPort {
  record(entry: Omit<ApiMetricEntry, 'createdAt'>): Promise<void>;
  recordBatch(entries: Omit<ApiMetricEntry, 'createdAt'>[]): Promise<void>;
  getStats(tenantId: string, pathTemplate: string, from: Date, to: Date): Promise<{
    count: number;
    avgLatencyMs: number;
    p50LatencyMs: number;
    p95LatencyMs: number;
    p99LatencyMs: number;
    errorRate: number;
  }>;
}