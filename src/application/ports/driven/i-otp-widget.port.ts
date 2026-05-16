/**
 * Driven port - OTP Widget Configuration Repository
 * Manages tenant-specific OTP widget configurations with isolation
 */

export interface TenantOtpWidgetConfig {
  id: string;
  tenantId: string;
  providerName: string;
  widgetId: string;
  tokenAuthEncrypted: string;
  themeConfig: Record<string, unknown>;
  layoutConfig: Record<string, unknown>;
  behaviorConfig: Record<string, unknown>;
  localization: Record<string, unknown>;
  allowedOrigins: string[];
  allowedChannels: string[];
  ipWhitelist: string[] | null;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface ITenantOtpWidgetRepository {
  findByTenantId(tenantId: string): Promise<TenantOtpWidgetConfig | null>;
  create(config: Omit<TenantOtpWidgetConfig, 'id' | 'createdAt' | 'updatedAt'>): Promise<TenantOtpWidgetConfig>;
  update(tenantId: string, config: Partial<TenantOtpWidgetConfig>): Promise<TenantOtpWidgetConfig>;
  delete(tenantId: string): Promise<void>;
}