export interface PageDefinition {
  path: string;
  title: string;
  module: string;
  description: string;
  widgets: string[];
}

const paths = [
  '/auth/login','/auth/register','/auth/verify-otp','/auth/mfa','/auth/magic-link','/auth/device-verification','/auth/suspicious-login','/auth/session-expired','/auth/account-locked','/auth/oauth/callback','/auth/sso','/auth/consent',
  '/dashboard/overview','/dashboard/realtime','/dashboard/activity','/dashboard/incidents','/dashboard/system-health','/dashboard/quick-actions',
  '/tenants/list','/tenants/create','/tenants/details/[tenantId]','/tenants/branding','/tenants/domains','/tenants/providers','/tenants/communication','/tenants/security','/tenants/policies','/tenants/queues','/tenants/webhooks','/tenants/environments','/tenants/audit',
  '/providers/sms','/providers/sms/msg91','/providers/sms/twilio','/providers/email','/providers/email/resend','/providers/email/maileroo','/providers/whatsapp','/providers/health','/providers/fallback','/providers/retries','/providers/templates','/providers/regions','/providers/diagnostics','/providers/api-keys','/providers/webhooks',
  '/communication/sms','/communication/emails','/communication/whatsapp','/communication/templates','/communication/delivery','/communication/tracking','/communication/logs','/communication/sender-ids','/communication/domains','/communication/fallback',
  '/sessions/active','/sessions/revoked','/sessions/expired','/sessions/devices','/sessions/replay','/sessions/lineage','/sessions/threats','/sessions/investigations','/sessions/forensics',
  '/security/threats','/security/replay','/security/brute-force','/security/incidents','/security/investigations','/security/devices','/security/geo-analysis','/security/risk-engine','/security/anomalies','/security/blocked-ips','/security/forensics',
  '/queues/active','/queues/delayed','/queues/failed','/queues/dead-letter','/queues/retries','/queues/concurrency','/queues/metrics','/queues/diagnostics','/queues/workers','/queues/events',
  '/audit/logs','/audit/auth','/audit/sessions','/audit/providers','/audit/queues','/audit/lineage','/audit/compliance',
  '/developer/api-keys','/developer/sdk','/developer/webhooks','/developer/events','/developer/playground','/developer/schemas','/developer/rate-limits','/developer/logs','/developer/sandbox',
];

export const pages: PageDefinition[] = paths.map((path) => {
  const [module = 'dashboard', leaf = 'overview'] = path.split('/').filter(Boolean);
  return {
    path,
    title: leaf.replace(/\[|\]/g, '').split('-').map((part) => part[0]?.toUpperCase() + part.slice(1)).join(' '),
    module,
    description: `${module} runtime surface for tenant-scoped identity operations.`,
    widgets: ['Live status', 'Lineage', 'Audit trail', 'Policy state'],
  };
});

export function resolvePage(path: string): PageDefinition {
  return pages.find((page) => page.path === path) ?? {
    path,
    title: 'Runtime Surface',
    module: path.split('/').filter(Boolean)[0] ?? 'dashboard',
    description: 'Tenant-scoped operational view.',
    widgets: ['Live status', 'Lineage', 'Audit trail'],
  };
}
