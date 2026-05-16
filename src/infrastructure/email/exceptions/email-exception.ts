export enum EmailErrorCode {
  // Provider errors - recoverable
  PROVIDER_TIMEOUT = 'PROVIDER_TIMEOUT',
  PROVIDER_RATE_LIMIT = 'PROVIDER_RATE_LIMIT',
  PROVIDER_CIRCUIT_OPEN = 'PROVIDER_CIRCUIT_OPEN',
  PROVIDER_AUTH_FAILED = 'PROVIDER_AUTH_FAILED',
  PROVIDER_RESPONSE_ERROR = 'PROVIDER_RESPONSE_ERROR',

  // Provider errors - non-recoverable
  PROVIDER_INVALID_CREDENTIALS = 'PROVIDER_INVALID_CREDENTIALS',
  PROVIDER_DAILY_LIMIT = 'PROVIDER_DAILY_LIMIT',
  PROVIDER_SPF_DKIM_FAILED = 'PROVIDER_SPF_DKIM_FAILED',

  // Tenant errors
  TENANT_NOT_FOUND = 'TENANT_NOT_FOUND',
  TENANT_NO_PROVIDERS = 'TENANT_NO_PROVIDERS',
  TENANT_SENDER_INVALID = 'TENANT_SENDER_INVALID',

  // Delivery errors
  DELIVERY_BOUNCED = 'DELIVERY_BOUNCED',
  DELIVERY_SPAM = 'DELIVERY_SPAM',
  DELIVERY_INVALID_RECIPIENT = 'DELIVERY_INVALID_RECIPIENT',

  // Queue errors
  QUEUE_FULL = 'QUEUE_FULL',
  QUEUE_MAX_RETRIES = 'QUEUE_MAX_RETRIES',

  // Template errors
  TEMPLATE_NOT_FOUND = 'TEMPLATE_NOT_FOUND',
  TEMPLATE_RENDER_ERROR = 'TEMPLATE_RENDER_ERROR',

  // General errors
  UNKNOWN = 'UNKNOWN',
  VALIDATION_ERROR = 'VALIDATION_ERROR',
}

export enum RecoveryAction {
  RETRY = 'RETRY',
  RETRY_WITH_BACKOFF = 'RETRY_WITH_BACKOFF',
  SWITCH_PROVIDER = 'SWITCH_PROVIDER',
  ALERT = 'ALERT',
  DROP = 'DROP',
}

export interface RecoveryStrategy {
  action: RecoveryAction;
  maxRetries?: number;
  backoffMs?: number;
  nextErrorCode?: EmailErrorCode;
}

export const RECOVERY_STRATEGIES: Record<EmailErrorCode, RecoveryStrategy> = {
  [EmailErrorCode.PROVIDER_TIMEOUT]: {
    action: RecoveryAction.RETRY_WITH_BACKOFF,
    maxRetries: 3,
    backoffMs: 5000,
  },
  [EmailErrorCode.PROVIDER_RATE_LIMIT]: {
    action: RecoveryAction.RETRY_WITH_BACKOFF,
    maxRetries: 3,
    backoffMs: 60000,
  },
  [EmailErrorCode.PROVIDER_CIRCUIT_OPEN]: {
    action: RecoveryAction.SWITCH_PROVIDER,
    maxRetries: 2,
  },
  [EmailErrorCode.PROVIDER_AUTH_FAILED]: {
    action: RecoveryAction.ALERT,
    maxRetries: 0,
  },
  [EmailErrorCode.PROVIDER_RESPONSE_ERROR]: {
    action: RecoveryAction.RETRY_WITH_BACKOFF,
    maxRetries: 2,
    backoffMs: 3000,
  },
  [EmailErrorCode.PROVIDER_INVALID_CREDENTIALS]: {
    action: RecoveryAction.ALERT,
    maxRetries: 0,
  },
  [EmailErrorCode.PROVIDER_DAILY_LIMIT]: {
    action: RecoveryAction.SWITCH_PROVIDER,
    maxRetries: 1,
  },
  [EmailErrorCode.PROVIDER_SPF_DKIM_FAILED]: {
    action: RecoveryAction.ALERT,
    maxRetries: 0,
  },
  [EmailErrorCode.TENANT_NOT_FOUND]: {
    action: RecoveryAction.ALERT,
    maxRetries: 0,
  },
  [EmailErrorCode.TENANT_NO_PROVIDERS]: {
    action: RecoveryAction.ALERT,
    maxRetries: 0,
  },
  [EmailErrorCode.TENANT_SENDER_INVALID]: {
    action: RecoveryAction.ALERT,
    maxRetries: 0,
  },
  [EmailErrorCode.DELIVERY_BOUNCED]: {
    action: RecoveryAction.DROP,
    maxRetries: 0,
  },
  [EmailErrorCode.DELIVERY_SPAM]: {
    action: RecoveryAction.DROP,
    maxRetries: 0,
  },
  [EmailErrorCode.DELIVERY_INVALID_RECIPIENT]: {
    action: RecoveryAction.DROP,
    maxRetries: 0,
  },
  [EmailErrorCode.QUEUE_FULL]: {
    action: RecoveryAction.RETRY_WITH_BACKOFF,
    maxRetries: 2,
    backoffMs: 10000,
  },
  [EmailErrorCode.QUEUE_MAX_RETRIES]: {
    action: RecoveryAction.ALERT,
    maxRetries: 0,
  },
  [EmailErrorCode.TEMPLATE_NOT_FOUND]: {
    action: RecoveryAction.ALERT,
    maxRetries: 0,
  },
  [EmailErrorCode.TEMPLATE_RENDER_ERROR]: {
    action: RecoveryAction.RETRY,
    maxRetries: 1,
  },
  [EmailErrorCode.UNKNOWN]: {
    action: RecoveryAction.RETRY,
    maxRetries: 1,
  },
  [EmailErrorCode.VALIDATION_ERROR]: {
    action: RecoveryAction.ALERT,
    maxRetries: 0,
  },
};

export class EmailException extends Error {
  constructor(
    public readonly code: EmailErrorCode,
    public readonly message: string,
    public readonly provider?: string,
    public readonly tenantId?: string,
    public readonly retryable: boolean = false,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'EmailException';

    // Maintains proper stack trace for where error was thrown
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, EmailException);
    }
  }

  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      provider: this.provider,
      tenantId: this.tenantId,
      retryable: this.retryable,
      details: this.details,
      stack: this.stack,
    };
  }
}

export class ProviderTimeoutError extends EmailException {
  constructor(provider: string, tenantId: string, timeoutMs: number) {
    super(
      EmailErrorCode.PROVIDER_TIMEOUT,
      `Provider ${provider} timed out after ${timeoutMs}ms`,
      provider,
      tenantId,
      true,
      { timeoutMs }
    );
    this.name = 'ProviderTimeoutError';
  }
}

export class ProviderRateLimitError extends EmailException {
  constructor(provider: string, tenantId: string, retryAfterMs?: number) {
    super(
      EmailErrorCode.PROVIDER_RATE_LIMIT,
      `Provider ${provider} rate limit exceeded`,
      provider,
      tenantId,
      true,
      { retryAfterMs }
    );
    this.name = 'ProviderRateLimitError';
  }
}

export class ProviderCircuitOpenError extends EmailException {
  constructor(provider: string, tenantId: string) {
    super(
      EmailErrorCode.PROVIDER_CIRCUIT_OPEN,
      `Provider ${provider} circuit breaker is OPEN`,
      provider,
      tenantId,
      true,
      {}
    );
    this.name = 'ProviderCircuitOpenError';
  }
}

export class ProviderAuthError extends EmailException {
  constructor(provider: string, tenantId: string, reason?: string) {
    super(
      EmailErrorCode.PROVIDER_AUTH_FAILED,
      `Provider ${provider} authentication failed: ${reason ?? 'Unknown reason'}`,
      provider,
      tenantId,
      false,
      { reason }
    );
    this.name = 'ProviderAuthError';
  }
}

export class TenantNotFoundError extends EmailException {
  constructor(tenantId: string) {
    super(
      EmailErrorCode.TENANT_NOT_FOUND,
      `Tenant ${tenantId} not found`,
      undefined,
      tenantId,
      false,
      {}
    );
    this.name = 'TenantNotFoundError';
  }
}

export class TenantNoProvidersError extends EmailException {
  constructor(tenantId: string) {
    super(
      EmailErrorCode.TENANT_NO_PROVIDERS,
      `No email providers configured for tenant ${tenantId}`,
      undefined,
      tenantId,
      false,
      {}
    );
    this.name = 'TenantNoProvidersError';
  }
}

export class TemplateNotFoundError extends EmailException {
  constructor(templateKey: string, tenantId: string) {
    super(
      EmailErrorCode.TEMPLATE_NOT_FOUND,
      `Template ${templateKey} not found for tenant ${tenantId}`,
      undefined,
      tenantId,
      false,
      { templateKey }
    );
    this.name = 'TemplateNotFoundError';
  }
}

export class DeliveryBouncedError extends EmailException {
  constructor(recipient: string, tenantId: string, bounceType?: string) {
    super(
      EmailErrorCode.DELIVERY_BOUNCED,
      `Email bounced for recipient ${recipient}`,
      undefined,
      tenantId,
      false,
      { recipient, bounceType }
    );
    this.name = 'DeliveryBouncedError';
  }
}

export class QueueMaxRetriesError extends EmailException {
  constructor(tenantId: string, lineageId: string, maxRetries: number) {
    super(
      EmailErrorCode.QUEUE_MAX_RETRIES,
      `Email ${lineageId} exceeded maximum retries (${maxRetries})`,
      undefined,
      tenantId,
      false,
      { lineageId, maxRetries }
    );
    this.name = 'QueueMaxRetriesError';
  }
}