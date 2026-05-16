import { Injectable, Logger } from '@nestjs/common';
import { EmailException, EmailErrorCode, RecoveryAction, RecoveryStrategy, RECOVERY_STRATEGIES } from './email-exception';

export interface EmailContext {
  tenantId: string;
  lineageId: string;
  provider?: string;
  recipient?: string;
  templateKey?: string;
  attempt: number;
}

export interface HandleResult {
  action: RecoveryAction;
  retry: boolean;
  backoffMs?: number;
  newProvider?: string;
  alert?: boolean;
  drop?: boolean;
}

@Injectable()
export class EmailErrorHandler {
  private readonly logger = new Logger(EmailErrorHandler.name);

  async handle(error: Error, context: EmailContext): Promise<HandleResult> {
    const emailError = this.normalizeError(error);
    const strategy = RECOVERY_STRATEGIES[emailError.code];

    if (!strategy) {
      this.logger.warn(
        { code: emailError.code, message: emailError.message, context },
        'Unknown error code, defaulting to RETRY'
      );
      return { action: RecoveryAction.RETRY, retry: true };
    }

    this.logger.debug(
      {
        code: emailError.code,
        action: strategy.action,
        context,
      },
      'Handling email error'
    );

    // Handle action-specific logic
    switch (strategy.action) {
      case RecoveryAction.SWITCH_PROVIDER:
        return this.handleSwitchProvider(emailError, context, strategy);

      case RecoveryAction.RETRY:
        return this.handleRetry(strategy);

      case RecoveryAction.RETRY_WITH_BACKOFF:
        return this.handleRetryWithBackoff(strategy, context);

      case RecoveryAction.ALERT:
        return this.handleAlert(emailError, context);

      case RecoveryAction.DROP:
        return this.handleDrop(emailError, context);

      default:
        return { action: RecoveryAction.RETRY, retry: true };
    }
  }

  private normalizeError(error: Error): EmailException {
    if (error instanceof EmailException) {
      return error;
    }

    // Convert standard errors to EmailException
    const message = error.message.toLowerCase();

    if (message.includes('timeout') || message.includes('etimedout')) {
      return new EmailException(
        EmailErrorCode.PROVIDER_TIMEOUT,
        error.message,
        undefined,
        undefined,
        true
      );
    }

    if (message.includes('rate limit') || message.includes('429')) {
      return new EmailException(
        EmailErrorCode.PROVIDER_RATE_LIMIT,
        error.message,
        undefined,
        undefined,
        true
      );
    }

    if (message.includes('auth') || message.includes('unauthorized') || message.includes('401')) {
      return new EmailException(
        EmailErrorCode.PROVIDER_AUTH_FAILED,
        error.message,
        undefined,
        undefined,
        false
      );
    }

    if (message.includes('circuit') || message.includes('open')) {
      return new EmailException(
        EmailErrorCode.PROVIDER_CIRCUIT_OPEN,
        error.message,
        undefined,
        undefined,
        true
      );
    }

    // Default to unknown but retryable
    return new EmailException(
      EmailErrorCode.UNKNOWN,
      error.message,
      undefined,
      undefined,
      true
    );
  }

  private handleSwitchProvider(
    error: EmailException,
    context: EmailContext,
    strategy: RecoveryStrategy
  ): HandleResult {
    const remainingRetries = (strategy.maxRetries ?? 0) - context.attempt;

    if (remainingRetries > 0) {
      return {
        action: RecoveryAction.SWITCH_PROVIDER,
        retry: true,
        newProvider: undefined, // Caller will fetch next available provider
      };
    }

    // No more retries - alert and drop
    return {
      action: RecoveryAction.ALERT,
      retry: false,
      alert: true,
    };
  }

  private handleRetry(strategy: RecoveryStrategy): HandleResult {
    const maxRetries = strategy.maxRetries ?? 1;
    return {
      action: RecoveryAction.RETRY,
      retry: maxRetries > 0,
    };
  }

  private handleRetryWithBackoff(
    strategy: RecoveryStrategy,
    context: EmailContext
  ): HandleResult {
    const baseBackoff = strategy.backoffMs ?? 1000;
    const attempt = context.attempt;

    // Exponential backoff: base * 2^attempt
    const exponential = baseBackoff * Math.pow(2, attempt);
    // Add jitter: ±30%
    const jitter = (Math.random() * 0.6 + 0.7);
    const backoffMs = Math.round(exponential * jitter);

    const maxRetries = strategy.maxRetries ?? 3;
    const canRetry = attempt < maxRetries;

    return {
      action: RecoveryAction.RETRY_WITH_BACKOFF,
      retry: canRetry,
      backoffMs,
    };
  }

  private handleAlert(error: EmailException, context: EmailContext): HandleResult {
    this.logger.error(
      {
        error: error.toJSON(),
        context,
      },
      'Non-recoverable email error - alerting'
    );

    return {
      action: RecoveryAction.ALERT,
      retry: false,
      alert: true,
    };
  }

  private handleDrop(error: EmailException, context: EmailContext): HandleResult {
    this.logger.warn(
      {
        error: error.toJSON(),
        context,
      },
      'Email dropped due to permanent failure'
    );

    return {
      action: RecoveryAction.DROP,
      retry: false,
      drop: true,
    };
  }

  isRetryable(error: Error): boolean {
    if (error instanceof EmailException) {
      return error.retryable;
    }

    const message = error.message.toLowerCase();
    return (
      message.includes('timeout') ||
      message.includes('rate limit') ||
      message.includes('429') ||
      message.includes('circuit')
    );
  }

  getRecoveryStrategy(code: EmailErrorCode): RecoveryStrategy | undefined {
    return RECOVERY_STRATEGIES[code];
  }
}