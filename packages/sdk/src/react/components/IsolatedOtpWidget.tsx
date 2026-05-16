import React, { useState, useEffect, useCallback, useMemo } from 'react';

// Types for widget configuration
export interface WidgetTheme {
  primaryColor: string;
  backgroundColor: string;
  fontFamily: string;
  borderRadius: string;
  logoUrl?: string;
}

export interface WidgetLayout {
  showChannelSelector: boolean;
  showTimer: boolean;
  showResendButton: boolean;
  showLogo: boolean;
  channelOrder: string[];
}

export interface WidgetBehavior {
  resendCooldownSeconds: number;
  maxAttempts: number;
  autoRedirectOnVerify: boolean;
  animationEnabled: boolean;
  timeoutSeconds: number;
}

export interface WidgetLocalization {
  [locale: string]: {
    title?: string;
    subtitle?: string;
    buttonText?: string;
    resendText?: string;
    placeholderText?: string;
    successMessage?: string;
  };
}

export interface WidgetConfig {
  widgetId: string;
  tokenAuth: string;
  theme: WidgetTheme;
  layout: WidgetLayout;
  behavior: WidgetBehavior;
  localization: WidgetLocalization;
  channels: string[];
  isolationSignature: string;
}

export interface IsolatedOtpWidgetProps {
  tenantId: string;
  channel?: 'SMS' | 'WHATSAPP' | 'EMAIL';
  purpose?: 'IDENTITY_VERIFICATION' | 'MFA' | 'PASSWORD_RESET';
  onSuccess?: (result: { verified: boolean; identity?: string; sessionToken?: string }) => void;
  onError?: (error: { code: string; message: string }) => void;
  onChannelChange?: (channel: string) => void;
  locale?: string;
  className?: string;
}

// Default English translations
const defaultTranslations = {
  title: 'Verify your phone number',
  subtitle: 'Enter the code sent to your device',
  buttonText: 'Send Code',
  resendText: 'Resend Code',
  placeholderText: 'Enter 6-digit code',
  verifyingText: 'Verifying...',
  successMessage: 'Verification successful!',
  selectChannelText: 'Preferred channel:',
};

export function IsolatedOtpWidget({
  tenantId,
  channel = 'SMS',
  purpose = 'IDENTITY_VERIFICATION',
  onSuccess,
  onError,
  onChannelChange,
  locale = 'en',
  className = '',
}: IsolatedOtpWidgetProps) {
  const [config, setConfig] = useState<WidgetConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [step, setStep] = useState<'input' | 'verify' | 'success'>('input');
  const [selectedChannel, setSelectedChannel] = useState(channel);
  const [phone, setPhone] = useState('');
  const [code, setCode] = useState('');
  const [countdown, setCountdown] = useState(0);
  const [attempts, setAttempts] = useState(0);

  // Load widget configuration on mount
  useEffect(() => {
    async function loadConfig() {
      try {
        setLoading(true);
        // In real implementation, call API to get config
        // const response = await fetch(`/v1/auth/otp/widget/config?tenantId=${tenantId}`);
        // const configData = await response.json();

        // Mock config for now
        const mockConfig: WidgetConfig = {
          widgetId: `widget_${tenantId.slice(0, 8)}`,
          tokenAuth: `token_${tenantId}`,
          theme: {
            primaryColor: '#3B82F6',
            backgroundColor: '#FFFFFF',
            fontFamily: 'Inter, system-ui, sans-serif',
            borderRadius: '8px',
          },
          layout: {
            showChannelSelector: true,
            showTimer: true,
            showResendButton: true,
            showLogo: false,
            channelOrder: ['SMS', 'WHATSAPP', 'EMAIL'],
          },
          behavior: {
            resendCooldownSeconds: 60,
            maxAttempts: 3,
            autoRedirectOnVerify: true,
            animationEnabled: true,
            timeoutSeconds: 120,
          },
          localization: {
            en: defaultTranslations,
          },
          channels: ['SMS', 'WHATSAPP', 'EMAIL'],
          isolationSignature: 'mock-signature',
        };

        setConfig(mockConfig);
      } catch (err) {
        setError('Failed to load widget configuration');
        onError?.({ code: 'CONFIG_ERROR', message: 'Failed to load widget configuration' });
      } finally {
        setLoading(false);
      }
    }

    loadConfig();
  }, [tenantId, onError]);

  // Countdown timer
  useEffect(() => {
    if (countdown > 0) {
      const timer = setTimeout(() => setCountdown(countdown - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [countdown]);

  // Get translations based on locale
  const t = useMemo(() => {
    if (!config?.localization?.[locale]) {
      return defaultTranslations;
    }
    return { ...defaultTranslations, ...config.localization[locale] };
  }, [config, locale]);

  // Apply theme styles
  const style = useMemo(() => {
    if (!config?.theme) return {};
    return {
      '--primary-color': config.theme.primaryColor,
      '--background-color': config.theme.backgroundColor,
      '--font-family': config.theme.fontFamily,
      '--border-radius': config.theme.borderRadius,
    } as React.CSSProperties;
  }, [config]);

  // Handle send OTP
  const handleSendOtp = useCallback(async () => {
    if (!phone || phone.length < 10) {
      setError('Please enter a valid phone number');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      // In real implementation, call API
      // await fetch('/v1/auth/otp/widget/send', {
      //   method: 'POST',
      //   body: JSON.stringify({ tenantId, identity: phone, channel: selectedChannel, purpose })
      // });

      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));

      setStep('verify');
      setCountdown(config?.behavior.resendCooldownSeconds ?? 60);
      onChannelChange?.(selectedChannel);
    } catch (err) {
      setError('Failed to send OTP');
      onError?.({ code: 'SEND_ERROR', message: 'Failed to send OTP' });
    } finally {
      setLoading(false);
    }
  }, [phone, selectedChannel, tenantId, purpose, config, onError, onChannelChange]);

  // Handle verify OTP
  const handleVerify = useCallback(async () => {
    if (!code || code.length !== 6) {
      setError('Please enter a valid 6-digit code');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      // In real implementation, call API with widget token
      // const response = await fetch('/v1/auth/otp/widget/verify', {
      //   method: 'POST',
      //   body: JSON.stringify({ tenantId, providerToken: widgetToken, identity: phone })
      // });

      // Simulate verification
      await new Promise(resolve => setTimeout(resolve, 1500));

      setStep('success');
      setAttempts(prev => prev + 1);

      onSuccess?.({
        verified: true,
        identity: phone,
        sessionToken: 'mock-session-token',
      });
    } catch (err) {
      setError('Invalid OTP code');
      setAttempts(prev => prev + 1);

      if (attempts >= (config?.behavior.maxAttempts ?? 3) - 1) {
        onError?.({ code: 'MAX_ATTEMPTS', message: 'Maximum verification attempts exceeded' });
      } else {
        onError?.({ code: 'INVALID_OTP', message: 'Invalid OTP code' });
      }
    } finally {
      setLoading(false);
    }
  }, [code, phone, tenantId, attempts, config, onSuccess, onError]);

  // Handle resend
  const handleResend = useCallback(async () => {
    if (countdown > 0) return;

    setError(null);
    setCode('');
    setStep('input');
  }, [countdown]);

  // Loading state
  if (loading && !config) {
    return (
      <div className={`otp-widget-loading ${className}`} style={style}>
        <div className="otp-spinner" />
        <p>Loading...</p>
      </div>
    );
  }

  // Success state
  if (step === 'success') {
    return (
      <div className={`otp-widget-success ${className}`} style={style}>
        <div className="otp-success-icon">✓</div>
        <p>{t.successMessage}</p>
      </div>
    );
  }

  return (
    <div className={`otp-widget-container ${className}`} style={style}>
      {/* Header */}
      <div className="otp-header">
        {config?.layout.showLogo && config.theme.logoUrl && (
          <img src={config.theme.logoUrl} alt="Logo" className="otp-logo" />
        )}
        <h2 className="otp-title">{t.title}</h2>
        <p className="otp-subtitle">{t.subtitle}</p>
      </div>

      {/* Error message */}
      {error && <div className="otp-error">{error}</div>}

      {/* Channel selector */}
      {step === 'input' && config?.layout.showChannelSelector && (
        <div className="otp-channel-selector">
          <label>{t.selectChannelText}</label>
          <div className="otp-channels">
            {(config.layout.channelOrder || config.channels).map((ch) => (
              <button
                key={ch}
                className={`otp-channel-btn ${selectedChannel === ch ? 'active' : ''}`}
                onClick={() => setSelectedChannel(ch as typeof selectedChannel)}
                disabled={!config.channels.includes(ch)}
              >
                {ch}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Phone input */}
      {step === 'input' && (
        <div className="otp-input-group">
          <input
            type="tel"
            value={phone}
            onChange={(e) => setPhone(e.target.value)}
            placeholder="+1 234 567 8900"
            className="otp-input"
            disabled={loading}
          />
          <button
            onClick={handleSendOtp}
            disabled={loading || !phone}
            className="otp-submit-btn"
            style={{ backgroundColor: config?.theme.primaryColor }}
          >
            {loading ? 'Sending...' : t.buttonText}
          </button>
        </div>
      )}

      {/* OTP verification */}
      {step === 'verify' && (
        <div className="otp-verify-group">
          <input
            type="text"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            placeholder={t.placeholderText}
            className="otp-input otp-code-input"
            maxLength={6}
            disabled={loading}
          />
          <button
            onClick={handleVerify}
            disabled={loading || code.length !== 6}
            className="otp-submit-btn"
            style={{ backgroundColor: config?.theme.primaryColor }}
          >
            {loading ? t.verifyingText : 'Verify'}
          </button>
        </div>
      )}

      {/* Timer and resend */}
      {step === 'verify' && config?.layout.showTimer && (
        <div className="otp-timer-section">
          {countdown > 0 ? (
            <span className="otp-countdown">Resend available in {countdown}s</span>
          ) : (
            config.layout.showResendButton && (
              <button
                onClick={handleResend}
                className="otp-resend-btn"
                disabled={loading}
              >
                {t.resendText}
              </button>
            )
          )}
        </div>
      )}

      {/* CSS styles */}
      <style>{`
        .otp-widget-container {
          font-family: var(--font-family);
          background: var(--background-color);
          border-radius: var(--border-radius);
          padding: 24px;
          max-width: 400px;
          margin: 0 auto;
        }
        .otp-header {
          text-align: center;
          margin-bottom: 20px;
        }
        .otp-title {
          font-size: 18px;
          font-weight: 600;
          margin: 0 0 8px;
          color: #1a1a1a;
        }
        .otp-subtitle {
          font-size: 14px;
          color: #666;
          margin: 0;
        }
        .otp-error {
          background: #fee2e2;
          color: #dc2626;
          padding: 10px;
          border-radius: 6px;
          margin-bottom: 16px;
          font-size: 14px;
        }
        .otp-channel-selector {
          margin-bottom: 16px;
        }
        .otp-channel-selector label {
          display: block;
          font-size: 14px;
          color: #666;
          margin-bottom: 8px;
        }
        .otp-channels {
          display: flex;
          gap: 8px;
        }
        .otp-channel-btn {
          flex: 1;
          padding: 8px;
          border: 1px solid #ddd;
          border-radius: 6px;
          background: white;
          cursor: pointer;
          font-size: 14px;
          transition: all 0.2s;
        }
        .otp-channel-btn.active {
          border-color: var(--primary-color);
          background: var(--primary-color);
          color: white;
        }
        .otp-input-group, .otp-verify-group {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }
        .otp-input {
          padding: 12px;
          border: 1px solid #ddd;
          border-radius: 6px;
          font-size: 16px;
          width: 100%;
          box-sizing: border-box;
        }
        .otp-code-input {
          text-align: center;
          letter-spacing: 8px;
          font-size: 24px;
        }
        .otp-submit-btn {
          padding: 12px;
          border: none;
          border-radius: 6px;
          color: white;
          font-size: 16px;
          font-weight: 600;
          cursor: pointer;
          transition: opacity 0.2s;
        }
        .otp-submit-btn:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }
        .otp-timer-section {
          text-align: center;
          margin-top: 16px;
        }
        .otp-countdown {
          color: #666;
          font-size: 14px;
        }
        .otp-resend-btn {
          background: none;
          border: none;
          color: var(--primary-color);
          cursor: pointer;
          font-size: 14px;
          text-decoration: underline;
        }
        .otp-widget-success {
          text-align: center;
          padding: 40px;
        }
        .otp-success-icon {
          width: 60px;
          height: 60px;
          background: #10b981;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 30px;
          color: white;
          margin: 0 auto 16px;
        }
        .otp-widget-loading {
          text-align: center;
          padding: 40px;
        }
        .otp-spinner {
          border: 3px solid #f3f3f3;
          border-top: 3px solid var(--primary-color);
          border-radius: 50%;
          width: 30px;
          height: 30px;
          animation: spin 1s linear infinite;
          margin: 0 auto 16px;
        }
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}

export default IsolatedOtpWidget;