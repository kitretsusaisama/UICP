'use client';

import { useState, useRef, useEffect, FormEvent } from 'react';
import { useRouter } from 'next/navigation';
import { useMutation } from '@tanstack/react-query';
import { Loader2, RefreshCw } from 'lucide-react';
import { authService } from '@/services/auth.service';
import { useAuthStore } from '@/stores/auth.store';
import { resolveTenantKey } from '@/lib/api-client';

const RESEND_COOLDOWN = 60; // seconds

export default function VerifyOtpPage() {
  const router = useRouter();
  const { pendingVerification, setPendingVerification, setTokens, setUser } = useAuthStore();

  const [code, setCode] = useState(['', '', '', '', '', '']);
  const [resendCooldown, setResendCooldown] = useState(0);
  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  useEffect(() => {
    if (!pendingVerification) {
      router.replace('/auth/login');
    }
  }, [pendingVerification, router]);

  useEffect(() => {
    if (resendCooldown > 0) {
      const timer = setTimeout(() => setResendCooldown(resendCooldown - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [resendCooldown]);

  const verifyMutation = useMutation({
    mutationFn: async (codeStr: string) => {
      if (!pendingVerification) throw new Error('No pending verification');
      return authService.verifyOtp(resolveTenantKey(), {
        userId: pendingVerification.userId,
        code: codeStr,
        purpose: pendingVerification.purpose as Parameters<typeof authService.verifyOtp>[1]['purpose'],
      });
    },
    onSuccess: (data) => {
      if (data.data.accessToken) {
        setTokens(data.data.accessToken, data.data.refreshToken);
      }
      setPendingVerification(null);
      router.push('/dashboard/overview');
    },
  });

  const handleInput = (index: number, value: string) => {
    if (value.length > 1) {
      // Handle paste
      const digits = value.replace(/\D/g, '').slice(0, 6 - index).split('');
      const newCode = [...code];
      digits.forEach((digit, i) => {
        if (index + i < 6) newCode[index + i] = digit;
      });
      setCode(newCode);
      const nextIndex = Math.min(index + digits.length, 5);
      inputRefs.current[nextIndex]?.focus();
      return;
    }

    if (/^\d$/.test(value)) {
      const newCode = [...code];
      newCode[index] = value;
      setCode(newCode);

      // Auto-advance
      if (index < 5) {
        inputRefs.current[index + 1]?.focus();
      }
    }
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent) => {
    if (e.key === 'Backspace' && !code[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
  };

  const handlePaste = (e: React.ClipboardEvent) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
    const newCode = [...code];
    pasted.split('').forEach((digit, i) => {
      if (i < 6) newCode[i] = digit;
    });
    setCode(newCode);
  };

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    const codeStr = code.join('');
    if (codeStr.length === 6) {
      verifyMutation.mutate(codeStr);
    }
  };

  const resendMutation = useMutation({
    mutationFn: async () => {
      if (!pendingVerification) throw new Error('No pending verification');
      return authService.sendOtp(resolveTenantKey(), {
        userId: pendingVerification.userId,
        purpose: pendingVerification.purpose as Parameters<typeof authService.sendOtp>[1]['purpose'],
        channel: pendingVerification.channel as Parameters<typeof authService.sendOtp>[1]['channel'],
      });
    },
    onSuccess: () => {
      setResendCooldown(RESEND_COOLDOWN);
    },
  });

  return (
    <div>
      <div className="mb-6 text-center">
        <h1 className="text-2xl font-semibold text-ink">Verify your {pendingVerification?.channel?.toLowerCase()}</h1>
        <p className="text-muted text-sm mt-2">Enter the 6-digit code we sent to your {pendingVerification?.channel?.toLowerCase()}</p>
      </div>

      {verifyMutation.error && (
        <div className="mb-4 p-3 bg-red-50 border border-danger/20 rounded-lg text-danger text-sm">
          {(verifyMutation.error as { message?: string }).message || 'Invalid code'}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* OTP inputs */}
        <div className="flex gap-2 justify-center" onPaste={handlePaste}>
          {code.map((digit, i) => (
            <input
              key={i}
              ref={(el) => { inputRefs.current[i] = el; }}
              type="text"
              inputMode="numeric"
              maxLength={6}
              value={digit}
              onChange={(e) => handleInput(i, e.target.value)}
              onKeyDown={(e) => handleKeyDown(i, e)}
              className="w-12 h-12 text-center text-xl font-semibold border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
              autoFocus={i === 0}
            />
          ))}
        </div>

        <button
          type="submit"
          disabled={code.join('').length < 6 || verifyMutation.isPending}
          className="w-full py-2.5 bg-accent text-white rounded-lg font-medium text-sm hover:bg-accent/90 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
        >
          {verifyMutation.isPending && <Loader2 size={16} className="animate-spin" />}
          Verify code
        </button>
      </form>

      {/* Resend */}
      <div className="mt-6 text-center">
        {resendCooldown > 0 ? (
          <p className="text-muted text-sm">
            Resend in {resendCooldown}s
          </p>
        ) : (
          <button
            onClick={() => resendMutation.mutate()}
            disabled={resendMutation.isPending}
            className="text-accent text-sm hover:underline flex items-center justify-center gap-1 mx-auto"
          >
            <RefreshCw size={14} />
            Resend code
          </button>
        )}
      </div>

      <p className="text-center text-sm text-muted mt-6">
        <button onClick={() => router.back()} className="text-muted hover:text-ink">
          Back to sign in
        </button>
      </p>
    </div>
  );
}
