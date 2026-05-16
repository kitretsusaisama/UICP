'use client';

import { useState, FormEvent } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useMutation } from '@tanstack/react-query';
import { Loader2, CheckCircle2 } from 'lucide-react';
import { authService } from '@/services/auth.service';
import { resolveTenantKey } from '@/lib/api-client';

export default function ForgotPasswordPage() {
  const router = useRouter();
  const [step, setStep] = useState<'request' | 'confirm'>('request');
  const [resetToken, setResetToken] = useState('');
  const [identity, setIdentity] = useState('');
  const [identityType, setIdentityType] = useState<'EMAIL' | 'PHONE'>('EMAIL');
  const [error, setError] = useState('');

  const requestMutation = useMutation({
    mutationFn: async () => {
      return authService.requestPasswordReset(resolveTenantKey(), identity, identityType);
    },
    onSuccess: () => {
      setStep('confirm');
    },
    onError: (err: { message?: string }) => {
      setError(err.message || 'Failed to send reset code');
    },
  });

  const confirmMutation = useMutation({
    mutationFn: async (data: { resetToken: string; newPassword: string }) => {
      return authService.confirmPasswordReset(resolveTenantKey(), data.resetToken, data.newPassword);
    },
    onSuccess: () => {
      router.push('/auth/login');
    },
    onError: (err: { message?: string }) => {
      setError(err.message || 'Failed to reset password');
    },
  });

  const handleConfirmSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const newPassword = formData.get('newPassword') as string;
    const confirmPassword = formData.get('confirmPassword') as string;

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    confirmMutation.mutate({ resetToken, newPassword });
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-semibold text-ink">Reset password</h1>
        <p className="text-muted text-sm mt-1">
          {step === 'request'
            ? 'Enter your email or phone to receive a reset code'
            : 'Enter your new password'}
        </p>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-50 border border-danger/20 rounded-lg text-danger text-sm">
          {error}
        </div>
      )}

      {step === 'request' ? (
        <>
          {/* Identity type toggle */}
          <div className="flex rounded-lg border border-gray-200 p-1 gap-1 mb-4">
            <button
              type="button"
              onClick={() => setIdentityType('EMAIL')}
              className={`flex-1 py-2 text-sm rounded-md transition-colors ${
                identityType === 'EMAIL' ? 'bg-accent text-white' : 'text-muted hover:text-ink'
              }`}
            >
              Email
            </button>
            <button
              type="button"
              onClick={() => setIdentityType('PHONE')}
              className={`flex-1 py-2 text-sm rounded-md transition-colors ${
                identityType === 'PHONE' ? 'bg-accent text-white' : 'text-muted hover:text-ink'
              }`}
            >
              Phone
            </button>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              setError('');
              requestMutation.mutate();
            }}
            className="space-y-4"
          >
            <div>
              <label className="block text-sm font-medium text-ink mb-1">
                {identityType === 'EMAIL' ? 'Email address' : 'Phone number'}
              </label>
              <input
                type={identityType === 'EMAIL' ? 'email' : 'tel'}
                value={identity}
                onChange={(e) => setIdentity(e.target.value)}
                placeholder={identityType === 'EMAIL' ? 'you@company.com' : '+1 555 000 0000'}
                className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
                required
              />
            </div>

            <button
              type="submit"
              disabled={requestMutation.isPending}
              className="w-full py-2.5 bg-accent text-white rounded-lg font-medium text-sm hover:bg-accent/90 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {requestMutation.isPending && <Loader2 size={16} className="animate-spin" />}
              Send reset code
            </button>
          </form>

          <p className="text-center text-sm text-muted mt-6">
            Remember your password?{' '}
            <Link href="/auth/login" className="text-accent hover:underline font-medium">
              Sign in
            </Link>
          </p>
        </>
      ) : (
        <>
          <div className="mb-4 p-3 bg-green-50 border border-green-200 rounded-lg text-green-700 text-sm flex items-center gap-2">
            <CheckCircle2 size={16} />
            <span>Reset code sent to your {identityType.toLowerCase()}</span>
          </div>

          <div className="mb-4">
            <label className="block text-sm font-medium text-ink mb-1">Reset token</label>
            <input
              type="text"
              value={resetToken}
              onChange={(e) => setResetToken(e.target.value)}
              placeholder="Paste the token from your message"
              className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent font-mono"
              required
            />
          </div>

          <form onSubmit={handleConfirmSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-ink mb-1">New password</label>
              <input
                type="password"
                name="newPassword"
                placeholder="Min. 8 characters"
                className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-ink mb-1">Confirm password</label>
              <input
                type="password"
                name="confirmPassword"
                placeholder="Repeat password"
                className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
                required
              />
            </div>

            <button
              type="submit"
              disabled={confirmMutation.isPending}
              className="w-full py-2.5 bg-accent text-white rounded-lg font-medium text-sm hover:bg-accent/90 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {confirmMutation.isPending && <Loader2 size={16} className="animate-spin" />}
              Reset password
            </button>
          </form>
        </>
      )}
    </div>
  );
}
