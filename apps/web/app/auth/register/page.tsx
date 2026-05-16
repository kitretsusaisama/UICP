'use client';

import { useState, FormEvent } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useMutation } from '@tanstack/react-query';
import { Eye, EyeOff, Loader2, CheckCircle2 } from 'lucide-react';
import { authService } from '@/services/auth.service';
import { useAuthStore } from '@/stores/auth.store';
import { resolveTenantKey } from '@/lib/api-client';

export default function RegisterPage() {
  const router = useRouter();
  const { setPendingVerification } = useAuthStore();

  const [step, setStep] = useState<'form' | 'otp'>('form');
  const [identityType, setIdentityType] = useState<'EMAIL' | 'PHONE'>('EMAIL');
  const [identity, setIdentity] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [passwordError, setPasswordError] = useState('');

  const signupMutation = useMutation({
    mutationFn: async () => {
      return authService.signup(resolveTenantKey(), {
        email: identityType === 'EMAIL' ? identity : undefined,
        phone: identityType === 'PHONE' ? identity : undefined,
        password,
        identityType,
      });
    },
    onSuccess: (data) => {
      setPendingVerification({
        userId: data.data.principalId,
        purpose: data.data.challenge.purpose,
        channel: data.data.challenge.channel,
      });
      setStep('otp');
    },
  });

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    setPasswordError('');

    if (password.length < 8) {
      setPasswordError('Password must be at least 8 characters');
      return;
    }
    if (password !== confirmPassword) {
      setPasswordError('Passwords do not match');
      return;
    }

    signupMutation.mutate();
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-semibold text-ink">Create account</h1>
        <p className="text-muted text-sm mt-1">Join UICP to manage identity and communications</p>
      </div>

      {step === 'form' ? (
        <>
          {signupMutation.error && (
            <div className="mb-4 p-3 bg-red-50 border border-danger/20 rounded-lg text-danger text-sm">
              {(signupMutation.error as { message?: string }).message || 'Registration failed'}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Identity type toggle */}
            <div className="flex rounded-lg border border-gray-200 p-1 gap-1">
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

            {/* Identity */}
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

            {/* Password */}
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Password</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Min. 8 characters"
                  className="w-full px-3 py-2 pr-10 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-ink"
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {/* Confirm Password */}
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Confirm password</label>
              <input
                type={showPassword ? 'text' : 'password'}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Repeat password"
                className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
                required
              />
            </div>

            {passwordError && (
              <p className="text-danger text-sm">{passwordError}</p>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={signupMutation.isPending}
              className="w-full py-2.5 bg-accent text-white rounded-lg font-medium text-sm hover:bg-accent/90 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {signupMutation.isPending && <Loader2 size={16} className="animate-spin" />}
              Create account
            </button>
          </form>

          {/* Terms */}
          <p className="text-xs text-muted text-center mt-4">
            By creating an account, you agree to our{' '}
            <a href="#" className="text-accent hover:underline">Terms of Service</a>
            {' '}and{' '}
            <a href="#" className="text-accent hover:underline">Privacy Policy</a>
          </p>
        </>
      ) : (
        <div className="text-center py-4">
          <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <CheckCircle2 className="text-green-600" size={24} />
          </div>
          <h2 className="text-lg font-semibold text-ink mb-2">Account created</h2>
          <p className="text-muted text-sm mb-6">
            A verification code has been sent to your {identityType.toLowerCase()}.
          </p>
          <Link
            href="/auth/verify-otp"
            className="inline-block w-full py-2.5 bg-accent text-white rounded-lg font-medium text-sm hover:bg-accent/90 transition-colors text-center"
          >
            Continue to verification
          </Link>
        </div>
      )}

      {/* Sign in link */}
      <p className="text-center text-sm text-muted mt-6">
        Already have an account?{' '}
        <Link href="/auth/login" className="text-accent hover:underline font-medium">
          Sign in
        </Link>
      </p>
    </div>
  );
}
