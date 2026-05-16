'use client';

import { useState, FormEvent } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useMutation } from '@tanstack/react-query';
import { Eye, EyeOff, Loader2, Shield } from 'lucide-react';
import { authService } from '@/services/auth.service';
import { useAuthStore } from '@/stores/auth.store';
import { resolveTenantKey } from '@/lib/api-client';

export default function LoginPage() {
  const router = useRouter();
  const { setTokens, setUser, setPendingVerification } = useAuthStore();

  const [identity, setIdentity] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [identityType, setIdentityType] = useState<'EMAIL' | 'PHONE'>('EMAIL');

  const loginMutation = useMutation({
    mutationFn: async (body: { identity: string; password: string; identityType: string }) => {
      return authService.login(resolveTenantKey(), body as Parameters<typeof authService.login>[1]);
    },
    onSuccess: (data) => {
      setTokens(data.data.accessToken, data.data.refreshToken);
      setUser({
        id: data.data.principal.id,
        displayName: data.data.actor?.displayName || data.data.principal.id,
        status: data.data.principal.status,
        email: identityType === 'EMAIL' ? identity : undefined,
        phone: identityType === 'PHONE' ? identity : undefined,
        createdAt: new Date().toISOString(),
        identities: [],
      });
      router.push('/dashboard/overview');
    },
    onError: (err: { message?: string }) => {
      setError(err.message || 'Invalid credentials');
    },
  });

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    setError('');
    loginMutation.mutate({ identity, password, identityType });
  };

  const handleOAuthLogin = (provider: 'google' | 'github') => {
    const redirectUri = `${window.location.origin}/auth/oauth/callback`;
    window.location.href = authService.getOAuthRedirect(provider, resolveTenantKey(), redirectUri);
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-semibold text-ink">Sign in</h1>
        <p className="text-muted text-sm mt-1">Enter your credentials to access your account</p>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-50 border border-danger/20 rounded-lg text-danger text-sm">
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Identity type toggle */}
        <div className="flex rounded-lg border border-gray-200 p-1 gap-1">
          <button
            type="button"
            onClick={() => setIdentityType('EMAIL')}
            className={`flex-1 py-2 text-sm rounded-md transition-colors ${
              identityType === 'EMAIL'
                ? 'bg-accent text-white'
                : 'text-muted hover:text-ink'
            }`}
          >
            Email
          </button>
          <button
            type="button"
            onClick={() => setIdentityType('PHONE')}
            className={`flex-1 py-2 text-sm rounded-md transition-colors ${
              identityType === 'PHONE'
                ? 'bg-accent text-white'
                : 'text-muted hover:text-ink'
            }`}
          >
            Phone
          </button>
        </div>

        {/* Identity input */}
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
              placeholder="Enter your password"
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

        {/* Remember + Forgot */}
        <div className="flex items-center justify-between text-sm">
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" className="rounded border-gray-300" />
            <span className="text-muted">Remember me</span>
          </label>
          <Link href="/auth/forgot-password" className="text-accent hover:underline">
            Forgot password?
          </Link>
        </div>

        {/* Submit */}
        <button
          type="submit"
          disabled={loginMutation.isPending}
          className="w-full py-2.5 bg-accent text-white rounded-lg font-medium text-sm hover:bg-accent/90 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
        >
          {loginMutation.isPending && <Loader2 size={16} className="animate-spin" />}
          Sign in
        </button>
      </form>

      {/* Divider */}
      <div className="relative my-6">
        <div className="absolute inset-0 flex items-center">
          <div className="w-full border-t border-gray-200" />
        </div>
        <div className="relative flex justify-center text-xs">
          <span className="px-2 bg-white text-muted">or continue with</span>
        </div>
      </div>

      {/* OAuth buttons */}
      <div className="grid grid-cols-2 gap-3">
        <button
          onClick={() => handleOAuthLogin('google')}
          className="flex items-center justify-center gap-2 py-2.5 border border-gray-200 rounded-lg text-sm font-medium hover:bg-gray-50 transition-colors"
        >
          <svg className="w-4 h-4" viewBox="0 0 24 24">
            <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
            <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
            <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
            <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
          </svg>
          Google
        </button>
        <button
          onClick={() => handleOAuthLogin('github')}
          className="flex items-center justify-center gap-2 py-2.5 border border-gray-200 rounded-lg text-sm font-medium hover:bg-gray-50 transition-colors"
        >
          <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
          </svg>
          GitHub
        </button>
      </div>

      {/* Register link */}
      <p className="text-center text-sm text-muted mt-6">
        Don&apos;t have an account?{' '}
        <Link href="/auth/register" className="text-accent hover:underline font-medium">
          Sign up
        </Link>
      </p>

      {/* Security badge */}
      <div className="flex items-center justify-center gap-1.5 mt-4 text-muted text-xs">
        <Shield size={12} />
        <span>Secured with TLS 1.3</span>
      </div>
    </div>
  );
}
