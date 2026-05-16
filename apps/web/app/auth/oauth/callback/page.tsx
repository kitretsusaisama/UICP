'use client';

import { Suspense, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Loader2 } from 'lucide-react';
import { useAuthStore } from '@/stores/auth.store';
import { buildHeaders, getApiUrl, resolveTenantKey } from '@/lib/api-client';

function OAuthCallbackContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { setTokens, setUser } = useAuthStore();
  const [error, setError] = useState('');

  useEffect(() => {
    const code = searchParams.get('code');
    const state = searchParams.get('state');
    const errorParam = searchParams.get('error');

    if (errorParam) {
      setError(errorParam);
      return;
    }

    if (!code) {
      setError('No authorization code received');
      return;
    }

    const exchangeCode = async () => {
      try {
        const response = await fetch(getApiUrl('v1/auth/oauth2/callback'), {
          method: 'POST',
          headers: buildHeaders(resolveTenantKey()),
          credentials: 'include',
          body: JSON.stringify({ code, state }),
        });

        if (!response.ok) {
          const data = await response.json();
          throw new Error(data.error?.message || 'OAuth exchange failed');
        }

        const data = await response.json();
        setTokens(data.data.accessToken, data.data.refreshToken);

        if (data.data.user) {
          setUser(data.data.user);
        }

        router.push('/dashboard/overview');
      } catch (err) {
        setError((err as Error).message || 'OAuth authentication failed');
      }
    };

    exchangeCode();
  }, [searchParams, setTokens, setUser, router]);

  if (error) {
    return (
      <div className="text-center py-8">
        <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
          <span className="text-red-600 text-2xl">!</span>
        </div>
        <h2 className="text-lg font-semibold text-ink mb-2">Authentication failed</h2>
        <p className="text-danger text-sm mb-4">{error}</p>
        <a href="/auth/login" className="inline-block px-4 py-2 bg-accent text-white rounded-lg text-sm hover:bg-accent/90">
          Return to login
        </a>
      </div>
    );
  }

  return (
    <div className="text-center py-8">
      <Loader2 className="animate-spin mx-auto mb-4 text-accent" size={32} />
      <p className="text-muted text-sm">Completing sign in...</p>
    </div>
  );
}

export default function OAuthCallbackPage() {
  return (
    <Suspense fallback={
      <div className="text-center py-8">
        <Loader2 className="animate-spin mx-auto mb-4 text-accent" size={32} />
        <p className="text-muted text-sm">Loading...</p>
      </div>
    }>
      <OAuthCallbackContent />
    </Suspense>
  );
}
