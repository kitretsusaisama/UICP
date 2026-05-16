'use client';

import { ReactNode } from 'react';
import { useRouter } from 'next/navigation';
import { useAuthStore } from '@/stores/auth.store';

export default function AuthLayout({ children }: { children: ReactNode }) {
  const router = useRouter();
  const { accessToken, pendingVerification } = useAuthStore();

  // Redirect logged-in users to dashboard
  if (accessToken && !pendingVerification) {
    router.replace('/dashboard/overview');
    return null;
  }

  return (
    <div className="min-h-screen bg-surface flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-2 mb-2">
            <div className="w-10 h-10 bg-accent rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-lg">U</span>
            </div>
            <span className="text-ink font-semibold text-xl">UICP</span>
          </div>
          <p className="text-muted text-sm">Unified Identity Communication Platform</p>
        </div>

        {/* Card */}
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
          {children}
        </div>

        {/* Footer */}
        <p className="text-center text-muted text-xs mt-6">
          &copy; {new Date().getFullYear()} UICP. All rights reserved.
        </p>
      </div>
    </div>
  );
}