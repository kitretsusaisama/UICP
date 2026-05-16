/**
 * @uicp/sdk - React Hooks
 */

import { createContext, useContext, useState, useCallback, ReactNode } from 'react';
import { UicpClient } from '../core/client';

export const UicpContext = createContext<UicpClient | null>(null);

export function useUicp(): UicpClient {
  const client = useContext(UicpContext);
  if (!client) throw new Error('Use UicpProvider to provide the client');
  return client;
}

export function useAuth() { return useUicp().auth; }
export function useUser() { return useUicp().user; }
export function useSession() { return useUicp().session; }
export function useCore() { return useUicp().core; }
export function usePlatform() { return useUicp().platform; }
export function useAdmin() { return useUicp().admin; }

export interface UseOtpWidgetOptions {
  channel?: 'sms' | 'whatsapp' | 'email';
  purpose?: string;
}

export interface OtpWidgetState {
  step: 'idle' | 'sending' | 'sent' | 'verifying' | 'verified' | 'error';
  identity: string;
  code: string;
  error: string | null;
  attempts: number;
}

export function useOtpWidget(options: UseOtpWidgetOptions = {}) {
  const auth = useAuth();
  const [state, setState] = useState<OtpWidgetState>({
    step: 'idle', identity: '', code: '', error: null, attempts: 0,
  });

  const sendOtp = useCallback(async (identity: string) => {
    setState(s => ({ ...s, step: 'sending', identity, error: null }));
    try {
      await auth.sendOtp({ identity, channel: options.channel ?? 'sms', purpose: options.purpose ?? 'IDENTITY_VERIFICATION' });
      setState(s => ({ ...s, step: 'sent' }));
    } catch (err: any) {
      setState(s => ({ ...s, step: 'error', error: err?.message ?? 'Failed to send OTP' }));
    }
  }, [auth, options.channel, options.purpose]);

  const verifyOtp = useCallback(async (code: string) => {
    setState(s => ({ ...s, step: 'verifying', code, error: null }));
    try {
      const result = await auth.verifyOtp({ userId: '', code, purpose: options.purpose ?? 'IDENTITY_VERIFICATION' }) as { verified: boolean };
      if (result.verified) { setState(s => ({ ...s, step: 'verified', attempts: s.attempts + 1 })); return true; }
      setState(s => ({ ...s, step: 'error', error: 'Invalid code', attempts: s.attempts + 1 }));
      return false;
    } catch (err: any) {
      setState(s => ({ ...s, step: 'error', error: err?.message ?? 'Verification failed', attempts: s.attempts + 1 }));
      return false;
    }
  }, [auth, options.purpose, state.identity]);

  const resendOtp = useCallback(() => setState(s => ({ ...s, step: 'idle', code: '' })), []);
  const reset = useCallback(() => setState({ step: 'idle', identity: '', code: '', error: null, attempts: 0 }), []);

  return { ...state, sendOtp, verifyOtp, resendOtp, reset };
}

export interface UicpProviderProps {
  client: UicpClient;
  children: ReactNode;
}

export function UicpProvider({ client, children }: UicpProviderProps) {
  return <UicpContext.Provider value={client}>{children}</UicpContext.Provider>;
}

export interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
}

export function useAuthState() {
  const client = useUicp();
  const [state, setState] = useState<AuthState>({ isAuthenticated: false, isLoading: true, error: null });

  useState(() => {
    client.isAuthenticated().then((isAuth) => setState({ isAuthenticated: isAuth, isLoading: false, error: null }));
  });

  client.events.on('tokens:cleared', () => setState({ isAuthenticated: false, isLoading: false, error: null }));

  return state;
}