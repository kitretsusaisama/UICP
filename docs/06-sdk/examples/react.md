# React Example

## Metadata
```yaml
title: React SDK Example
domain: sdk/examples
owner: platform-team
criticality: MEDIUM
runtime-impact: LOW
security-impact: MEDIUM
queue-impact: NONE
provider-impact: NONE
tenant-impact: LOW
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - frontend-sdk.md
  - initialization.md
  - hooks.md
related-docs:
  - examples/nextjs.md
  - examples/react-native.md
related-queues: []
related-services: []
```

---

## Overview

This guide demonstrates integrating the UICP SDK into a React application. It covers React-specific patterns including Context API, hooks, and component integration.

## Installation

```bash
npm install @uicp/client
```

## SDK Provider

Create a React Context to manage the SDK instance across your application:

```typescript
// context/UICPContext.tsx
import React, { createContext, useContext, useEffect, useState } from 'react';
import { UICPClient } from '@uicp/client';

interface UICPContextType {
  client: UICPClient | null;
  isReady: boolean;
}

const UICPContext = createContext<UICPContextType>({
  client: null,
  isReady: false
});

interface UICPProviderProps {
  children: React.ReactNode;
  publishableKey: string;
  baseUrl?: string;
}

export function UICPProvider({ children, publishableKey, baseUrl }: UICPProviderProps) {
  const [client, setClient] = useState<UICPClient | null>(null);
  const [isReady, setIsReady] = useState(false);

  useEffect(() => {
    const uicpClient = new UICPClient({
      publishableKey,
      baseUrl
    });

    uicpClient.bootstrap().then(() => {
      setClient(uicpClient);
      setIsReady(true);
    });
  }, [publishableKey, baseUrl]);

  return (
    <UICPContext.Provider value={{ client, isReady }}>
      {children}
    </UICPContext.Provider>
  );
}

export function useUICPClient() {
  const context = useContext(UICPContext);
  if (!context.client) {
    throw new Error('useUICPClient must be used within UICPProvider');
  }
  return context.client;
}

export function useUICPReady() {
  return useContext(UICPContext).isReady;
}
```

## Authentication Hook

Create custom hooks for authentication logic:

```typescript
// hooks/useAuth.ts
import { useState, useCallback } from 'react';
import { useUICPClient } from '../context/UICPContext';

interface LoginCredentials {
  identity: string;
  password: string;
}

interface UseAuthReturn {
  login: (credentials: LoginCredentials) => Promise<void>;
  logout: () => Promise<void>;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: Error | null;
}

export function useAuth(): UseAuthReturn {
  const client = useUICPClient();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  const login = useCallback(async ({ identity, password }: LoginCredentials) => {
    setIsLoading(true);
    setError(null);

    try {
      await client.auth.attempt({
        identity,
        authMethod: 'password',
        secret: password
      });
      setIsAuthenticated(true);
    } catch (err) {
      setError(err as Error);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [client]);

  const logout = useCallback(async () => {
    setIsLoading(true);
    try {
      await client.auth.logout();
      setIsAuthenticated(false);
    } finally {
      setIsLoading(false);
    }
  }, [client]);

  return { login, logout, isAuthenticated, isLoading, error };
}
```

## Protected Route Component

Implement route protection for authenticated pages:

```typescript
// components/ProtectedRoute.tsx
import { ReactNode } from 'react';
import { useUICPClient } from '../context/UICPContext';

interface ProtectedRouteProps {
  children: ReactNode;
  fallback?: ReactNode;
}

export function ProtectedRoute({ children, fallback = null }: ProtectedRouteProps) {
  const client = useUICPClient();

  if (!client.session) {
    return <>{fallback}</>;
  }

  return <>{children}</>;
}
```

## Login Form Example

A complete login form component:

```typescript
// components/LoginForm.tsx
import { useState } from 'react';
import { useAuth } from '../hooks/useAuth';

export function LoginForm() {
  const { login, isLoading, error } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await login({ identity: email, password });
  };

  return (
    <form onSubmit={handleSubmit}>
      <div>
        <label htmlFor="email">Email</label>
        <input
          id="email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
      </div>

      <div>
        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
      </div>

      {error && <div role="alert">{error.message}</div>}

      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Logging in...' : 'Login'}
      </button>
    </form>
  );
}
```

## Using with React Router

Integration with React Router for navigation:

```typescript
// App.tsx
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { UICPProvider } from './context/UICPContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';

export function App() {
  return (
    <UICPProvider publishableKey={process.env.REACT_APP_UICP_KEY!}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute fallback={<Navigate to="/login" />}>
                <DashboardPage />
              </ProtectedRoute>
            }
          />
        </Routes>
      </BrowserRouter>
    </UICPProvider>
  );
}
```

---

## Related Documents

- `examples/nextjs.md` - Next.js integration
- `examples/react-native.md` - React Native mobile example