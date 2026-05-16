# Next.js Example

## Metadata
```yaml
title: Next.js SDK Example
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
  - examples/react.md
  - middleware.md
related-queues: []
related-services: []
```

---

## Overview

This guide demonstrates integrating the UICP SDK into a Next.js application using the App Router. The example covers authentication, protected routes, and server-side integration.

## Installation

```bash
npm install @uicp/client
```

## Environment Configuration

Create a `.env.local` file in your project root:

```env
NEXT_PUBLIC_UICP_PUBLISHABLE_KEY=uF1abc123def456ghi789
NEXT_PUBLIC_UICP_BASE_URL=https://api.uicp.io
```

## Client-Side Integration

### SDK Provider Component

Create a provider component to manage the SDK instance:

```typescript
// components/UICPProvider.tsx
'use client';

import { createContext, useContext, useEffect, useState } from 'react';
import { UICPClient } from '@uicp/client';

const UICPContext = createContext<UICPClient | null>(null);

export function UICPProvider({ children }: { children: React.ReactNode }) {
  const [client, setClient] = useState<UICPClient | null>(null);

  useEffect(() => {
    const uicpClient = new UICPClient({
      publishableKey: process.env.NEXT_PUBLIC_UICP_PUBLISHABLE_KEY!,
      baseUrl: process.env.NEXT_PUBLIC_UICP_BASE_URL
    });
    setClient(uicpClient);
  }, []);

  return (
    <UICPContext.Provider value={client}>
      {children}
    </UICPContext.Provider>
  );
}

export const useUICP = () => {
  const client = useContext(UICPContext);
  if (!client) throw new Error('useUICP must be used within UICPProvider');
  return client;
};
```

### Layout Integration

Wrap your application in the provider:

```typescript
// app/layout.tsx
import { UICPProvider } from '@/components/UICPProvider';

export default function RootLayout({ children }: {
  children: React.ReactNode
}) {
  return (
    <html>
      <body>
        <UICPProvider>
          {children}
        </UICPProvider>
      </body>
    </html>
  );
}
```

### Authentication Hook

Create a custom hook for authentication:

```typescript
// hooks/useAuth.ts
import { useUICP } from '@/components/UICPProvider';
import { useRouter } from 'next/navigation';

export function useAuth() {
  const client = useUICP();
  const router = useRouter();

  const login = async (identity: string, password: string) => {
    const session = await client.auth.attempt({
      identity,
      authMethod: 'password',
      secret: password
    });
    router.push('/dashboard');
    return session;
  };

  const logout = async () => {
    await client.auth.logout();
    router.push('/login');
  };

  return { login, logout, client };
}
```

## Server-Side Integration

For server components, use the backend SDK with secret keys:

```bash
npm install @uicp/server
```

```typescript
// lib/uicp-server.ts
import { UICPBackendClient } from '@uicp/server';

export const serverClient = new UICPBackendClient({
  secretKey: process.env.UICP_SECRET_KEY!,
  tenantId: process.env.UICP_TENANT_ID!,
  baseUrl: process.env.UICP_BASE_URL
});
```

## Middleware Protection

Protect routes using Next.js middleware:

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const token = request.cookies.get('uicp_token');

  if (!token && request.nextUrl.pathname.startsWith('/dashboard')) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  return NextResponse.next();
}
```

## Example Application

A complete login page example:

```typescript
// app/login/page.tsx
'use client';

import { useState } from 'react';
import { useAuth } from '@/hooks/useAuth';

export default function LoginPage() {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await login(email, password);
    } catch (err) {
      setError('Invalid credentials');
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Email"
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
      />
      {error && <p>{error}</p>}
      <button type="submit">Login</button>
    </form>
  );
}
```

---

## Related Documents

- `examples/react.md` - React integration details
- `middleware.md` - Full middleware documentation