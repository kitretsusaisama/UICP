# React Native Example

## Metadata
```yaml
title: React Native SDK Example
domain: sdk/examples
owner: platform-team
criticality: MEDIUM
runtime-impact: MEDIUM
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
  - token-handling.md
related-docs:
  - examples/react.md
  - publishable-keys.md
related-queues: []
related-services: []
```

---

## Overview

This guide demonstrates integrating the UICP SDK into React Native applications for iOS and Android. The SDK supports secure token storage using device keychain and handles mobile-specific authentication flows.

## Installation

```bash
npm install @uicp/client-react-native
# For TypeScript
npm install -D @types/uicp-client-react-native
```

## SDK Initialization

Create the SDK client with mobile-specific configuration:

```typescript
// lib/uicp.ts
import { UICPClient } from '@uicp/client-react-native';

export const client = new UICPClient({
  publishableKey: process.env.UICP_PUBLISHABLE_KEY!,
  baseUrl: 'https://api.uicp.io',
  // Use secure keychain storage
  tokenStorage: {
    type: 'secure-store',
    keychainService: 'com.yourapp.uicp'
  }
});

export default client;
```

## Authentication Context

Create a React Context for authentication:

```typescript
// context/AuthContext.tsx
import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import client from '../lib/uicp';

interface AuthContextType {
  isLoading: boolean;
  isAuthenticated: boolean;
  user: any | null;
  login: (identity: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isLoading, setIsLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    checkExistingSession();
  }, []);

  async function checkExistingSession() {
    try {
      const session = await client.auth.getSession();
      if (session) {
        setIsAuthenticated(true);
        setUser(await client.users.me());
      }
    } catch {
      // No valid session
    } finally {
      setIsLoading(false);
    }
  }

  async function login(identity: string, password: string) {
    const session = await client.auth.attempt({
      identity,
      authMethod: 'password',
      secret: password
    });

    setIsAuthenticated(true);
    setUser(await client.users.me());
  }

  async function logout() {
    await client.auth.logout();
    setIsAuthenticated(false);
    setUser(null);
  }

  return (
    <AuthContext.Provider value={{ isLoading, isAuthenticated, user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}
```

## Login Screen

Implement a login screen:

```typescript
// screens/LoginScreen.tsx
import React, { useState } from 'react';
import { View, TextInput, Button, Text, StyleSheet, ActivityIndicator } from 'react-native';
import { useAuth } from '../context/AuthContext';

export function LoginScreen() {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleLogin() {
    setIsLoading(true);
    setError('');

    try {
      await login(email, password);
    } catch (err: any) {
      setError(err.message || 'Login failed');
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <View style={styles.container}>
      <TextInput
        style={styles.input}
        placeholder="Email"
        value={email}
        onChangeText={setEmail}
        autoCapitalize="none"
        keyboardType="email-address"
      />

      <TextInput
        style={styles.input}
        placeholder="Password"
        value={password}
        onChangeText={setPassword}
        secureTextEntry
      />

      {error ? <Text style={styles.error}>{error}</Text> : null}

      <Button
        title={isLoading ? 'Logging in...' : 'Login'}
        onPress={handleLogin}
        disabled={isLoading}
      />

      {isLoading && <ActivityIndicator style={styles.loader} />}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 20, justifyContent: 'center' },
  input: { borderWidth: 1, padding: 10, marginBottom: 15, borderRadius: 5 },
  error: { color: 'red', marginBottom: 10 },
  loader: { marginTop: 10 }
});
```

## Protected Routes

Implement navigation with authentication:

```typescript
// App.tsx
import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { AuthProvider, useAuth } from './context/AuthContext';
import { LoginScreen } from './screens/LoginScreen';
import { DashboardScreen } from './screens/DashboardScreen';

const Stack = createNativeStackNavigator();

function AppNavigator() {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return <ActivityIndicator />;
  }

  return (
    <Stack.Navigator>
      {isAuthenticated ? (
        <Stack.Screen name="Dashboard" component={DashboardScreen} />
      ) : (
        <Stack.Screen name="Login" component={LoginScreen} />
      )}
    </Stack.Navigator>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <NavigationContainer>
        <AppNavigator />
      </NavigationContainer>
    </AuthProvider>
  );
}
```

## Biometric Authentication

Enable biometric (Face ID/Touch ID) authentication:

```typescript
const client = new UICPClient({
  publishableKey: process.env.UICP_PUBLISHABLE_KEY!,
  // Enable biometric authentication
  biometric: {
    enabled: true,
    prompt: 'Authenticate to access UICP'
  }
});

// Use biometric for login
async function biometricLogin() {
  await client.auth.biometricAuth();
  const user = await client.users.me();
  return user;
}
```

## Push Notifications

Handle push notification token registration:

```typescript
import { client } from './lib/uicp';

async function registerPushToken(token: string) {
  await client.notifications.registerToken({
    platform: 'firebase',
    token
  });
}
```

---

## Related Documents

- `examples/react.md` - Web React example
- `token-handling.md` - Token management details