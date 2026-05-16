import { createUicpClient } from '../core/client';
import { UicpClientConfig } from '../types';

export function createRouteHandlerClient(config: UicpClientConfig) {
  return createUicpClient(config);
}

export function createRscClient(config: UicpClientConfig) {
  return createUicpClient(config);
}

export function createUicpMiddleware() {
  return function middleware() {
    return undefined;
  };
}

export async function getServerSession() {
  return null;
}

export async function requireAuth() {
  return null;
}

export async function requireTenant() {
  return null;
}

export async function validateAccessTokenAtEdge() {
  return true;
}

export function withTenantRoute<T>(handler: T): T {
  return handler;
}
