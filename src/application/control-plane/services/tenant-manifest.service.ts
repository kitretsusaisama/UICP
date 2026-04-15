import { createHash } from 'crypto';
import { Inject, Injectable } from '@nestjs/common';
import { IManifestRepository } from '../../ports/driven/i-manifest.repository';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import {
  EffectiveManifest,
  ModuleManifestContract,
} from '../contracts/effective-manifest.contract';

const DEFAULT_MANIFESTS: ModuleManifestContract[] = [
  {
    moduleKey: 'auth',
    version: '1.0.0',
    description: 'Authentication and challenge flows',
    resources: [],
    commands: [
      {
        key: 'otp.send',
        description: 'Dispatch an OTP challenge for phone or email authentication',
        capability: 'identity.challenge.send',
        requestSchema: [
          { key: 'recipient', type: 'string', required: true },
          { key: 'purpose', type: 'string', required: true },
          { key: 'channel', type: 'string' },
        ],
      },
      {
        key: 'otp.verify',
        description: 'Verify an OTP challenge for the current tenant context',
        capability: 'identity.challenge.verify',
        requestSchema: [
          { key: 'userId', type: 'string', required: true },
          { key: 'code', type: 'string', required: true },
          { key: 'purpose', type: 'string', required: true },
        ],
      },
    ],
    actions: [],
    extensions: [],
    docs: { summary: 'Public auth flows projected per tenant profile.' },
  },
  {
    moduleKey: 'core',
    version: '1.0.0',
    description: 'Membership, actor, and session self-service',
    resources: [
      {
        key: 'session',
        description: 'Session details available to the current actor',
        capability: 'identity.session.read',
        fields: [
          { key: 'id', type: 'string', required: true },
          { key: 'status', type: 'string', required: true },
          { key: 'actorId', type: 'string' },
        ],
      },
    ],
    commands: [
      {
        key: 'actor.switch',
        description: 'Switch the active actor inside the current membership',
        capability: 'tenant.actor.switch',
        requestSchema: [{ key: 'actorId', type: 'string', required: true }],
      },
    ],
    actions: [
      {
        key: 'session.revoke',
        description: 'Revoke a session family or specific session',
        capability: 'identity.session.revoke',
      },
    ],
    extensions: [],
    docs: { summary: 'Core tenant membership and session interactions.' },
  },
  {
    moduleKey: 'iam',
    version: '1.0.0',
    description: 'Capability and policy management',
    resources: [
      {
        key: 'policy',
        description: 'Tenant policy documents',
        capability: 'policy.read',
      },
    ],
    commands: [
      {
        key: 'policy.simulate',
        description: 'Simulate a policy decision with actor and resource context',
        capability: 'policy.simulate',
      },
    ],
    actions: [
      {
        key: 'policy.explain',
        description: 'Explain a policy decision for audit and support',
        capability: 'policy.explain',
      },
    ],
    extensions: [
      {
        key: 'policy.input.enrichment',
        description: 'Controlled hook to enrich policy input before evaluation',
        extensionPoint: 'policy.input.enrichment',
        runtimeTarget: 'shared',
      },
    ],
    docs: { summary: 'Tenant-aware policy and capability tooling.' },
  },
];

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function mergeDeep<T>(base: T, override: unknown): T {
  if (!isObject(base) || !isObject(override)) {
    return (override as T) ?? base;
  }

  const merged: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(override)) {
    const current = merged[key];
    if (Array.isArray(value)) {
      merged[key] = value;
      continue;
    }
    if (isObject(current) && isObject(value)) {
      merged[key] = mergeDeep(current, value);
      continue;
    }
    merged[key] = value;
  }
  return merged as T;
}

@Injectable()
export class TenantManifestService {
  constructor(
    @Inject(INJECTION_TOKENS.MANIFEST_REPOSITORY)
    private readonly manifestRepository: IManifestRepository,
  ) {}

  async resolveEffectiveManifest(tenantId: string): Promise<EffectiveManifest> {
    const storedManifests = await this.manifestRepository.listActiveModuleManifests();
    const tenantOverrides = await this.manifestRepository.listTenantOverrides(tenantId);

    const modules = new Map<string, ModuleManifestContract>();
    for (const manifest of DEFAULT_MANIFESTS) {
      modules.set(manifest.moduleKey, manifest);
    }

    for (const record of storedManifests) {
      modules.set(record.moduleKey, JSON.parse(record.manifestJson) as ModuleManifestContract);
    }

    for (const override of tenantOverrides) {
      const base = modules.get(override.moduleKey);
      if (!base) {
        continue;
      }
      const overrideJson = JSON.parse(override.overrideJson);
      modules.set(override.moduleKey, mergeDeep(base, overrideJson));
    }

    const manifestMap = Object.fromEntries(modules.entries());
    const versionHash = createHash('sha256')
      .update(JSON.stringify(manifestMap))
      .digest('hex');

    return {
      tenantId,
      versionHash,
      modules: manifestMap,
    };
  }
}
