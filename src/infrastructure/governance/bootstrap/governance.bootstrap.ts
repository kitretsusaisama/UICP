import { Injectable, OnApplicationBootstrap } from '@nestjs/common';
import { DiscoveryService, Reflector } from '@nestjs/core';
import { GovernanceMetadata } from '../decorators/governance.decorator';
import { ROUTE_MANIFEST } from '../route-manifest';

@Injectable()
export class GovernanceBootstrapValidator implements OnApplicationBootstrap {
  constructor(
    private readonly discovery: DiscoveryService,
    private readonly reflector: Reflector
  ) {}

  onApplicationBootstrap() {
    const controllers = this.discovery.getControllers();
    const manifestKeys = Object.keys(ROUTE_MANIFEST);
    const discoveredKeys = new Set<string>();

    for (const wrapper of controllers) {
      const { instance } = wrapper;
      if (!instance) continue;

      const prototype = Object.getPrototypeOf(instance);
      const methods = Object.getOwnPropertyNames(prototype);
      const controllerPath = this.reflector.get('path', instance.constructor);
      let cPath = controllerPath ? (controllerPath.startsWith('/') ? controllerPath : `/${controllerPath}`) : '';
      if (cPath.endsWith('/')) cPath = cPath.slice(0, -1);

      for (const method of methods) {
        const handler = prototype[method];
        if (typeof handler !== 'function' || method === 'constructor') continue;

        // Try extracting NestJS HTTP decorators manually as a fallback
        let mPath = this.reflector.get('path', handler);
        const mType = Object.keys(Reflect.getMetadataKeys(handler) || {}).find(k => k.includes('method'));

        let httpMethod = 'GET';
        if (this.reflector.get('method', handler) !== undefined) {
           const methodCode = this.reflector.get('method', handler);
           if (methodCode === 0) httpMethod = 'GET';
           if (methodCode === 1) httpMethod = 'POST';
           if (methodCode === 2) httpMethod = 'PUT';
           if (methodCode === 3) httpMethod = 'DELETE';
           if (methodCode === 4) httpMethod = 'PATCH';
        } else {
           continue; // Not an HTTP handler
        }

        mPath = mPath ? (mPath.startsWith('/') ? mPath : `/${mPath}`) : '';
        let fullPath = `${cPath}${mPath}`;
        if (!fullPath.startsWith('/')) fullPath = `/${fullPath}`;

        const routeKey = `${httpMethod} ${fullPath}`.replace(/\/\//g, '/');
        discoveredKeys.add(routeKey);

        const meta = this.reflector.get<GovernanceMetadata>('governance', handler);

        // Cross-Check 1: Route existence
        if (!ROUTE_MANIFEST[routeKey]) {
            this.handleViolation(`MISSING_IN_MANIFEST: Route ${routeKey} is undocumented in ROUTE_MANIFEST.`);
        }

        // Cross-Check 3: Metadata mismatch
        if (meta && ROUTE_MANIFEST[routeKey]) {
           const manifestEntry = ROUTE_MANIFEST[routeKey];
           if (meta.owner !== manifestEntry.owner) {
              this.handleViolation(`OWNER_MISMATCH: ${routeKey} owner in code '${meta.owner}' !== manifest '${manifestEntry.owner}'`);
           }
           if (meta.auth !== manifestEntry.auth) {
              this.handleViolation(`AUTH_MISMATCH: ${routeKey} auth in code '${meta.auth}' !== manifest '${manifestEntry.auth}'`);
           }
           // Enforce critical fields completeness
           if (!manifestEntry.edgeCases || !manifestEntry.failure || !manifestEntry.audit) {
              this.handleViolation(`INCOMPLETE_MANIFEST: ${routeKey} is missing critical failure or edge-case definitions.`);
           }
        }
      }
    }

    // Cross-Check 2: Manifest Orphan Check
    for (const key of manifestKeys) {
       if (!discoveredKeys.has(key)) {
          this.handleViolation(`ORPHAN_MANIFEST_ENTRY: ${key} exists in ROUTE_MANIFEST but not in runtime controllers.`);
       }
    }
  }

  private handleViolation(msg: string) {
    if (process.env.RELEASE_MODE === 'production') {
      throw new Error(`[PRODUCTION BOOT ERROR] ${msg}`);
    } else {
      console.warn(`[GOVERNANCE LEAK DETECTED]: ${msg}`);
    }
  }
}
