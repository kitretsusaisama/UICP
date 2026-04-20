import { Injectable, OnApplicationBootstrap } from '@nestjs/common';
import { DiscoveryService, Reflector } from '@nestjs/core';
import { GovernanceMetadata } from '../decorators/governance.decorator';

@Injectable()
export class GovernanceBootstrapValidator implements OnApplicationBootstrap {
  constructor(
    private readonly discovery: DiscoveryService,
    private readonly reflector: Reflector
  ) {}

  onApplicationBootstrap() {
    const controllers = this.discovery.getControllers();

    for (const wrapper of controllers) {
      const { instance } = wrapper;
      if (!instance) continue;

      const prototype = Object.getPrototypeOf(instance);
      const methods = Object.getOwnPropertyNames(prototype);

      for (const method of methods) {
        const handler = prototype[method];
        if (typeof handler !== 'function' || method === 'constructor') continue;

        // Ensure this method is actually an HTTP route handler before strictly enforcing
        const path = this.reflector.get('path', handler);
        const methodType = this.reflector.get('method', handler);
        if (path === undefined || methodType === undefined) continue;

        const meta = this.reflector.get<GovernanceMetadata>('governance', handler);

        // FOR NOW: Let's log instead of hard crashing everything since we just introduced this
        // In a true production roll-out, this throw new Error(...) would be uncommented
        if (!meta) {
          if (process.env.RELEASE_MODE === 'production') {
            throw new Error(`[PRODUCTION BOOT ERROR] Missing governance metadata: ${instance.constructor.name}.${method}`);
          } else {
            console.warn(`[GOVERNANCE LEAK DETECTED]: ${instance.constructor.name}.${method} lacks @Governance() metadata.`);
          }(`Missing governance metadata: ${instance.constructor.name}.${method}`);
        }
      }
    }
  }
}
