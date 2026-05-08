import { Injectable } from '@nestjs/common';
import { promises as dns } from 'dns';

export const DNS_ADAPTER = 'DNS_ADAPTER';

export interface IDnsAdapter {
  resolveTxt(domain: string): Promise<string[][]>;
}

@Injectable()
export class DnsAdapter implements IDnsAdapter {
  async resolveTxt(domain: string): Promise<string[][]> {
    try {
      return await dns.resolveTxt(domain);
    } catch (e: any) {
      if (e.code === 'ENODATA' || e.code === 'ENOTFOUND') {
        return [];
      }
      throw e;
    }
  }
}
