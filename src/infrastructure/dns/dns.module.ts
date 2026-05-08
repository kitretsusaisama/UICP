import { Module, Global } from '@nestjs/common';
import { DnsAdapter, DNS_ADAPTER } from './dns.adapter';

@Global()
@Module({
  providers: [
    {
      provide: DNS_ADAPTER,
      useClass: DnsAdapter,
    },
  ],
  exports: [DNS_ADAPTER],
})
export class DnsModule {}
