import { Global, Module } from '@nestjs/common';
import { OtelTracerAdapter } from './otel-tracer.adapter';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';

@Global()
@Module({
  providers: [
    OtelTracerAdapter,
    {
      provide: INJECTION_TOKENS.TRACER_PORT,
      useExisting: OtelTracerAdapter,
    },
  ],
  exports: [INJECTION_TOKENS.TRACER_PORT, OtelTracerAdapter],
})
export class TracingModule {}
