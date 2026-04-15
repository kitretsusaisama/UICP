import { Global, Module } from '@nestjs/common';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';
import { Aes256GcmEncryptionAdapter } from './aes256-gcm.encryption.adapter';

@Global()
@Module({
  providers: [
    Aes256GcmEncryptionAdapter,
    { provide: INJECTION_TOKENS.ENCRYPTION_PORT, useExisting: Aes256GcmEncryptionAdapter },
  ],
  exports: [Aes256GcmEncryptionAdapter, INJECTION_TOKENS.ENCRYPTION_PORT],
})
export class EncryptionModule {}
