import { Injectable, Inject } from '@nestjs/common';
import { randomUUID, generateKeyPairSync } from 'crypto';
import { RotateKeysCommand } from './rotate-keys.command';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { IEncryptionPort } from '../../ports/driven/i-encryption.port';
import { IOutboxRepository, OutboxEvent } from '../../ports/driven/i-outbox.repository';
import { TokenService } from '../../services/token.service';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';

@Injectable()
export class RotateKeysHandler {
  constructor(
    private readonly tokenService: TokenService,
    @Inject(INJECTION_TOKENS.ENCRYPTION_PORT)
    private readonly encryption: IEncryptionPort,
    @Inject(INJECTION_TOKENS.OUTBOX_REPOSITORY)
    private readonly outboxRepo: IOutboxRepository,
  ) {}

  async handle(cmd: RotateKeysCommand): Promise<{ kid: string; publicKey: string }> {
    // 1. Generate RSA-4096 key pair
    const { privateKey: privateKeyPem, publicKey: publicKeyPem } = generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    }) as unknown as { privateKey: string; publicKey: string };

    // 2. Generate new kid
    const newKid = randomUUID();

    // 3. Encrypt private key
    const tenantId = TenantId.from(cmd.tenantId);
    const encryptedPrivateKey = await this.encryption.encrypt(privateKeyPem, 'JWT_PRIVATE_KEY', tenantId);

    // 4. Rotate signing key in token service
    this.tokenService.rotateSigningKey(privateKeyPem, publicKeyPem, newKid);

    // 5. Insert outbox event
    const outboxEvent: OutboxEvent = {
      id: randomUUID(),
      eventType: 'JwtKeyRotated',
      aggregateId: cmd.tenantId,
      aggregateType: 'Tenant',
      tenantId: cmd.tenantId,
      payload: {
        newKid,
        publicKeyPem,
        encryptedPrivateKey,
        requestedBy: cmd.requestedBy,
      },
      status: 'PENDING',
      attempts: 0,
      createdAt: new Date(),
    };
    await this.outboxRepo.insertWithinTransaction(outboxEvent, null);

    return { kid: newKid, publicKey: publicKeyPem };
  }
}
