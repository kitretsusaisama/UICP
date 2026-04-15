import { Global, Module } from '@nestjs/common';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { MysqlUserRepository } from './mysql-user.repository';
import { MysqlIdentityRepository } from './mysql-identity.repository';
import { MysqlOutboxRepository } from './mysql-outbox.repository';
import { MysqlTokenRepository } from './mysql-token.repository';
import { MysqlEventStoreRepository } from './mysql-event-store.repository';
import { MysqlAbacPolicyRepository } from './mysql-abac-policy.repository';
import { MysqlAlertRepository } from './mysql-alert.repository';
import { MysqlAuditLogRepository } from './mysql-audit-log.repository';
import { MysqlManifestRepository } from './mysql-manifest.repository';
import { MysqlProviderRoutingRepository } from './mysql-provider-routing.repository';
import { MysqlRuntimeIdentityRepository } from './mysql-runtime-identity.repository';
import { MysqlExtensionBindingRepository } from './mysql-extension-binding.repository';

@Global()
@Module({
  providers: [
    { provide: INJECTION_TOKENS.USER_REPOSITORY,        useClass: MysqlUserRepository },
    { provide: INJECTION_TOKENS.IDENTITY_REPOSITORY,    useClass: MysqlIdentityRepository },
    { provide: INJECTION_TOKENS.OUTBOX_REPOSITORY,      useClass: MysqlOutboxRepository },
    { provide: INJECTION_TOKENS.TOKEN_REPOSITORY,       useClass: MysqlTokenRepository },
    { provide: INJECTION_TOKENS.EVENT_STORE,            useClass: MysqlEventStoreRepository },
    { provide: INJECTION_TOKENS.ABAC_POLICY_REPOSITORY, useClass: MysqlAbacPolicyRepository },
    { provide: INJECTION_TOKENS.ALERT_REPOSITORY,       useClass: MysqlAlertRepository },
    { provide: INJECTION_TOKENS.AUDIT_LOG_REPOSITORY,   useClass: MysqlAuditLogRepository },
    { provide: INJECTION_TOKENS.MANIFEST_REPOSITORY,    useClass: MysqlManifestRepository },
    { provide: INJECTION_TOKENS.PROVIDER_ROUTING_REPOSITORY, useClass: MysqlProviderRoutingRepository },
    { provide: INJECTION_TOKENS.RUNTIME_IDENTITY_REPOSITORY, useClass: MysqlRuntimeIdentityRepository },
    { provide: INJECTION_TOKENS.EXTENSION_BINDING_REPOSITORY, useClass: MysqlExtensionBindingRepository },
  ],
  exports: [
    INJECTION_TOKENS.USER_REPOSITORY,
    INJECTION_TOKENS.IDENTITY_REPOSITORY,
    INJECTION_TOKENS.OUTBOX_REPOSITORY,
    INJECTION_TOKENS.TOKEN_REPOSITORY,
    INJECTION_TOKENS.EVENT_STORE,
    INJECTION_TOKENS.ABAC_POLICY_REPOSITORY,
    INJECTION_TOKENS.ALERT_REPOSITORY,
    INJECTION_TOKENS.AUDIT_LOG_REPOSITORY,
    INJECTION_TOKENS.MANIFEST_REPOSITORY,
    INJECTION_TOKENS.PROVIDER_ROUTING_REPOSITORY,
    INJECTION_TOKENS.RUNTIME_IDENTITY_REPOSITORY,
    INJECTION_TOKENS.EXTENSION_BINDING_REPOSITORY,
  ],
})
export class RepositoriesModule {}
