import { Global, Module } from '@nestjs/common';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { MysqlUserRepository } from './mysql-user.repository';
import { MysqlIdentityRepository } from './mysql-identity.repository';
import { MysqlOutboxRepository } from './mysql-outbox.repository';
import { MysqlTokenRepository } from './mysql-token.repository';
import { MysqlEventStoreRepository } from './mysql-event-store.repository';
import { MysqlAbacPolicyRepository } from './mysql-abac-policy.repository';
import { MysqlAlertRepository } from './mysql-alert.repository';
import { MysqlManifestRepository } from './mysql-manifest.repository';
import { MysqlProviderRoutingRepository } from './mysql-provider-routing.repository';
import { MysqlRuntimeIdentityRepository } from './mysql-runtime-identity.repository';
import { MysqlExtensionBindingRepository } from './mysql-extension-binding.repository';

// Platform Repositories
import { MysqlAppRepository } from './repositories/platform/mysql-app.repository';
import { MysqlAppSecretRepository } from './repositories/platform/mysql-app-secret.repository';
import { MysqlDomainRepository } from './repositories/platform/mysql-domain.repository';
import { MysqlWebhookRepository } from './repositories/platform/mysql-webhook.repository';

// Governance Repositories
import { MysqlRoleRepository } from './repositories/governance/mysql-role.repository';
import { MysqlRoleAssignmentRepository } from './repositories/governance/mysql-role-assignment.repository';
import { MysqlPolicyRepository } from './repositories/governance/mysql-policy.repository';

// SOC Repositories
import { MysqlSocAlertRepository } from './repositories/soc/mysql-soc-alert.repository';
import { MysqlIncidentRepository } from './repositories/soc/mysql-incident.repository';
import { MysqlAuditLogRepository } from './mysql-audit-log.repository';

import { APP_REPOSITORY } from '../../../domain/repositories/platform/app.repository.interface';
import { APP_SECRET_REPOSITORY } from '../../../domain/repositories/platform/app-secret.repository.interface';
import { DOMAIN_REPOSITORY } from '../../../domain/repositories/platform/domain.repository.interface';
import { WEBHOOK_REPOSITORY } from '../../../domain/repositories/platform/webhook.repository.interface';

import { ROLE_REPOSITORY } from '../../../domain/repositories/governance/role.repository.interface';
import { ROLE_ASSIGNMENT_REPOSITORY } from '../../../domain/repositories/governance/role-assignment.repository.interface';
import { POLICY_REPOSITORY } from '../../../domain/repositories/governance/policy.repository.interface';

import { SOC_ALERT_REPOSITORY } from '../../../domain/repositories/soc/soc-alert.repository.interface';
import { INCIDENT_REPOSITORY } from '../../../domain/repositories/soc/incident.repository.interface';
import { AUDIT_LOG_REPOSITORY } from '../../../domain/repositories/audit-log.repository.interface';

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
    { provide: INJECTION_TOKENS.MANIFEST_REPOSITORY,    useClass: MysqlManifestRepository },
    { provide: INJECTION_TOKENS.PROVIDER_ROUTING_REPOSITORY, useClass: MysqlProviderRoutingRepository },
    { provide: INJECTION_TOKENS.RUNTIME_IDENTITY_REPOSITORY, useClass: MysqlRuntimeIdentityRepository },
    { provide: INJECTION_TOKENS.EXTENSION_BINDING_REPOSITORY, useClass: MysqlExtensionBindingRepository },

    // Platform
    { provide: APP_REPOSITORY, useClass: MysqlAppRepository },
    { provide: APP_SECRET_REPOSITORY, useClass: MysqlAppSecretRepository },
    { provide: DOMAIN_REPOSITORY, useClass: MysqlDomainRepository },
    { provide: WEBHOOK_REPOSITORY, useClass: MysqlWebhookRepository },

    // Governance
    { provide: ROLE_REPOSITORY, useClass: MysqlRoleRepository },
    { provide: ROLE_ASSIGNMENT_REPOSITORY, useClass: MysqlRoleAssignmentRepository },
    { provide: POLICY_REPOSITORY, useClass: MysqlPolicyRepository },

    // SOC
    { provide: SOC_ALERT_REPOSITORY, useClass: MysqlSocAlertRepository },
    { provide: INCIDENT_REPOSITORY, useClass: MysqlIncidentRepository },
    { provide: AUDIT_LOG_REPOSITORY, useClass: MysqlAuditLogRepository },
  ],
  exports: [
    INJECTION_TOKENS.USER_REPOSITORY,
    INJECTION_TOKENS.IDENTITY_REPOSITORY,
    INJECTION_TOKENS.OUTBOX_REPOSITORY,
    INJECTION_TOKENS.TOKEN_REPOSITORY,
    INJECTION_TOKENS.EVENT_STORE,
    INJECTION_TOKENS.ABAC_POLICY_REPOSITORY,
    INJECTION_TOKENS.ALERT_REPOSITORY,
    INJECTION_TOKENS.MANIFEST_REPOSITORY,
    INJECTION_TOKENS.PROVIDER_ROUTING_REPOSITORY,
    INJECTION_TOKENS.RUNTIME_IDENTITY_REPOSITORY,
    INJECTION_TOKENS.EXTENSION_BINDING_REPOSITORY,

    APP_REPOSITORY,
    APP_SECRET_REPOSITORY,
    DOMAIN_REPOSITORY,
    WEBHOOK_REPOSITORY,

    ROLE_REPOSITORY,
    ROLE_ASSIGNMENT_REPOSITORY,
    POLICY_REPOSITORY,

    SOC_ALERT_REPOSITORY,
    INCIDENT_REPOSITORY,
    AUDIT_LOG_REPOSITORY,
  ],
})
export class RepositoriesModule {}
