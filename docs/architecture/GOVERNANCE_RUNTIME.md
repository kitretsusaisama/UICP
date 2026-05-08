# UICP Architecture: Governance Runtime

## System Classification
Governance & Compliance Plane

## Governance Runtime Architecture
Every API route requires `@Governance` decorators mapping to a static `ROUTE_MANIFEST`. A dual-lock system (`GovernanceBootstrapValidator`) checks at boot time; missing metadata results in a fatal crash in production.

## Compliance Implications
Must support SOC2, GDPR, HIPAA. Audit logs are tamper-evident using a verifiable hash chain model (`hash_n = SHA256(hash_(n-1) + event_data)`).

## Failure Modes
Boot loop if manifest falls out of sync with code.

## Recovery Strategy
Strict CI/CD gates (AST/Regex analyzers, OPA/Rego policies) prevent merging misconfigured governance states.