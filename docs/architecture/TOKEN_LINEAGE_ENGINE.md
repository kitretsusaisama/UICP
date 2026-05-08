# UICP Architecture: Token Lineage Engine

## System Classification
Token Runtime

## Token Lineage Design
Strict refresh-token families. When a token is refreshed, a new family is established, and the old token is burned.
Any reuse of a burned token IMMEDIATELY revokes the entire family and triggers a SOC Alert via the outbox.

## Architectural Philosophy
JWTs represent identity only; evaluate authority from DB/cache. Do not trust JWTs without continuous JTI blocklist checking.

## Security Threat Model
Token theft, replay attacks, and offline JWT forging. Mitigation includes KMS isolation for signing keys and S256 PKCE for OAuth.