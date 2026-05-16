---
title: Audit Storage Design
domain: data
owner: Security Team
criticality: CRITICAL
runtime-impact: MEDIUM
security-impact: CRITICAL
queue-impact: MEDIUM
provider-impact: LOW
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - schema-overview.md
  - event-store.md
  - 07-security/audit-requirements.md
related-docs:
  - event-store.md
  - replay-storage.md
  - lineage-storage.md
related-queues:
  - audit-events
related-services:
  - audit-service
  - mysql-database
---

# Audit Storage Design

## Overview

UICP maintains comprehensive audit logs capturing all security-relevant events across the platform. The audit storage design ensures tamper-proof records with long-term retention for compliance requirements. Audit data supports forensic investigation, regulatory reporting, and security monitoring use cases.

## Audit Event Categories

Authentication events log all login attempts including successful and failed attempts. Events capture user identifier, authentication method, source IP address, and timestamp. Session events track session creation, termination, and modification. API key events record key creation, rotation, and revocation actions.

Authorization events log access decisions including permission checks and denial outcomes. Resource access events capture each API request with user, resource, and action details. Configuration changes record administrative actions modifying system settings. Data export events track bulk data access for compliance verification.

## Audit Storage Architecture

Audit logs are written to the audit store immediately, bypassing the standard outbox pattern for security-critical events. The audit store uses append-only storage preventing modification or deletion of historical records. Write-ahead logging ensures audit entries survive system failures. Cryptographic chaining links audit entries enabling tamper detection.

Partitioning by tenant ensures data isolation while enabling cross-tenant security monitoring. Time-based partitioning supports retention policy enforcement and efficient historical queries. The storage tier automatically transitions to cold storage after active retention expires. Immutable archives maintain compliance retention periods.

## Audit Query Interface

The administrative interface provides search capabilities across audit events. Filters support time ranges, user identification, event types, and resource access patterns. Export functionality generates audit reports in compliance-required formats. Integration with security information and event management systems enables real-time alerting.

## Integrity Protection

Each audit entry includes a hash of the previous entry creating a cryptographic chain. Hash verification detects any attempt to modify historical entries. The chain seed stored in hardware security modules prevents offline tampering. Integrity verification runs periodically confirming chain consistency.

## Retention and Archival

Standard retention maintains audit logs in active storage for two years enabling rapid access. Extended retention keeps archives for seven years supporting regulatory compliance. Legal holds suspend deletion for records relevant to ongoing investigations. Automated culling removes records only after retention expiration and hold release verification.