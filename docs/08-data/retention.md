---
title: Data Retention Policy
domain: data
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: HIGH
queue-impact: MEDIUM
provider-impact: LOW
tenant-impact: HIGH
ai-ingestable: true
review-cycle: yearly
last-reviewed: 2026-05-16
depends-on:
  - schema-overview.md
  - archival.md
  - 07-security/data-classification.md
related-docs:
  - archival.md
  - encryption.md
  - audit-storage.md
related-queues:
  - retention-events
related-services:
  - mysql-database
  - object-storage
---

# Data Retention Policy

## Overview

UICP implements tiered data retention policies based on data classification and regulatory requirements. The retention framework enforces automatic expiration while providing legal hold capabilities for data requiring extended preservation. All retention policies respect tenant-specific overrides configured through the administrative interface.

## Retention Tiers

The active tier stores data requiring immediate access within the primary database. Active data includes current user sessions, pending operations, and recent audit entries. The active tier maintains full query performance and real-time indexing. Data transitions to the archive tier automatically upon reaching the configured retention threshold.

The archive tier stores data in cost-optimized object storage with database references pointing to archived records. Archive data remains queryable through the application layer with automatic retrieval for access requests. The archive tier maintains metadata indexes for search and discovery while storing blob contents in compressed format.

The compliance tier implements indefinite retention for data subject to legal or regulatory requirements. Audit logs, financial records, and security events are automatically promoted to compliance storage upon archive expiration. Compliance data supports audit-ready retrieval with cryptographic integrity verification.

## Retention Periods

User session data automatically expires 24 hours after creation or manual revocation. Expired sessions are marked for archival and removed from active storage within the configured cleanup interval. API key rotations archive previous key versions for 90 days before permanent deletion, enabling security incident investigation.

Audit logs maintain a 7-year retention period supporting compliance requirements for financial and healthcare domains. The event store retains all events for 5 years with optional extension for specific tenant configurations. User data follows a soft-delete pattern with permanent removal occurring 30 days after account deletion.

## Automated Enforcement

The retention enforcement system runs daily to identify expired data across all storage tiers. Expired records are moved to pending deletion queues for processing. Archive data exceeding retention limits undergoes secure deletion with cryptographic verification. The system generates compliance reports documenting retention policy enforcement for audit purposes.

## Tenant Configuration

Enterprise tenants may configure custom retention periods within defined boundaries. The minimum retention period prevents accidental data loss, while maximum periods accommodate regulatory requirements. Tenant configuration changes trigger recalculation of expiration dates for affected records. Override capabilities enable legal holds that suspend retention enforcement for specific records.