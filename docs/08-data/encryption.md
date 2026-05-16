---
title: Data Encryption Framework
domain: data
owner: Security Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: MEDIUM
provider-impact: LOW
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - schema-overview.md
  - 07-security/encryption-standards.md
  - 07-security/key-management.md
related-docs:
  - archival.md
  - retention.md
  - audit-storage.md
related-queues:
  - key-rotation-events
related-services:
  - kms-service
  - mysql-database
  - redis-cache
---

# Data Encryption Framework

## Overview

UICP implements defense-in-depth encryption protecting data at rest and in transit. The encryption framework uses AES-256 for symmetric encryption with RSA-2048 for key wrapping. All encryption operations flow through the centralized KMS service enabling key rotation without data re-encryption. The framework complies with FIPS 140-2 standards and supports tenant-managed encryption keys for enterprise requirements.

## Encryption Layers

Transport layer encryption secures all network communication using TLS 1.3 with modern cipher suites. Inter-service communication requires mutual TLS authentication preventing man-in-the-middle attacks. Client connections enforce TLS with automatic upgrade for legacy clients. Certificate rotation occurs automatically through the PKI infrastructure.

Application layer encryption protects sensitive data fields before database insertion. PII fields including email addresses, phone numbers, and names undergo encryption with tenant-specific keys. API key storage uses salted hashing for credential verification while encrypted storage preserves key material for rotation support. Session tokens are encrypted in Redis to prevent unauthorized session hijacking.

Database layer encryption provides transparent protection for all data at rest. Transparent Data Encryption encrypts database pages before writing to storage. Encryption key management uses envelope encryption where data keys encrypt data while key encryption keys protect data keys. Key retrieval occurs through the KMS service with caching for performance optimization.

## Key Management

The KMS service maintains master keys with hardware security module backup for critical key material. Key derivation uses HKDF with unique salt per encryption context preventing key reuse attacks. Key rotation occurs annually for master keys with immediate rotation upon suspected compromise. All key operations generate audit logs for compliance verification.

Tenant-managed keys enable enterprises to provide their own encryption infrastructure. Key integration supports AWS KMS, Azure Key Vault, and GCP Cloud KMS with abstraction layer for vendor independence. Tenant keys remain under tenant control with UICP operations unable to access decrypted data. Key retrieval failures trigger data access blocking preventing unauthorized data exposure.

## Encryption Operations

Field-level encryption occurs in the application layer before data reaches database handlers. The encryption middleware intercepts write operations for protected field types. Read operations automatically decrypt data for authorized requests. Encryption context includes tenant identifier enabling per-tenant key selection. Batch operations optimize encryption by grouping records with similar key requirements.

## Key Rotation

Automatic key rotation minimizes the impact of potential key compromise. Data key rotation occurs without data re-encryption through key version tracking. Historical versions remain available for decrypting data encrypted with previous key versions. The rotation system maintains key metadata enabling seamless decryption of data across key versions. Rotated keys undergo secure deletion after verifying all dependent data uses current versions.