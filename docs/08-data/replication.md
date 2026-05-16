---
title: Database Replication
domain: data
owner: Platform Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: MEDIUM
provider-impact: HIGH
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - schema-overview.md
  - partitioning.md
  - 03-architecture/database-patterns.md
related-docs:
  - partitioning.md
  - consistency-model.md
  - migrations.md
related-queues:
  - replication-events
related-services:
  - mysql-database
  - redis-cache
---

# Database Replication

## Overview

UICP implements multi-tier database replication providing high availability, disaster recovery, and read scaling capabilities. The replication architecture uses asynchronous streaming replication for geographic distribution with synchronous replication for critical write operations. Replication configuration supports both automated failover and manual intervention scenarios.

## Replication Topology

The primary database handles all write operations with replication to secondary instances across availability zones. Each secondary maintains a lag indicator measuring milliseconds behind the primary. Read queries route to secondaries for read-heavy workloads while writes always execute against the primary. The topology automatically reconfigures during failover events without application interruption.

Cross-region replication extends the architecture for disaster recovery and latency optimization. Asynchronous replication replicates data to remote regions with configurable lag tolerance. Read replicas in each region serve local traffic reducing cross-region latency. Replication uses compressed binary format minimizing bandwidth requirements across regions.

## Failover Handling

Automatic failover triggers when the primary becomes unavailable for configured thresholds. The failover coordinator promotes the most current secondary to primary status. DNS updates propagate new primary endpoints to application connections. The system maintains replication health metrics enabling proactive failover before complete primary failure.

Manual failover supports maintenance windows and controlled migration scenarios. Operations teams initiate failover through the administrative interface with automated pre-checks and validation. Failover procedures include data consistency verification and rollback capability if issues arise. Post-failover analysis documents event timeline and identifies root causes.

## Replication Monitoring

Real-time replication lag monitoring alerts when secondaries fall behind primary by configurable thresholds. Lag metrics feed into autoscaling decisions for read replica provisioning. Historical lag analysis identifies patterns enabling capacity planning. Checksum verification ensures replica data integrity through periodic consistency checks.

## Conflict Resolution

Multi-primary replication scenarios use last-writer-wins conflict resolution for most fields. Vector clocks track update causality enabling intelligent conflict merging for complex objects. Application-defined conflict handlers provide custom resolution logic for business-critical conflicts. Conflict logging captures resolution decisions for audit and debugging purposes.