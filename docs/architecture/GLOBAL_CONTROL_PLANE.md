# UICP Architecture: Global Control Plane

## System Classification
Orchestration brain and distributed policy controller.

## Strategic Positioning
The global control plane determines the truth of the system topology, tenant boundaries, and regional deployments.

## Macro Architecture
- Tenant Provisioning
- Runtime Orchestration
- Rollout Governance
- Multi-region configuration propagation

## Multi-Region Strategy
- Configuration pushed from Global Control Plane to regional clusters.
- Eventual consistency is accepted for configuration, but not for security invariants.

## Blast Radius Analysis
If the Global Control Plane goes down, the regional data planes MUST continue to operate autonomously using cached policies and last-known-good configurations (Static Fallback).

## Hard Tradeoffs
Global Control Plane requires 99.999% availability for administrative updates, but must NEVER bottleneck the critical runtime path (authentication/authorization).

## Production Rollout Plan
Implement as a decoupled service using gRPC or highly reliable message buses to sync to Edge nodes.