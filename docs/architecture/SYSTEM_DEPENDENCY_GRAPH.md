# UICP System Dependency Graph

## Execution Dependencies
To prevent catastrophic sequencing, systems MUST be built in this precise order:

### Layer 1: Data & Event Plane
- **MySQL / Relational Store**
- **Transactional Outbox**
  - *Depends on*: MySQL
- **Continuation Local Storage (CLS)**

### Layer 2: Core Domain Logic
- **Multi-Tenant Isolation Model**
  - *Depends on*: CLS, MySQL
- **Session Lineage & Token Families**
  - *Depends on*: Redis, MySQL, Outbox
- **Replay Protection Model**
  - *Depends on*: Redis (Atomic Locks)

### Layer 3: Observability
- **Observability & Forensics**
  - *Depends on*: Outbox, CLS

--- ^^^ PHASE 1 BOUNDARY ^^^ ---

### Layer 4: Intelligence & Graph
- **Identity Graph Runtime**
  - *Depends on*: Observability, Outbox, Session Lineage
- **Consistency Graph Engine**
  - *Depends on*: Observability, Graph Runtime

### Layer 5: Advanced Orchestration
- **Global Control Plane**
  - *Depends on*: Consistency Graph
- **Adaptive Runtime Engine**
  - *Depends on*: Observability, Global Control Plane

### Layer 6: Edge & Scale
- **Edge Identity Fabric**
  - *Depends on*: Global Control Plane, Consistency Graph
- **Governance Runtime**
  - *Depends on*: Control Plane, Edge Fabric