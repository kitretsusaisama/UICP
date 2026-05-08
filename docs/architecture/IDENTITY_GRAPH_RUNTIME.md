# UICP Architecture: Identity Graph Runtime

## System Classification
Identity Graph Runtime

## Identity Graph Architecture
Tracks realtime relationships: Users, Sessions, Devices, IP Addresses, and Tokens.
Nodes: Identity elements.
Edges: `authenticated_with`, `accessed_from`, `replayed_by`.

## Strategic Positioning
Essential for detecting attack chains, lateral movement, and privilege escalations across tenants.

## Security Threat Model
Graph poisoning (inserting fake nodes) or Graph DoS (creating massive cyclic relationships).

## Distributed Consistency Risks
Graph propagation must be causal. A session cannot exist in the graph before its underlying identity.

## Scalability Bottlenecks
Real-time graph queries are expensive. Speculative execution and pre-computation will be required.