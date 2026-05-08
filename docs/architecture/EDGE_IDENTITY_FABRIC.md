# UICP Architecture: Edge Identity Fabric

## System Classification
Edge Authorization Platform

## Edge Runtime Architecture
Push JWT validation, replay checking, and regional policies to edge compute nodes (e.g., Cloudflare Workers). State is synced from the Global Control Plane.

## Edge Synchronization Strategy
Asynchronous propagation of graph updates. Edge maintains local KV caches of revoked JTIs and compromised device fingerprints.

## Hard Tradeoffs
We accept eventual consistency for *new* policies at the edge to preserve sub-5ms latency, but *revocations* require synchronous invalidation routing or tight TTL windows.