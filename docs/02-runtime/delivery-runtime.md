```yaml
title: Delivery Runtime
domain: execution
owner: platform-runtime
criticality: high
runtime-impact: cross-component
security-impact: medium
queue-impact: high
provider-impact: high
tenant-impact: low
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - request-lifecycle.md
  - provider-selection.md
  - retry-runtime.md
related-docs:
  - request-lifecycle.md
  - provider-selection.md
  - retry-runtime.md
  - reconciliation-runtime.md
related-queues:
  - delivery-requests
  - delivery-results
  - delivery-confirmations
related-services:
  - delivery-coordinator
  - response-normalizer
  - delivery-confirmator
related-providers:
  - all-configured-providers
related-runtime-states:
  - pending
  - delivering
  - delivered
  - confirmed
  - failed
related-threat-models:
  - response-spoofing
  - man-in-middle
```

# Delivery Runtime

The delivery-runtime handles the transmission of requests to providers and the receipt of responses, managing protocol handling, response normalization, and delivery confirmation to ensure complete request-response cycles.

## Delivery Channels

The delivery-coordinator selects appropriate delivery channels based on request characteristics. Synchronous delivery sends requests and waits for immediate responses, suitable for low-latency requirements. Asynchronous delivery queues requests for later processing, suitable for batch operations. Streaming delivery maintains persistent connections for continuous data exchange. Webhook delivery receives responses via callback URLs for event-driven patterns.

## Protocol Handling

Multiple protocol adapters enable communication with diverse providers. HTTP/HTTPS handling manages request serialization, response parsing, and connection pooling. gRPC handling provides efficient binary protocol communication for compatible providers. WebSocket handling maintains persistent connections for real-time communication. Custom protocol adapters support provider-specific communication requirements.

## Response Processing

The response-normalizer standardizes provider responses into consistent formats. Status code mapping translates provider-specific status codes to canonical status values. Response schema transformation converts provider response structures to internal formats. Partial response handling manages responses containing only partial data. Error response parsing extracts error details from provider error responses.

## Delivery Confirmation

The delivery-confirmator ensures delivery reliability through confirmation mechanisms. Acknowledgment tracking verifies providers received requests. Delivery receipt processing handles provider confirmations. Timeout handling triggers retry or fallback when confirmations do not arrive. Duplicate detection prevents processing duplicate deliveries.

## Security Handling

Delivery security protects request and response data in transit. TLS encryption secures all network communication. Request signing proves message authenticity and prevents tampering. Response validation verifies response integrity before processing. Certificate management maintains trust relationships with providers.
```