```yaml
title: State Machines
domain: execution
owner: platform-runtime
criticality: high
runtime-impact: cross-component
security-impact: low
queue-impact: medium
provider-impact: low
tenant-impact: low
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - request-lifecycle.md
  - runtime-context-propagation.md
related-docs:
  - request-lifecycle.md
  - orchestration-runtime.md
related-queues:
  - state-transitions
related-services:
  - state-machine-engine
  - workflow-orchestrator
related-providers: []
related-runtime-states:
  - pending
  - validated
  - routing
  - executing
  - completed
  - failed
  - retrying
  - suspended
related-threat-models:
  - state-replay-attack
  - invalid-state-transitions
```

# State Machines

State machines govern the lifecycle of every request within the execution runtime, ensuring predictable transitions between well-defined states and preventing invalid state progressions that could compromise system integrity.

## State Definitions

The execution runtime defines eight primary states. The pending state represents newly created requests awaiting initial validation. The validated state indicates that input validation has passed and the request is ready for provider routing. The routing state signifies that provider selection is in progress. The executing state marks active provider communication. The completed state indicates successful finish. The failed state represents unrecoverable errors. The retrying state indicates pending retry attempts. The suspended state captures paused requests awaiting external conditions.

## Transition Logic

Each state transition follows strict validation rules enforced by the state-machine-engine. Transitions must be explicitly defined in the state transition matrix, preventing arbitrary state jumps. Guard conditions evaluate whether transitions can proceed based on current context values. Actions execute at transition points to perform side effects such as logging, metric recording, and context updates. Compensation logic triggers when transitions represent error conditions, ensuring rollback of partial state changes.

## Persistence and Recovery

State machines persist their current state to enable recovery after failures. Write-ahead logging records state transitions before they take effect, ensuring durability. Checkpointing captures intermediate states during long-running executions to minimize restart costs. State reconstruction algorithms rebuild in-memory state from persisted logs when runtime processes recover from crashes.

## Concurrency Control

Multiple concurrent operations on the same request require coordination to prevent state corruption. Optimistic locking versions each state transition, rejecting concurrent modifications that would create inconsistent state. Pessimistic locking reserves requests during critical transitions, blocking other operations until completion. Event sourcing maintains a complete history of all transitions, enabling conflict resolution through replay.

## Observability

State machine executions generate comprehensive telemetry for monitoring and debugging. Transition latency metrics identify bottlenecks in state progression. State distribution dashboards show request populations across all states. Anomaly detection alerts when requests remain in transitional states longer than expected. Trace correlation links state transitions to underlying execution traces for end-to-end visibility.
```