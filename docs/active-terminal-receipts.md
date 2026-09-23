# Active terminal receipt retention

The active lifecycle retains a private `ActiveTerminalRecord` after successful
terminal finalization. It owns the final active decision and a compact reference
to the actual verified durable custody receipt. It is not a permit, a new
attestation, a serialized observation, or evidence that a downstream client
received the response.

Before appending, the lifecycle prepares the exact terminal event and validates
its request, generation, ingress sequence, phase, plan, outcome, effect and
response bindings. The returned HTTP status participates in the final-decision
commitment. After appending, it requires the receipt to match the prepared event.
Only matching `Committed` or `Existing` terminal outcomes are usable; a fork,
unavailable receipt, mismatched binding or failed custody completion is not a
successful terminal handoff.

Publication into lifecycle state still follows the existing finalization and
response-terminal compare-and-exchange checks and the final state lock. An
append can have succeeded even when a later local step fails. Such a failure
does not publish a new terminal record or assert that the append was undone;
the existing fail-closed accounting and reconciliation obligations remain.

The retained addition is fixed-size: inline digests, receipt identifiers,
sequence values, status and phase. It does not retain an extra request/response
body, canonical event buffer or signature buffer. Queue accounting includes the
additional retained size. This is not a new general memory or latency bound for
the whole lifecycle.

The component fixtures sign receipt bytes and pass them through the existing
signature, trusted-time/checkpoint, persistence and retrieval verifier before
constructing a compact receipt reference. Their local exact-byte persistence
checks are not independent production storage or a production assignment-bound
custody service. They do not establish the full RPC, restart-recovery,
finalization-race or provider request flow.

## Remaining active/candidate separation

This retention step does not select a new evidence profile, change sampling, or
decouple candidate queues from active liveness. Those changes must move together
with mandatory active admission for both sampling outcomes, parent-to-resolved
plan ancestry and prerequisite receipts, truthful denial terminals, independent
candidate resource accounting, and matching signed Rust/Python/custody evidence
producers and consumers. Candidate workers must ultimately receive immutable
facts and completed active evidence, not an effect-capable lifecycle.

The requirements in `goal.md` remain authoritative. A local receipt component
test is not completion of that integrated runtime or production acceptance.
