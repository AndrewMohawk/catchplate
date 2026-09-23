# Custody response verification boundary

The production RPC client now reconstructs `BeginIngress` and `AppendTerminal`
responses through the existing assignment-bound verifiers. Previously these
requests were encoded, but their responses fell through to custody-unavailable.
This is a consumer implementation, not an installed authority service or proof
that the production request path works. The current changes are source-only
until the exact frozen commit completes the required execution workflow.

## Untrusted wire and authenticated results

The artifact decoder checks the exact artifact kind and byte envelope, then
deserializes and requires an exact canonical round trip. The two new wire enums
use an `outcome` tag and `receipt` content;
unknown tags and fields are rejected. Neither wire contains a deserializable
verified receipt or a response-supplied generation identity.

| Operation and outcome | Required binding before returning a verified result |
| --- | --- |
| `BeginIngress`, `assigned` | Request binding, locally retained published generation, committed sequence range, sampling authorization and the exact signed ingress-opening event. |
| `BeginIngress`, `unavailable` | Request binding, receipt constructor invariants, generation equality when both expected and reported generations exist, and authenticated unavailable evidence. This never authorizes ingress. |
| `AppendTerminal`, `committed` or `existing` | Exact requested terminal event, request and commitment tuple, terminal phase, and an appended disposition. |
| `AppendTerminal`, `fork` | Same generation, ingress sequence, request and commitment tuple, but a different stored terminal event. The stored conflict is authenticated and returned as a fork, never as success for the replacement. |

All paths still require the applicable production authority assignment,
signature/key, trust checkpoint, time, persistence and immutable retrieval
checks. A valid JSON shape, outcome tag, or outer RPC response alone does not
construct a verified custody result. Deserialized unavailable receipts are
revalidated through their constructor invariants before signature verification.

The assigned receipt's wrapper uses camel-case fields; existing nested receipt
types retain their own serialization contracts. The new unavailable receipt
representation uses its Rust field names. This does not change the signed
payload domains or negotiate a new fleet evidence profile.

## Bounded publication context

The client retains at most one pending publication and one published context.
Preparation captures the exact configuration, request digest, immutable locally
verified successor, expected predecessor and publication revision. Returned
preparation data must match that successor and its recomputed sequence-range
commitment. A verified `Published` reconciliation receipt must match the retained
preparation, successor, predecessor, revision and sequence bounds before the
context is exposed to ingress.

Request construction holds the configuration read guard through local context
capture, then releases it before the network operation. Response reconstruction
reacquires that guard, checks the original configuration binding, and keeps it
through verification and local publication. Configuration replacement cannot
silently reinterpret an old response or let an old request repopulate cleared
publication state.

Each ingress request captures its immutable published context before RPC; it
does not reread a newer generation when the response arrives. A monotonic local
revision also accompanies recovery requests. Delayed recovery responses cannot
erase intervening preparations or publications. Abort affects only its exact
retained context; configuration replacement invalidates local publication
state. Revision overflow fails closed.

Local transition validation precedes retaining a returned sealed capability.
The validated next state is installed only if capability retention succeeds.
Preparation similarly checks its reservation before consuming a recovered
capability. Duplicate capability insertion does not overwrite an existing
entry. These rules prevent rejected transitions from consuming or replacing
capabilities merely because they reached local response handling.

Recovery preserves a published identity only when it is already retained and
exactly matches the authenticated receipt. A digest-only recovery receipt
cannot seed an absent verified assignment/load identity. After a fresh process
start, the ordinary authenticated prepare/commit chain must supply that
identity before an `assigned` response is accepted. Ambiguous remote operations
remain recovery obligations; local failure does not undo remote persistence.

## Test and completion limits

The new test sources cover shared binding checks with real Ed25519 signatures,
key/time/checkpoint and exact-byte proof rejection, terminal outcome selection,
ingress range/request/sampling checks, unavailable receipt invariants, the
actual artifact decoder, and bounded publication-state transitions. Source
assertions separately check production-verifier wiring and ordering. Local
generation data is explicitly structural fixture data, not a verified
production assignment; in-memory proof stores are not independent durable
storage. Test-source presence is not a passing test result.

The full assignment-bound RPC fixture, receiving authority implementation,
durable publication/journal and restart recovery, role-separated signed fleet
envelope producers, and live provider/Nitro/KMS evidence remain incomplete.
This consumer repair also does not implement sampling-independent active
execution, candidate resource isolation, or a coordinated successor to the
existing evidence profile. See [the production goal](../goal.md) and
[credential prerequisite retention](credential-prerequisite-receipts.md) for
the broader integration requirements.
