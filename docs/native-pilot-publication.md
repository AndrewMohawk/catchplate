# Native policy publication

Policy publication is mandatory before the first application request. The
startup path calls `RecoverCurrentState`, `PrepareGenerationPublication` and
`CommitGenerationPublication`, settling each invocation. Installing the custody
configuration does not publish the policy; neither does the later origin
handoff supply its own earlier baseline.

This slice connects the four publication operations, including abort, through
real native signing, immutable retrieval storage, durable recovery-store state
and an independent current-signature witness. It does not implement checkpoint
verification, activation publication, unavailable-ingress signing or compaction.

## Actual operation sequence

```mermaid
sequenceDiagram
    participant BR as Production bridge
    participant DRS as Durable recovery store
    participant N as Native publication signer
    participant R as Immutable retrieval store
    participant CSA as Independent current-signature authority
    BR->>DRS: Exact request; read authenticated publication state
    DRS-->>BR: Signed request-bound snapshot
    BR->>N: Prepare from that snapshot
    N-->>BR: Signed preparation; no final receipt yet
    opt Commit creates a new publication receipt
        BR->>R: Store the acyclic core
        R-->>BR: Signed immutable storage result
    end
    BR->>N: Complete with exact preparation and storage result
    N-->>BR: Signed proposal
    BR->>DRS: Commit against the original state
    DRS-->>BR: Durable result and signed state transition
    BR->>CSA: Mirror that exact proposal and durable result
    CSA-->>BR: Independently durable signed transition
    BR->>N: Finish with both actual service transitions
    N-->>BR: Final signed dispatch reply
    Note over BR: Persist the final original before invocation settlement
```

The recovery store owns the mutable receipt, pending preparation and finite
approved ingress range. The independent witness keeps its own durable copy and
checks the recovery-store signature, exact result and predecessor head. Both
compare the snapshot against their actual local state. Signatures do not turn
an unrelated snapshot into the current state. A preparation binds the actual
successor, prior receipt/revision and ledger/spool roots; commit must match that
preparation and allocation. The native signer retains its actual bounded
flight, not a redundant third mutable publication journal.

Recovery returns the literal previously admitted business receipt. A new
operation-bound DRS seal wraps it; the business receipt is not re-signed with a
new timestamp. This preserves the signed policy load's exact receipt hash.
Prepare requires the actual recovery seal previously released by the service,
not a caller-invented reference. Actual append/readback precedes success. Exact
completed replay is read-only; conflicting operation/replay/fence reuse and
uncertain writes are refused rather than repaired or automatically retried.

## Explicit selection and evidence

| Layer | Selected successor | Boundaries retained |
| --- | --- | --- |
| Ordinary DRS/CSA runtime | Service runtime/v10; publication grant/v1 | Separate root-approved grant and writable publication journal; old profiles remain closed |
| Native signer | Publication service assignment/v1; publication guest launch/v1 | Actual assigned key, inspected peer, original ordinary histories and admitted prior receipt |
| Retrieval | Ledger/spool retrieval grant/v5 | Exact publication selection, actual fs-verity core storage, existing sequence/head and resource ceilings |
| Bridge | Production RPC runtime/v13; bridge launch/v9 | Required literal DRS/CSA grants and actual native publication endpoint; no generic Dispatch fallback |
| Settlement | Persistence assignment/v3; query/proof/settlement v2 | Explicit extra permission; real final publication reply and actual service transitions; legacy v1 queries stay restricted |

The retrieval addresses hash the stored acyclic core, not a final receipt that
already contains its own retrieval addresses. Native admission pins the assigned
retrieval public key and guest; subsequent independently approved ordinary
grants pin the exact retrieval grant digest. This removes a grant-to-grant hash
cycle without accepting arbitrary storage grants at final completion.

The prior baseline is separately approved, finite original context plus an
actual immutable acyclic object. Its native preparation, DRS snapshot and
retrieval signatures, payload, object hash, fs-verity measurement and retained
readback must agree with the literal prior receipt. Only the specifically
admitted baseline is available through that historical lookup; there is no
general legacy-store fallback. The same assignment/configuration/key/driver
scope and original lifetime are retained, with an independently pinned prior
policy generation. Cross-configuration/history/key recovery is still separate
unfinished work.

## Remaining pilot gates

These consumers do **not** create the first cold-start receipt. A real
receipt-first commissioning producer must establish and persist the genuine
baseline before the policy load and grants that reference it are signed. An
empty journal only means the independently admitted baseline, never evidence
of an uninstalled policy or made-up ledger/spool roots.

The old ten-endpoint commissioning/cohort inventory must not silently acquire
the new publication role. Native selection is explicit; the expanded independently
approved closure/transport inventory and Python commissioning/package producers
still need completion. Counts for the existing graph remain **164/164 jobs and
113 selectors**; those counts do not cover a ready publication deployment.
Uncertain invocation/restart recovery, the other external signer families,
protected provisioning, approved dependencies and connected application
allow/deny/cleanup acceptance remain open. Source checkpoints **36/46** and
production acceptance **0/6** are unchanged.

## Verification

Assembled native compilation is pending. Pure state/snapshot and terminal query
controls are authored, not yet executed. No actual journal/service transcript,
native guest, cold-baseline commissioning, provider, cloud or paid test has run
for this slice. The previous interactive-interval Python checks do not cover
these new Rust paths.
