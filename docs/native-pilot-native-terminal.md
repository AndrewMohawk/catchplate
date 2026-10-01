# Native completed-invocation settlement

`.395` adds an explicit successful-native-invocation protocol. It does not
report process death, global retirement, or successful upstream business effects.
This is a source-design handoff; verification results remain pending below.

## Explicit selection

Outer commissioning policy/v19 selects bridge runtime/v12 and bridge launch/v8.
The receiving gate selects this behavior from its actual retained `Factory`,
whose runtime original is bound to the authenticated native closure. A response
tag or caller-supplied flag cannot select it. Earlier policy/runtime/launch
profiles keep their existing contracts, including legacy v4 process-termination
settlement; there is no fallback between the two evidence formats.

Persistence Assignment/v2 separately authorizes `verify-completed-invocation`.
The permission permits a read-only export of an already committed final
invocation, not a new write, manufactured success, or cleanup action.

## Evidence chain

The bridge resolves the exact operation from its durable completed-request and
response records before requesting persistence evidence. The gate independently
retains its actual successful outer RPC request and response only after business
result reconstruction and existing native-computation checks succeed.

The [shared wire](../data-plane/decision-gate-rs/src/policy_custody/native_terminal.rs)
uses a closed completed-invocation query, proof, and settlement artifact. The
query contains the full closed dispatch request, the canonical closed-response
SHA, and the original cleanup-not-before boundary. The artifact binds the
literal outer RPC originals separately; these are different hash domains and
cannot be substituted for one another.

The [persistence owner](../data-plane/decision-gate-rs/src/policy_custody/services/native_guest/persistence.rs)
rechecks its actual held chain and resolves one signed commit containing the
original final endpoint request/reply. It exports that literal commit and its
linked head, plus the actual current head sequence/hash. The existing assigned
StoreResponse endpoint key signs the reply. A later current head is not itself
a replacement for the selected commit's linked head. Existing per-invocation
operation/fence/replay alias refusals and exact idempotent replay remain intact.

The [receiver verifier](../data-plane/decision-gate-rs/src/policy_custody/native_terminal_verify.rs)
authenticates the store reply, existing commit signature, linked head, final
native signer reply/completion, and operation-derived ordinary-service roster.
It compares full canonical requests/results with the gate's retained originals,
not a caller's assertion of their hashes. It checks the original operation,
request, durable request, replay, fence, configuration, driver and deadline
bindings; assigned key IDs, SPKIs and raw key material remain independently
selected. The native spool reservation uses its actual completion-core signer
role rather than assuming the eventual event's append signer.

The commit's proof scope equals the receiving configuration's authenticated
scope. Its guest UID/GID and authority match the retained persistence endpoint;
boot/time namespace and original window are checked. Guest delivery/configuration/
runtime digest fields remain signed producer metadata, not a new gate-side
measurement of the persistence process.

## History provenance and clocks

Only runtime/v12 adds a literal `historyOriginal` to each of the five
`ordinaryInitialHistories` members. Runtime/v10 and v11 retain their closed
two-field member grammar. The startup builder takes these literals from actual
authenticated ordinary contexts; bridge startup checks equality with its
retained credentials. The gate obtains the whole runtime from its retained
Factory, never from the settlement artifact.

Each wrapper is verified under the corresponding runtime's independently pinned
root, with its generation grant, semantic history commitment, role and complete
scope association. The narrow retained-completed-history entrypoint reuses
wrapper/checkpoint signatures and original lifetime bounds. It does not reopen
startup admission, repeat an empty-directory claim, or change the existing
startup-only loader. The minimum authenticated grant expiry, history checkpoint
expiry, original history/persistence lifetime and cleanup deadline survives
verification and is checked again at final acceptance. No clock is renewed.

## Supported boundary

The selected native final paths cover exactly eight operations:

- `BeginIngress`, `CommitRequest`, `ReserveSpoolAppend`, `AppendSpoolEvent`;
- `AppendTerminal`, `AppendActiveEffectBarrier`, `CommitActiveEffect`,
  `ReconcileActiveEffect`.

Only their native `FinishCommitRequest`, `FinishNativeSpool` or
`FinishNativeActiveEffect` evidence is accepted. A signed generic `Dispatch`
cannot substitute. All other operations remain outside this successor,
including generic `VerifyObservationEvidence`. The four external signer
families—unavailable ingress, spool compaction, publication reconciliation and
activation publication—are not made operational by this work.

Aborted invocations and uncertain/incomplete recovered attempts do not acquire
success evidence. Existing durable pre-contact fencing and fail-closed recovery
remain necessary. Definite protocol completion does not turn `OutcomeUnknown`
or `ReconcileRequired` into known business success, nor revoke a separately
one-use barrier permit for a later operation ID.

## Limits and verification

The existing 4 MiB frame/runtime bounds are unchanged. Nested literal commit,
endpoint and RPC originals can exceed the settlement frame even when an earlier
dispatch fit; such an invocation is not promised settleable by this format.
Persistence heads remain bounded to 128 records, and gate retention remains
bounded by the original maximum-in-flight count.

Root's assembled verification is pending. No full positive retained-Factory
receiver transcript, end-to-end native runtime settlement, uncertain-operation
recovery, or production readiness is claimed here. Passing source/primitive
controls or a compiler check would not establish those stronger properties.
