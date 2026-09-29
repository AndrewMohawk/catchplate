# Native canary durable delivery

This source slice connects the real native canary signer and generated TLS
owner to the protected delivery store and intake. It is not runtime acceptance,
provisioned assignment evidence, or implementation of the twelve real canary
exporters. The prior intake/signing and A23 protected-delivery slices are exact
prerequisites. Their old HTTP3, Statement22, native proof, signature domains and
intake path remain unchanged.

## Actual ownership and cold selection

`native_canary_delivery::prepare` admits the closed ten-field
`nativeCanaryDurableDelivery/v1` configuration, obtains the existing actual
`NativeCanaryHttpClient` from the same enclave identity, and retains the native
relay owner. `GateStateInputs.measured_canary_delivery` is optional only so older
profiles remain unselected. The native bootstrap consumes this field after
encrypted service installation, before sharing the state, and initializes the
same retained owner. There is no environment, header, request or lazy fallback.
The explicit [v19 startup](native-canary-delivery-startup.md) composes this
owner with v18's genuine succession and historical-key broker, without changing
older startup wire contracts.
The paired schema anchor is
`native-policy-canary-durable-delivery.v1.schema.json#/$defs/configuration`.

The independent cold inputs pin the authority root public key/SPKI and the exact
original signed full authority configuration. They must be part of the genuinely
admitted native startup closure, not supplied by the CP response being checked.
The full configuration signature and digest include every policy. The intake v2
and distinct delivery policy have no embedded self-hash. The current separately
enabled verifier/planner operations and per-canary assignments are checked.
Each of at most sixteen canary bindings selects the current intake and delivery
assignment, canary assignment and canary boot. None supplies native ownership.

The existing native role-4 key owner, actual executable reader, active policy,
same runtime CA and generated dedicated clientAuth leaf produce native identity
fields. `sign_native_canary_delivery` checks those actual owners and uses only
the new prepare/recover/claim domains. The same enclave-generated TLS private
key remains opaque and cannot be exported. The CP separately verifies its
actual TLS peer, original NSM evidence, assignments and every inner producer.

## Fixed producer and contact sequence

The source-only producer seam is
`native_canary_delivery::submit(state, BatchOriginal, original_deadline)`.
`BatchOriginal` is a bounded exact-original grammar, not proof that a record
came from a real exporter. Only the forthcoming actual exporter owners should
call it. No public arbitrary-upload or general signing endpoint is introduced.

The retained owner signs the future HTTP3 intake body once and preserves its
exact bytes, native sender, TLS owner, canary binding, original expiry and
BOOTTIME deadline. It then performs:

1. Atomic protected prepare of the exact future HTTP original and stable head.
2. A separate completed recover/read proving persisted slot, head and parts.
3. One irreversible claim containing the actual prepare/read completions.
4. One fixed-path POST of the unchanged future HTTP body, only after the actual
   claim completion has been independently verified by the same owner.
5. A completed recover/read of the consumed slot and exact intake batch result.

The local phase changes before claim/contact. The dedicated HTTP client also
retains attempted phase IDs and intake slot IDs before request construction.
HTTP redirects, connection pooling, protocol upgrades and automatic retries are
disabled for this client. The peer and request body cannot choose an endpoint:
delivery and intake are fixed paths on the admitted HTTPS origin, using the
same retained native relay and generated TLS identity. No bare client escapes.

An intake HTTP response is data, not the final protected-store proof. An actual
completed consumed read establishes known intake completion. No timeout, HTTP
status, read error or local result implies that a request was unsent.

## Lost acknowledgements and restart

`continue_prepared` operates only on the same retained, unexpired local future
HTTP owner, before any claim attempt. It never repeats prepare. If the prepare
response was lost, an explicitly labelled completed recover proving prepared
may supply the first completion; another completed read supplies the second.
Both retain exact same native ownership and original expiry. They are not
relabelled as prepare, and expiry is not extended.

Once claim has been attempted, even a recovered `claimed` row cannot authorize
contact. Once intake has been attempted, it cannot be resent or replaced.
Subsequent `recover` calls have fresh recovery-only processing allowance under
the independently current policy; they do not change the original action's
deadline. The stable deployment/canary/logical-instance head prevents a new
batch ID or boot from bypassing unresolved state.

A completed consumed read may settle an attempted original only while this
same process still retains that exact original and the current head names it.
This releases the local unresolved slot without creating another contact.
Fresh recovery requires its current delivery policy, not a renewed or live old
intake window; creating a new intake still requires current intake permission.

The required `recoveryTargets` array contains at most sixteen exact selectors
`canaryId`, `slotId`, `httpSha256`, `partCount`, `originalExpiresAtEpochNs`.
Startup invokes the actual recovery signer/transport and retains completed
observations. Selectors alone are never authority. The controlled writer must
admit genuine current/historical assignments and any new-boot association.
Cold recovery does not reconstruct a pending sender, expected consumed head or
lost contact permit, even when history says prepared or claimed. It does not
replace an old native boot with configured strings. Root/cohort migration and
continuing a consumed lineage under a new boot still need an explicit successor;
they are not silently granted by this observation profile.

## Completion verification

`native_canary_delivery_v1::Completion` has a private constructor and is not
cloneable. Its verifier retains the exact runtime request/response strings and
checks the independent root-signed full configuration, verifier signature,
exact sent command, source/cohort/manifest identity, planner identity/signature,
typed request and business intent, actual executor receipt/result, external
witness signature/reservation/fence/generation/head, and original time bounds.
No HTTP boolean or SELECT is promoted into a writer receipt.
The native verifier independently reconstructs the exact source-fixed handler
contract (dependencies, grants, templates and budgets), and checks the committed
claim's exact evidence and both retained completion-original commitments.

The purpose-only radix verifier checks every selected key/full row, absence
proof, shared before prefix, all 64-by-16 sibling vectors, mutation template,
full-row CAS, exact root inventory, revision/count delta, union ancestor
recomputation and original work metrics. The source table inventory is fixed,
not learned from untrusted rows. It verifies the complete before/after roots
against the actual executor and external terminal originals. Prepare mutations
prove the written original; the separate completed recover's selected rows and
before proofs prove persisted readback. All immutable parts must reassemble to
the exact original; matching a parsed object or a caller-supplied digest is not
enough. Consumed historical slots may coexist with a later current head but
can never be converted into current contact permission.

One concrete prerequisite correction was required at this producer/consumer
join: A23 delivery specifications wrote the audit outbox without declaring the
actual global audit-capacity counter. The genuine planner rejects that missing
counter contract. This slice adds the existing protected aggregate root, exact
UPDATE template and `aggregate-high-water` primitive to those three operations.
Native verification therefore checks seven real roots. The existing 48/24
business limits plus one framework row/mutation remain 49/25; no global proof
or transport ceiling is raised. The held A23 tree remains unchanged.

## Bounds and remaining work

Original intake HTTP remains at most 1,245,184 bytes; delivery requests at most
3 MiB; each retained prepare/read completion at most 768 KiB; the combined claim
originals at most 1,536 KiB; complete HTTP and signed-runtime responses at most
6 MiB. Segmentation remains exact reassembly of one immutable original and one
atomic preparation, not effect batching or partial acceptance. Native cold
configuration original is capped at 3 MiB. Native proof processing retains
bounded rows/mutations/depth/nodes; its whole proof snapshot must fit the same
6 MiB consumer ceiling. Oversized originals refuse, not silently truncate.
Each native client retains at most 256 delivery-attempt IDs and 64 intake slots
without eviction or reset. These are explicit temporary capacity limits, not
production-scale lifecycle completion.

Remaining source work includes the twelve genuine producers and automatic
callers: assignment, canary revision, load receipt, runtime-attestation handoff,
custody, ingress, active decision, shadow observation, instance revision,
checkpoint, compiler analysis, and readiness. Each must emit its actual
independently signed original under its real key/service/closure owner. No
fixtures or local success flags replace them. Protected Setup continuation,
canary-based onboarding, measured JIT and final proxy-ready receipt remain
separate required joins. Independent root/assignment/TLS/relay provisioning,
capacity/migration work and authorized runtime acceptance are also open.
