# Protected native policy activation

This explicit profile connects complete native readiness to a real two-person
approval, native custody publication and protected current-policy publication.
It does not create Fleet envelopes or change legacy Fleet activation semantics.
The source is unbuilt and runtime acceptance remains outstanding.

## Authority and effect ownership

`policyCanaryNativeActivationPolicy` is a separate optional field in the actual
root-signed authority configuration/v6. It pins exact canary/assignment pairs and
the real independently assigned custody publication public keys. All five
`native-policy-activation.*` operations must be explicitly enabled. The HTTP
owner borrows the existing canary intake cold public root/config originals, not
its intake permission. Their full configuration digest must equal the actual
cold controlled-writer binding. No new authority key or deployment is created.

The real final readiness intake is independently re-derived from complete
authenticated current populations at request, approval and consume. Missing
final seals, detailed observations, classifier facts, current keys or complete
coverage refuse activation. Original readiness expiry and checkpoint are kept;
a later browser request never supplies a renewed clock or root.

The legacy `policy_canary_heads` composite foreign key remains unchanged. A real
same-row CAS retains its sealing predecessor, while `policy_native_canary_ready`
and `policy_native_canary_heads` own the new READY and active association. No
invented legacy signed revision satisfies that foreign key. Both real protected
writer implementations refuse later legacy-head changes for this association.

## One native contact and a real hold

`POST /api/policy/authority/native-activations/draft` produces source-derived
argument originals for `phase=request` from `readinessRequestId` and the exact
`generationPublicationEnvelopeSha256`. Other drafts select an actual
`approvalId`; `record-inclusion` additionally retains the real `nativeRequest`
and returned `publicationOriginal`. Every body has the fixed
`catchplate.nativePolicyActivationHttp/v1` label. Drafts are not permission.

The actual OIDC actor must have literal `policy_publisher`, with normal CSRF and
a current trusted hardware WebAuthn credential. `/options` binds its challenge
to the exact phase and arguments. The requester uses `/request`, a distinct
publisher uses `/decide`, and the original requester uses `/publish`. Request
and decision audit rows must really be completed before consume; a transition
digest is not an audited event. The actual consumed approval retains the three
assertion provenance digests and exact original intent.

`/publish` owns a fresh protected `native-policy-activation.consume` PREPARE and
then precisely one authenticated management request to the fixed
`/v1/policy-shadow/native-activations` route. It passes the actual signed runtime
request/response originals, not a caller preparation DTO. The management URL and
token are the retained existing configuration, never browser-selected. Genuine
custody completion is HTTP 201 with the direct signed publication envelope.
The complete request/response handoff stays within 8 MiB, including escaping;
the publication envelope is at most 32 KiB. No generic frame is enlarged.
Before committing PREPARE, the actual planned post-state is also used only for
conservative byte accounting: the later receipt-inclusion input, including its
duplicated business-intent arguments, must fit the existing 4 MiB controlled
request bound. This projection is never a substitute for later current roots.

PREPARE is not itself a current-root lease. The same protected transaction
inserts/CASes the exact `policy_native_activation_holds` row to `held`. Both
actual admitted SQL execution paths take an exclusive lock on that fixed
relation before business mutations, including absence. While held, unrelated
business/authorization changes are fenced. Only source-fixed audit bookkeeping,
the exact owning receipt inclusion and its verified finalization can proceed.
The native verifier requires the real signed hold mutation/root transition and
the pinned source guard contract, not merely the row's shape or guard digest.

This requires independent deployment admission of the actual new SQL function
bodies, protected schema, table roots and least-privilege writer closure. A
privileged bypassing database owner is outside that protected-writer trust
claim. Installing only the Python HTTP module does not establish the hold.

Original native expiry restricts contact; it does not unlock the hold. A lost
ACK, timeout, crashed caller or expired readiness never permits retry, automatic
abort or new publication. No route accepts an old PREPARE for another contact.
Read-only `/lookup` returns actual approval/preparation/finalization/hold rows
with `okForAction:false` and `automaticRetryAllowed:false`. Unknown effects stay
held; operator recovery cannot pretend they are absent or successful.

## Definite settlement and real consumers

After a definite reply, `/record-inclusion` verifies the exact request5 and
publication17 signature, assigned key, original interval, prepared24, old/new
publication tuples and request hash. It stores the original once, with a new
audit outbox event. It never calls the native service. `/finalize` waits for the
actual request, decision, consume and inclusion audit rows to be completed,
then atomically advances the real policy high-water, committed publication,
native head and held-to-published row. Settlement can retain an expired original
only to record that already definite in-window effect; it creates no new native
contact or deadline. It preserves the original independently approved policy.

Both the complete-root current-policy reader and the genuine policy-file
materializer's retained PostgreSQL read-lock function resolve this explicit
native association. They require real native receipt/preparation/finalization,
the unchanged sealing predecessor, candidate artifact and completed audit
originals. The old branch is unchanged. A native journal publication is not
silently called CP active; only protected finalization changes the CP head.
Neither branch claims application enrollment, proxy readiness or fleet-wide
runtime acceptance merely from publication.

## Operator portal

The normal operator dashboard includes a separate **Native policy activation**
section beneath controlled candidate generation. Select an explicit phase, read
its current source-derived draft, review the exact intent/original, and confirm
before submitting. Request, distinct-operator approval and publication each use
a fresh hardware ceremony bound to the unmodified server-provided arguments.
The existing cookie-only OIDC session and CSRF controls apply. A local deadline,
actor/selection checks, bounded lossless JSON and exact original strings prevent
nanosecond rounding or an edited selection from silently changing the request.
Data-only human review is bounded to five minutes and, for approval/publication,
the unchanged original intent expiry. A subsequent actual action has a fresh
at-most-30-second transport window and revalidates server authority; longer
review never renews publication permission. Settlement has its own current
operation and cannot repeat the earlier native contact.

Before requesting approval, the portal obtains `/request-locator` for the exact
reviewed `argumentsOriginal`. The server uses the same request commitment and
deterministic approval-ID function as the protected transition. Its closed
`nativePolicyActivationLocator/v1` result contains the actor, activation,
readiness and approval IDs plus argument/request digests, with both action and
retry flags false. It creates no approval, reservation or hardware challenge.
The actual action still requires fresh hardware and all protected checks.

Immediately before effect submission, the browser stores this nonsecret hint
under the requester and readiness IDs, followed by its submitted-phase marker.
If storage fails, no effect is sent. A lost HTTP reply populates the predicted
approval ID; after a same-tab reload, enter the original readiness ID and use
**Restore this requester's submitted approval ID**, then the separate read-only
lookup. The hint is untrusted navigation data, not proof of commitment. Lookup
requires the actual actor association; a missing row, cleared storage or missing
hint never authorizes a replacement request. A successful request must return
the same approval ID and request commitment as the pre-contact locator.

The publication handoff stays in page memory for a separate receipt-inclusion
step. Its signed operational evidence must be kept private; it is not a replay
capability. Browser storage never contains passkey assertions, argument originals
or PREPARE evidence. Read-only lookup and locator restoration do not clear phase
markers or seed a new publication. Recovering a lost native publication reply
uses the [read-only journal exporter](native-policy-activation-recovery.md) when
the exact request and signed receipt both survive. Portal import is review-only;
partial journals remain unresolved. Receipt inclusion and finalization are
explicit, audit-gated steps; no action runs automatically.

## Frozen original contract

The paired schemas are `native-policy-activation.v1.schema.json` and
`native-policy-activation-custody.v1.schema.json`. PREPARE uses the distinct
`policyAuthorityNativeActivationRuntimeResponse/v1`: exact result9 and
`activationOriginals` exact5 (signed measured plan, executor completion, witness
request/response and actual effect hold), all raw canonical ASCII. The native
request is exact5 and prepared original exact24. Custody independently verifies
the source-fixed complete SQL populations and roots, full planner/executor/
witness proof, approval/assertion and hold, under its own admitted trust/time/
generation owner. Existing trusted-host attestation consumption is not relabeled
as produced TEE evidence. The real separately admitted native publisher signs
only after atomic journal CAS, file/directory fsync and original readback; its
receipt is also durably retained before reply.

Finite limits remain 32 rows per complete table, 240 declared canary population
rows and the unchanged 256 total query-proof ceiling. Actual extra approval,
role, audit, WebAuthn and capacity queries are charged before acquisition; an
oversized complete population refuses rather than truncates. No build, parser,
test, browser, provider or cloud action was performed for this source batch.
