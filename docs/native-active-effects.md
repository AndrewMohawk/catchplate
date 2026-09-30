# Required native ordinary-request effects

This is source implementation, not a tested, deployed or provisioned pilot.
An allowed ordinary authenticated HTTPS GET still calls `record_dispatch_barrier`
and prepares a `ProviderSend` effect. Credential generation/lease/decrypt,
optional OAuth rotation, and actual injection also need real effect permits.
Removing JIT, quota, custom-header and durable-budget options does not remove
these calls. The required path now has explicit native producers and consumers.

## Closed selection and independent owners

The new bridge is `nativeProofBridgeLaunch/v5`, production runtime `/v9`, with
`nativeSpoolServices/v3` exact five fields: `apiVersion`, `headGrantOriginal`,
`currentGrantOriginal`, `originFdName` (exactly `generation-origin`), and
`cleanupGrantOriginal`. Head and current originals must be version 3; cleanup
is `nativeActiveEffectCleanupGrant/v1`. Head is at most 65,536 bytes; current
and cleanup are each at most 131,072 bytes. Whole messages remain at most 8 MiB.

Three separate admitted and inspected children own `DispatchBarrier`,
`ActiveEffectBarrier` and `ActiveEffectCommit`. Their independently assigned
Ed25519 keys are never co-loaded, derived from another role, or given HMAC access.
Their closed 17-field supervisor-signed grants retain the existing spool scope,
key authorization, exact Guest/C9 identity, original lifetime, current trust
checkpoint and revocation pins. Each has `commitRequest:null`. New launch fields
are `dispatchBarrier`, `activeEffectBarrier`, and `activeEffectCommit` respectively.
The source-fixed purposes are `native-dispatch-barrier`,
`native-active-effect-barrier`, and `native-active-effect-commit`.

The existing independently assigned Ledger, Ingress and Terminal owners remain.
Retrieval launch `/v4` selects retrieval grant `/v3`, with the exact three new
public role pins. It does not obtain any other role's private key. The paired
fixed-eleven parent cohort retains all real child identities, original deadlines,
release, inspection and cleanup ownership. Old eight/seven/six/five profiles do
not gain these capabilities.

Ordinary launch `custodyOrdinaryServiceGuestLaunch/v6` and
`--guest-c9-effects-inspected` select ordinary service runtime `/v8` for DRS,
CurrentSignatureAuthority and CleanupAuthorizationConsumer. DRS and current keep
their actual dispatch/spool resources. Cleanup adds exactly
`active-effect-cleanup-grant` and `active-effect-cleanup-journal`; it has no HMAC
or CommitRequest grant. All three still require their real generation gate.

## Actual producer-to-consumer path

1. The existing gate caller supplies its retained preparation or one-use sealed
   permit under the original operation, replay identity and deadline. It cannot
   supply an arbitrary verified result, invented generation, or grant-selected head.
2. DRS checks the actual initialized generation/opening and existing pending
   work, then durably allocates one fixed effect step in its existing shared
   journal. Effect history is a separate typed head: it does not skip spill-ledger
   ordinals. Its initial domain-separated identity includes the real admitted
   generation origin and authoritative ledger predecessor.
3. The assigned native effect owner independently verifies the signed allocation,
   current grants and any actual earlier cleanup-sealed permit. It retains the
   exact preparation before contact. A separate typed `nativeActiveEffectCore/v1`
   is signed and stored by the real retained retrieval writer.
4. Retrieval performs exclusive creation, file/directory synchronization,
   fs-verity and held-original readback. Ledger and effect objects share one
   sequence, lock, existing 128-object bound and 32 MiB aggregate budget.
   No extra store or doubled allowance is created.
5. The native signer verifies the real storage original and signs the complete
   final barrier/commit receipt, including actual storage references. Storage
   addresses the domain-separated core, not the final receipt containing those
   references; no self-referential or guessed receipt hash is used.
6. Cleanup independently verifies the native completion and genuine DRS
   allocation, journals its own issue/consume transition, and only then exposes
   a sealed `ActiveEffectPermit` or consumed completion. The sealed issuer is
   **CleanupAuthorizationConsumer**, not DRS or the native signer. Commit and
   reconciliation require the exact previously retained barrier/reference once.
7. DRS consumes that actual cleanup transition and journals completion. Current
   validates DRS's genuine completion and journals its own transition. The native
   owner requires all three service originals. The bridge then commits the exact
   native request/response through the actual persistence endpoint before
   returning it to the existing independent gate receipt verifier.

The native storage signature uses `nativeActiveEffectStorage.signature/v1`;
preparation, allocation, completion, retrieval identity and retrieval proof each
have their own fixed domain. Existing active-effect receipt domains and existing
production sealed-artifact/service-transition signatures are unchanged. Full
originals, not schema shape or cached success, determine permission.

Dispatch spill reservations remain signed by LedgerAppend, as the existing
reservation verifier requires. The actual DispatchBarrier append is separately
signed by DispatchBarrier. The real DRS spool head joins both roles. A dispatch
reservation at the unchanged regular-append ceiling refuses closed; it does not
return an unavailable spill bearing Ledger's key in place of DispatchBarrier.

## Failure and remaining boundary

Only the required credential-generation, credential-lease, credential-decrypt,
credential-injection, OAuth-rotation and provider-send effect kinds are admitted
by this profile. This is not a new implementation of JIT, quotas, durable budgets,
Gmail sub-operations, range sealing or compaction.

Every original deadline remains absolute. The bridge fences itself before first
contact; journal/storage owners retain unknown or partial work and never roll it
back into reusable authority. Reconciliation can report only the existing signed
`ReconcileRequired` condition for an actual retained permit. It never infers
Committed/Aborted from timeout, absence, or restart. If no genuine barrier exists,
reconciliation refuses rather than inventing one. Lost completion does not
authorize repeating the external business effect.

Independent signed provisioning, trusted guest/driver admission, protected facts,
final Setup verifier packaging, and connected build/runtime acceptance remain
separate prerequisites. No key was generated, no grant signed, and no build,
test, provider contact or runtime acceptance was performed for this source batch.

The closed data contract is [native-active-effects.v1.schema.json](../schemas/native-active-effects.v1.schema.json).
The separate cleanup-owner details are in [native-active-effect-cleanup.md](native-active-effect-cleanup.md).
