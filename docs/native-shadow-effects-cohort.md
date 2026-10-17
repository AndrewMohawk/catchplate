# Native request-effect service launch

The fixed-eleven profile connects the DispatchBarrier, ActiveEffectBarrier and
ActiveEffectCommit signers to the existing native ledger and actual ordinary
DRS, CleanupAuthorizationConsumer and CurrentSignatureAuthority. These are
required by the ordinary authenticated request path, not optional agent features.
This is source implementation; build and connected pilot acceptance are pending.

## Fixed owners

`nativeShadowProofCohortConfiguration/v6` retains the first eight children and
adds `dispatchBarrierConfiguration`, `activeEffectBarrierConfiguration` and
`activeEffectCommitConfiguration`, in that order. Every child has a separately
pinned cold C9 original and distinct non-root UID/GID. The signed boot,
invocation, startup and lifetime remain unchanged. Old profiles retain their
exact inventory and cannot admit the extra roles.

| Owner | Explicit selection |
| --- | --- |
| Bridge | `nativeProofBridgeLaunch/v5`, production runtime/v9, spool/v3 |
| Retrieval | `nativeShadowRetrievalGuestLaunch/v4`, retrieval grant/v3 |
| Ledger/CommitRequest | existing launch/v3 and service assignment/v2 |
| TerminalAppend | existing terminal launch/v1 |
| DispatchBarrier | `nativeShadowDispatchBarrierGuestLaunch/v1` |
| ActiveEffectBarrier | `nativeShadowActiveEffectBarrierGuestLaunch/v1` |
| ActiveEffectCommit | `nativeShadowActiveEffectCommitGuestLaunch/v1` |

The three new launch pin fields are respectively `dispatchBarrier`,
`activeEffectBarrier` and `activeEffectCommit`. Each new signer has exactly its
independently assigned signing role, not the request HMAC. The observations,
release, cleanup authorization, terminal observations and cleanup result use
version5. Release/cleanup use their distinct version5 signature domains.
The existing 32768-byte packet and aggregate 128-rights ceilings are unchanged;
an inventory that cannot fit refuses before release.

## Actual resources

`SpoolInputs` retains three additional listeners and their directories at
`/run/catchplate-shadow-{dispatch-barrier,active-effect-barrier,active-effect-commit}/listener.sock`.
The corresponding child receives the fixed `<slug>-listener` activation and
the Bridge receives `<slug>-peer-directory`. Listeners use the actual child UID
and bridge GID, credentials and PIDFD receipt. Existing socket paths are refused,
never unlinked, repaired or adopted. Retained identities are checked and resource
closure follows actual child reaping.

The native bridge selects all six actual native signers, retaining nine other
ordinary outgoing endpoints: eighteen actual socket/directory descriptors.
`OperationalInputs.prepare_outgoing` joins their exact C9 inventory and purpose;
direct old launch selection does not silently enable the effects profile.

## Ordinary effect owners and grants

`FiveServiceLaunch.start_effects()` reads only the protected
`/etc/catchplate/custody-effects-five.json` and configuration/v6. It uses the
existing real five-service business resource owner. Its DRS, Cleanup and Current
children use runtime/v8 and `--guest-c9-effects-inspected`, with independently
supplied final peer inspection. The other two services keep their existing
generation-only profile. No synthetic process identities or root connections
are substituted for post-drop admission.

DRS and Current retain their actual generation and dispatch resources plus
spool head/current grant memfds and journals. Cleanup receives an actual
`active-effect-cleanup-grant` memfd and `active-effect-cleanup-journal`, but no
dispatch grant or HMAC. The producer seals each genuine grant once, verifies
readback and retains the descriptor before publishing the exact guest launch.

Head grant/v3 contains the three separately assigned signer keys/grant digests
and the independently supplied Cleanup epoch, public key and initial transition
head. Current grant/v3 embeds that exact head original. Cleanup grant/v1 embeds
the same head and DRS epoch/key; the head does not embed the Cleanup grant.
This avoids a circular digest dependency. Bridge selection/v3 retains all three
originals, including `cleanupGrantOriginal`. Retrieval grant/v3 binds the same
three role keys and unchanged completion policy/scope. Release requires the
exact seven native grant originals and all eleven actual transfers from the
same retained cohort.

The [actual effect chain](native-active-effects.md) is DRS allocation, fixed-purpose native signature,
retrieval persistence, Cleanup durable seal/consume, DRS/Current durable
transition and the same-owner reply. The Cleanup owner, not the native signer,
seals the cleanup permit. Unknown outcomes remain fenced under the original
deadline. Cohort process cleanup is not business Commit/Reconcile settlement.

## Evidence boundary

These connections do not claim a measured Linux host, installed production
authority, successful request or verified pilot. Independent service/key/image
provisioning and the connected acceptance pass remain required. Optional JIT,
quota and compaction functionality retains its separate scope.

Schemas: [eleven-child cohort](../schemas/native-shadow-proof-cohort.v6.schema.json)
and [ordinary effects inputs](../schemas/custody-effects-inputs.v1.schema.json).
Broad builds and tests are deferred until the connected pilot implementation
is assembled; no runtime, signing or paid cloud activity is asserted here.
