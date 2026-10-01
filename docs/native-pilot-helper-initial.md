# Fresh helper initialization and bridge launch preparation

The `.386` source adds an explicit fresh-helper startup path and a pure
bridge-launch adapter. Verification is **pending** at this freeze: no focused
test, native compile, protected initialization or connected pilot result is
claimed here. Supervisor coverage stays **127/136** in the current inventory,
with **108 selectors**, source checkpoints **36/46**, and production acceptance
**0/6**. The inventory still omits prerequisite ceremonies; it is not a readiness
percentage or a complete count of remaining work.

## Four authenticated helper roles

`serverware.policyCustodyServiceRuntimeConfig/v9` selects only the bounded
cleanup helper. Its existing flat runtime gains `initialEndpointHistories` and
`initialEndpointPins`, each with exactly four source-ordered roles:
`settlement-store`, `fence-authority`, `cgroup-executor`, `termination-ledger`.
Older service profiles retain their closed fields and behavior.

The [history validator](../serverware/native_pilot_ordinary_initial_profile.py)
authenticates four separately signed initial wrappers under the approved root.
Each uses the existing checkpoint and three-party retained-anchor ceremony;
one role's signature or identity cannot be relabeled for another. Shared
process, original window, directories, generations and public keys must agree,
while the role-specific identity/checkpoint commitments differ. Each literal
wrapper is bounded to 1 MiB; the complete runtime keeps its existing bound.
The primary history remains an exact member, not a newly reconstructed wrapper.

The [flat runtime validator](../serverware/native_pilot_ordinary_runtime_profile.py)
binds each pin to its actual member identity, checkpoint, listener, public
verification credentials and approved zero-consumed cursor. Every consume
predecessor must differ from **all four members'** typed initial-history
commitments. Neither those commitments nor the selected starting cursor are
historical receipts. Native admission repeats signature/key joins and real
process, executable, original-window and empty-directory checks before opening
the generation/helper journals.

## Eight requests, separate currentness decisions

The [retained request owner](../serverware/native_pilot_initial_requests.py)
now exports `nativePilotInitialTrustRequests/v2`: one genuine request for each
of the four other ordinary services, plus four role-specific helper requests.
It authenticates the complete selection before sampling entropy and one fixed
issuance time; subsequent reads recheck the same retained owners and originals.
Request deadlines are clipped to the original startup/checkpoint limits and
the earliest authentic ordinary generation-grant expiry, never extended.

`nativePilotCurrentHeadAuthorityInput/v2` adds explicit `endpointRole` and
`runtimeOriginal` for the helper, binding the selected literal member and pin.
Its [shared preparation](../serverware/native_pilot_current_head_profile.py)
still requires an independently approved, request-bound currentness decision.
Old signatures do not establish that no newer checkpoint exists. Input/v1 and
the legacy positive-consume floor remain unchanged.

The [handshake builder](../serverware/native_pilot_service_handshakes.py)
verifies the actual signed current-head result before framing the later native
handshake. Its digest includes the signed head and is distinct from the earlier
trust-request digest. Framing neither transmits a packet nor proves readiness.
Bridge-preparation/v2 binds all eight original requests and the helper's exact
ordered four handshakes; repeating one head cannot satisfy the role set.

## Empty journal, durable installation, durable seal

The unsigned
`serverware.policyCustodyCleanupHelperInitialBootstrap/v1` manifest has eight
closed fields: `apiVersion`, `initialization: "fresh-helper"`,
`operationGeneration`, `sharedConfigurationSha256`,
`serviceConfigurationSha256`, `initialEndpointHistorySha256`, `deadline`, and
`manifestSha256`. The [public builder](../serverware/native_pilot_helper_bootstrap_profile.py)
derives literal runtime/history hashes and the domain-framed manifest digest;
that is approved initialization data, not evidence that a journal is empty.

The actual [native receiver](../data-plane/decision-gate-rs/src/policy_custody/services/helper_initial.rs)
and [helper server](../data-plane/decision-gate-rs/src/policy_custody/services/bounded_cleanup_helper.rs)
perform the following sequence over the authenticated existing connection:

1. `InstallInitial` requires the admitted runtime/history/role pins, original
   deadline and an actual journal head of `None`. The exact request and reply
   are durably appended before the receiver retains installation.
2. `SealInitial` uses that actual persisted journal head. Its exact request and
   seal reply are durably appended before the receiver retains the seal.
3. Only then are the four ordered helper handshakes admitted. The production
   bridge performs both exchanges before sending those handshakes.

Peer revalidation, bounded polling and the minimum of the original startup and
approved bootstrap deadline surround the exchanges. The bootstrap deadline is
itself bounded by the retained requests and their original grant limits. No
clock window is renewed. This initial seal is not a fabricated effect manifest,
cleanup result or worker-reaping proof; legacy effect-manifest bootstrap remains
separate. Actual `ReapWorker` still requires genuine worker PIDFD acquisition
and retained parent/subreaper registration/proof. This batch does not supply
those capabilities or claim a successful cleanup operation.

## Explicit bridge successor and public launch adapter

Production runtime/v11 adds required `helperBootstrap` to the v10
`ordinaryInitialHistories` path, and only bridge launch/v7 selects it. The
retained native selection distinguishes v10/v6 from v11/v7 through parent,
cohort, proof-client and driver readers. Both successor runtimes retain the
4 MiB ceiling and selected 16 MiB bridge-input ceiling; legacy limits and field
closures are unchanged.

The [native history adapter](../data-plane/decision-gate-rs/src/policy_custody/services/production_initial_history.rs)
now decodes the actual five closed, **flat** ordinary runtime types instead of
expecting a nonexistent nested `service` object. Literal runtime, history,
root-signed generation grant, guest and scope joins still apply. Runtime/v11
also binds the helper manifest and exact ordered handshake roles.

The [bridge-launch adapter](../serverware/native_pilot_bridge_launch_publication.py)
backs `prepare_bridge_bundle` and `checked_bridge_result` in the existing launch
module. It verifies actual C9/key/admission originals and reuses the installer's
public closure/encrypted-delivery/verifier/TrustedTime checks, preserving
`nativeShadowRoleKeys/v2`, the original bootstrap key transport and exact time
bootstrap. It derives nine fixed public pins, including launch last, without
republishing runtime. It does not write files, create an owner, sign, contact
KMS or prove installation. The ten-role endpoint adapter remains endpoint-only.

## Remaining connection and verification

Supervisor role-specific initial ceremonies and independent currentness
composition are still missing. So are the complete bridge runtime/delivery/
late-authorization/launch composers, fixed phase-two public publisher and later
release/constructed/origin/stop connections. See the
[bridge assembly map](native-pilot-bridge-assembly.md). The existing full-coverage
startup guard stays closed; no new composer is counted by this batch.

Executable packaging, independent credential/service provisioning, the four
external signer services, real cleanup capabilities, connected runtime/provider
and hardware acceptance, approved dependency/provenance evidence and release
gates remain separate requirements.

### Focused verification

Pending at source freeze. Authored synthetic controls and source review are not
executed test results, compilation, journal durability evidence or live pilot
acceptance. Exact measured results will be recorded after the assembled pass.
