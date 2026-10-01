# Retained bridge preparation and authorization producers

The `.385` batch connects initial trust-request acquisition and peer preparation
to the actual conductor, and adds four bridge-specific authorization producers.
It does **not** add a supervisor composer or make the pilot runnable. Coverage
remains **127/136**, with **9 missing**, **108 selectors**, **36/46 source
checkpoints** and **0/6 production acceptance gates**. The
[focused checks](#focused-verification) pass across the initial run and one
fixture-only recheck; live ownership and bridge operation remain unverified.
These counts describe the current inventory; the remaining bridge signature
and role-complete helper prerequisites still need explicit job slots.

## Initial requests from actual owners

[InitialRequests](../serverware/native_pilot_initial_requests.py) accepts only
the actual retained pilot, ordinary launcher, generation inputs and business
resources. It checks all five admitted runtime/history/grant associations,
preparation and empty-directory originals before sampling one issuance time
and one entropy buffer. It preserves the approved zero-consumed cursors from
the authenticated runtime/checkpoint subjects; it creates neither a consume
receipt nor a replacement predecessor. The legacy positive-consume floor is
unchanged.

The public `nativePilotInitialTrustRequests/v1` export retains all five exact
`current-endpoint-trust` requests, their native domain-framed digests and the
original runtime/history/checkpoint/launch/resource pins. Each deadline is
bounded by the original startup window, checkpoint validity and earliest
authenticated generation-grant expiry. Rechecks also enforce that earliest
expiry. Missing or conflicting cursor coverage fails before entropy sampling.

Preparation sends nothing and signs nothing. A checkpoint authority must still
independently establish currentness and approve the exact retained request
before the [current-head producer](native-pilot-bridge-prerequisites.md) signs.
Trust-request digests remain distinct from later handshake digests containing
the signed head. The owner is one-attempt and one-use; failed preparation is
retained until the real pilot's terminal cleanup.

## Observations versus approved expectations

The real ordinary launcher, native endpoint cohort and driver/gate expose
`peer_preparation_original(profile="retain-observed-cgroup")`. Their
[private resource owner](../serverware/native_pilot_peer_resources.py) retains
duplicate PIDFDs, exact target-executable descriptors and cgroup capabilities.
Native parked targets are opened from the actual child's retained, sealed
executable descriptor, not a metadata-only caller path. The gate's executable
comes from its real executing process. Capture hashes each target once; later
checks revalidate retained descriptors and identity, including native executable
seals, rather than rehashing every binary. Ordinary targets have the existing
fs-verity requirement. The executing gate is checked for metadata/executable-
identity drift but is not required by this owner to have seals or fs-verity.

The exact `nativePilotPeerPreparation/v1` export distinguishes
`parked-pre-exec` ordinary/native peers from the `executing-gate`. It records
PID/start, PIDFD identity, target device/inode/length/hash and actual cgroup
path hash/mount/inode. The selected profile refuses cgroup migration. It does
not claim that parked children have executed, are ready, or have final labels.

The [composite preparation](../serverware/native_pilot_bridge_preparation.py)
joins these observations to the initial requests and original driver observation.
The actual [phase executor](../serverware/native_pilot_phase_execution.py) binds
runtime/v10's expected peers to those retained facts and prior admitted UID/GID,
using the native v4 process-identity framing. Security-label and configuration-
generation values remain independently approved final-state expectations;
native connection inspectors still verify actual peers after execution.
The four external signer peers are not these children and cannot be substituted
with their observations.

The [operator](../serverware/native_pilot_operator.py) captures this preparation
after real service admission, carries `bridgePreparationOriginal` in the
bridge-runtime request, rechecks it around subsequent approval exchanges, and
consumes it immediately before release. Cleanup follows the actual pilot's
terminal cleanup. Public DTOs and shape checks cannot construct live owners.

## Four bridge-only authorizations

The [bridge key profile](../serverware/native_pilot_bridge_key_profile.py) and
[authority](../serverware/native_pilot_bridge_authority.py) implement
`role-keys`, `admission`, `encrypted-delivery` and `verifier-transport`.
Inputs must be independently approved complete originals: original driver
control/window, actual bridge C9, authenticated assignment/closure/trust,
measured recipe/configuration and explicit policy. The production binding is
rederived with the same pure native-field recipe used by the actual measured
configuration owner; a caller-supplied digest alone is insufficient.

Admission binds the actual preceding role-key original. The two later decisions
revalidate that authenticated pair. Encrypted delivery uses only the original
bootstrap `continuation.keyTransport` and bound ciphertext metadata; it cannot
accept a replacement KMS transport. No private key, ciphertext, attestation,
currentness decision or verifier service is generated. Endpoint-only producers
remain restricted to their existing ten roles.

The fixed [protected-FD command](../scripts/authority/sign_native_pilot_bridge_authorization.py)
signs exactly one selected operation with an existing supervisor key. Exact
input identity, boot, monotonic deadlines and UNIX intervals are rechecked.
Complete output and successful exit are both required; uncertain output grants
no retry. A digest is not approval, and software key handling is not hardware
custody. Existing signature formats are preserved; later bridge launch assembly
must use the existing `nativeShadowRoleKeys/v2` wrapper, not invent a new wire.

Closure and constructed-driver readers also select runtime/v10's explicit
larger bounds and launch/v6 while retaining legacy limits. Their outer retained
aggregate budgets are unchanged. No native source changed in this batch.

## Remaining work and verification boundary

The next connected work is a retained bridge-runtime composer with explicit
currentness approval, final peer policy, credential bindings and four external
signer selections, followed by actual bridge C9/launch composition. Fixed
phase-two public publication and release/constructed/origin/stop continuations
also remain. See the [nine-composer map](native-pilot-bridge-assembly.md#remaining-nine-composers).
Next-slice source review identified a prior requirement: the helper must first
bootstrap its actual durably sealed effect manifest, which determines its
possibly multiple endpoint roles. This batch's single request per service is
insufficient for that multi-role path. Resolve role-indexed request/history/
currentness coverage and native bootstrap-before-handshake ordering before
claiming a complete runtime composer. See the
[concrete source gap](native-pilot-bridge-assembly.md#helper-bootstrap-precedes-complete-handshake-composition).
Independent provisioning, immutable dependencies/release provenance, Nitro/KMS,
provider/hardware ceremonies and full connected allow/deny/cleanup acceptance
are not replaced by these source changes.

Four new suites contain 32 focused controls over synthetic signed originals,
public grammar, associations and refusals. They do not exercise genuine kernel
owner capture, protected signing commands, actual service launch or full native
bridge admission. The composite fixture is intentionally a bounded grammar/
binding fixture, not a fully authenticated operational runtime. Unchanged
native and release artifacts were not rebuilt; no cloud or paid action ran.

## Focused verification

Exact source `cd38e7f9afe42b2d01d9739633cfdb8565d305b3` ran **189 controls in
23 suites**: **186 passed**, with three errors in the new bridge-authorization
suite. Its fixture used two shorthand service names that the actual outgoing
selector correctly refused. The other 22 suites passed. The first isolated
Python **3.11.15** run exited **1**, from `2026-10-01T02:20:17.959770231Z` to
`2026-10-01T02:21:09.998104941Z`.

`4ddc77df5e78f80ecc960fbdf3a66e75be8f01e8` corrects only those fixture names
to `cleanup-authorization-consumer` and `recovery-target-provider`. No production
code or admission check changed. All **8 targeted rechecks passed**, with
**22-file Python 3.11 grammar/both Make inventories** and **57 relative links**.
Exit was **0**, from `2026-10-01T02:23:38.327894577Z` to
`2026-10-01T02:23:41.909756388Z`; the suite reported **2.473 seconds**.
The final commit did not rerun the 22 unchanged passing suites.

Both exact source archives, harnesses, commands, logs, structured results and
checksums are retained at
`codex-offload/serverware/engineering-builds/4ddc77df-bridge-preparation-ASPOkl/`.
The final archive is **85,790,720 bytes**, SHA-256
`0587bea3b78e2593a804db3eb3cbd751276dd71103567990af033ab0812ef1b4`.
All 16 retained-file checksums passed, and the copied checksum manifest matches
the original. These checks use the existing unpublished dependency candidate. They invoked
no DB/app/authority-store modules, protected signing commands, live owners,
installers, services, providers or hardware and do not qualify a release.
