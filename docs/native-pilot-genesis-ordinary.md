# Cold recovery store and signature authority

This continues the [retained cold controller](native-pilot-genesis-authorities.md)
with a distinct two-service startup path. Cold genesis needs a fresh durable
recovery store (DRS) and current signature authority (CSA) before a hot driver
generation exists. The five-service hot launch, generation grant and history
profiles cannot supply that boundary.

This is implementation work, not a provisioned pilot or production acceptance.
Independently approved configurations, signatures and keys are still required.
Parsing an observation does not prove its provenance; actual retained owners
and native admission remain authoritative.

## Explicit contracts

| Layer | Cold selection | What remains separate |
| --- | --- | --- |
| Two-service control | `custodyGenesisTwoServiceLaunch/v1` | Only DRS and CSA; no hot five-service generation |
| Actual preparation and resources | `custodyGenesisTwoServicePreparation/v1`, `custodyGenesisTwoServiceResources/v1` | Actual retained children and empty directories, not supplied PID guesses |
| Initial state and history | `custodyOrdinaryInitialState/v2`, `custodyOrdinaryInitialHistory/v2` | Existing checkpoint and three independent anchor signatures |
| Service runtime | `policyCustodyServiceRuntimeConfig/v11` | Publication-genesis admission only |
| Native guest launch | `custodyOrdinaryServiceGuestLaunch/v7` | Explicit `--guest-c9-genesis-inspected` on DRS/CSA only |
| Coordinator peer preparation | `nativePilotGenesisCoordinatorPeerPreparation/v1` | Observed kernel identity versus independently approved final IDs and labels |

The two-service control and the per-service native guest launch are different
documents. Initial state commits the former's literal bytes; the latter selects
the exact C9 delivery and inspection credential. Neither substitutes for the other.

DRS receives `journal` and `publication-genesis-journal`; CSA receives only
`publication-genesis-journal`. Initial state requires empty, distinct, retained
directories with the selected service ownership. Hot generation, dispatch and
effect journals are not relabeled as cold resources.

## Genuine observations and independent authority

`ParkedGenesisController.peer_preparation_original()` captures the actual
parked coordinator's retained PIDFD, target executable and cgroup. It checks
the sealed target descriptor rather than treating the pre-exec process image
as the future service. The owner rechecks membership and retained resources,
preserves its original time window and retains the handles through real reap.
The legacy peer profiles do not accept this new one-role preparation.

The full approved peer must match those measured fields. Final UID/GID come
from the independently approved cold C9 configuration. Security labels and
configuration-generation commitments remain explicit policy expectations,
not fabricated measurements. Native peer admission still checks the live peer.

Initial-history issuance joins the signed parent precreation, its literal
coordinator observation, actual two-service preparation/resources, approved
service configuration and exact initial state. Root, checkpoint and service
authorities remain separate. Signing and keyless assembly preserve the native
signature domains and original deadlines; no prior receipt or fresh window
is invented. Runtime and grant production consume those same originals.

The Python two-service owner preserves a single-threaded parent. Actual parked
children have absolute kernel startup timers; the selected Rust entrypoint
then owns its original C9 lifetime timers. Resources include real listeners,
empty persistent journals and one-use grant descriptors allocated before C9.
No existing journal is silently adopted, emptied or relabeled.

Cleanup has an explicit remaining boundary: direct parked children can be
reaped through their retained PIDFDs, but a released inspected service has a
separate native inspection helper. Killing the service does not prove that
helper was reaped. The owner must retain capabilities and report uncertain
post-release cleanup until an actual stop/reap protocol supplies that evidence.
Created directory and socket names are retained as evidence, not deleted as
part of a failed ceremony. This is not a restart or recovery implementation.

## Fixed packaged commands

The [packaged entrypoint](native-pilot-publication-commissioning.md#packaged-pre-commissioning-entrypoint)
adds these exact modes, with the existing separately pinned installed package
and public-input descriptors:

- `--sign-genesis-ordinary-checkpoint`
- `--sign-genesis-ordinary-root-anchor`
- `--sign-genesis-ordinary-checkpoint-anchor`
- `--sign-genesis-ordinary-service-anchor`
- `--assemble-genesis-ordinary-history` (keyless)
- `--sign-genesis-ordinary-delivery`
- `--sign-genesis-ordinary-grant`

Each signing mode requires its independently provisioned sealed key descriptor.
The selected operation and approved sources are validated before key access.
Keyless assembly refuses a key. Output is acceptable only after complete bytes
and successful command exit. Package/input reinspection, output and final
closure consume the original BOOTTIME and applicable UNIX intervals.

## Verification and remaining work

Native selector commit `9f24e86e910dadcaed0a513396acb569e7f3777b` passes the
cached, offline Rust 1.88 check for the gate, DRS, CSA, cold controller and
adoption validator (2m47s). The check is CPU/memory-bounded and has no network;
it uses the previously pinned image and vendor cache. It does not run Rust
tests, privileged owners, real signing authorities or a live cold ceremony.
Existing compiler warnings remain. The Python source integration and its
single frozen focused pass are still pending at this checkpoint.

The native publication and retrieval grant originals still require their own
authentic issuers; ordinary grant production cannot create those authorities
from self-described keys. Cold key/closure/encrypted/verifier producers, full
commissioning composition, retained core transfer, adoption-signer ownership,
operational composition and real lifecycle acceptance remain open. Independent
Nitro/KMS, signing, witness, release provenance and provider/hardware acceptance
are unchanged external requirements. Source milestones remain **36/46** and
production gates **0/6**; these are not a claim of pilot readiness.

### Next acyclic issuer order

1. Add a genuine retained cold endpoint owner and C9 source adapter. The
   existing ten-role adapter requires hot cohort/precreation originals and
   cannot be reused by changing role labels. Endpoint image runtimes stay
   static; the coordinator's complete runtime remains late-bound.
2. Add explicit cold key admission, Closure/Assignment v6, encrypted-key and
   verifier inputs. Consume the independently approved cold binding and
   three-member closure set/v2, existing assigned keys, actual provisioned
   ciphertext/transport and original windows. Preserve old hot selectors.
3. Issue `nativePublicationGenesisAssignment/v1`, binding the actual DRS/CSA
   epochs, cold scope, endpoint guest and assigned Retrieval key/guest, without
   a hash of the future Retrieval grant.
4. Issue `nativePublicationGenesisRetrievalGrant/v1`, binding that exact native
   grant and the actual admitted sequence-zero store. Supply both originals to
   the ordinary-service grant issuer in this slice.
5. Compose the complete coordinator Runtime/v2, then its C9, key, closure,
   encrypted-key and verifier originals, and finally its independent signed
   parked release. Future runtime/grant hashes must not be embedded in the
   endpoint static runtimes or earlier native grant.

This order is source-derived. It does not make any serialized owner description
an actual owner, nor replace the separate real stop/reap and retained-core
handoff work.
