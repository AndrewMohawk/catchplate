# Native runtime opening export

This finite slice connects a **new runtime observation**, not a restatement of
successful installation. The request path calls `capture_for_gate`; the actual
custody owner allocates and durably records `IngressOpen`. Only its completed
`PersistedIngressAdmission`, the same retained installed generation, and current
independently assigned custody key can create the sealed native opening.

The exporter retains the original `SignedShadowSpillReceipt`, including exact
canonical event bytes, positive ingress sequence, request commitment, spool
predecessor/head, trusted time, and persistence/retrieval commitments. No HTTP
body, token, credential or final injected request is exported. It does not ask a
caller whether capture or persistence succeeded and does not re-sign the receipt
under a substitute custody, audit or response-proof domain.

The existing explicit native durable-delivery selection enables this path; old
profiles continue their original behavior. Preview and non-shadow ingress remain
outside shadow coverage. The outer native TLS/signing owner authenticates the
exporter independently of the inner custody receipt. The existing prepare,
authenticated read, irreversible claim, single intake contact and completed
recovery path retains the future HTTP original before contact. There is no new
endpoint, key provisioning path or outer startup version.

## Exact consumer join

`custody` has an additional closed record marker
`catchplate.nativeCustodyOpening/v1` (ten fields). It occupies one indivisible
batch. The writer rechecks existing protected assignment, load, observing member
and committed generation publication, the original dedicated custody signature,
the full assignment key-independence commitments and exact publication custody
configuration. It retains the new record and result in the existing protected
intake-batch journal, atomically with slot consumption and audit. It does not
invent a legacy `policy_canary_custody_heads` successor or a final ingress row.

The actual native assignment has two custody fields missing from the older
Python direct-payload keyset. The consumer now recognizes exactly either the
original fourteen-field shape or the actual sixteen-field shape; it retains and
verifies the **complete** signed payload. The new opening requires the latter.
The two direct readiness readers use the same closed distinction. This fixes a
consumer mismatch, not an initial assignment producer or a new permission.

The planner authenticates the complete existing batch population against its
transaction roots. Openings must start at the signed generation's first sequence
and remain contiguous. A new request UUID cannot skip/re-admit an opening. Result
coverage is explicitly `opening-only`; retained storage/retrieval commitments are
not independent physical-storage or provider-authorship proof.

## Lifetime, uncertainty and limits

The capture owner serializes admission through export. Its absolute export
deadline is fixed **before** custody admission, capped at thirty seconds and
clipped to the retained native lifetime and existing signed delivery bounds. It
is not refreshed after signing, storage, readback, claim or contact. An admitted
opening without authenticated consumed completion permanently fences further
capture in that owner, including ambiguous custody completion. Neither another
request nor installation clears this fence. Restart's delivery recovery remains
observation-only and cannot recreate contact permission. No timer implies unsent.

No global transport/proof/work limit is raised. This profile additionally caps a
record at 64 KiB, opening event bytes at 16 KiB and the complete assignment key
inventory at 256 bindings. Existing intake has a temporary 32-row table cap,
240-row query and 8192-unit work budget; the full authenticated population can
hit its limit earlier. Capacity exhaustion refuses and cannot confer retry or
contact authority. Production-scale retention/compaction and cross-boot recovery
of genuinely missing original observations remain required work, not a claimed
completed service profile.

## Remaining genuine producers

| Receiver kind | Actual ownership / remaining producer |
| --- | --- |
| assignment | Independent complete fleet/attestation/role-key inventory producer remains; never synthesized from one install. |
| canary-revision | Actual authorized lifecycle transition export remains. |
| load-receipt | Existing independently signed install prerequisite is reused, not re-emitted. |
| runtime-attestation-handoff | Existing verified original is reused; complete initial upstream intake still required. |
| custody | This slice exports actual newly persisted native openings only. Other custody/terminal evidence remains. |
| ingress | Final captured/unavailable/sampling accounting envelope and source-owned signer remain. |
| active-decision | Actual final-effect/final-response owner must emit its dedicated original. |
| shadow-observation | Actual evaluator result plus corresponding active/ingress originals must be emitted. |
| instance-revision | Actual lifecycle/heartbeat ownership must emit transitions. |
| checkpoint | Real sealed ledger ranges and roots must produce the checkpoint. |
| compiler-analysis | Actual independently authorized compiler result must enter the delivery owner. |
| readiness | Real complete fleet checkpoints and authority analysis must produce readiness. |

Opening export never makes Setup proxy-ready or completes canary/readiness/JIT.
No build, parser, test, runtime, provider or cloud execution was performed for
this source slice. Provisioning and runtime acceptance remain separate.
