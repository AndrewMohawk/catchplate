# Historical authority resolution (H05)

Implementation decision after `.218`: reuse the existing independently
root-admitted historical archive and genuine original replay. Do not create a
second trust catalog, infer retired keys from stored records, or weaken a
current-source equality check to an unverified list of source labels.
H05 remains open; this document records the integration boundary, not a landed
historical recovery implementation.

## Existing components and the actual gap

`authority_historical_archive.py` verifies a current-root-signed archive of
original configuration envelopes, artifact packages/trust states and attestation
cohorts. It freezes admitted snapshots, bounds the archive to 4 MiB and sixteen
historical entries, and meters selected-snapshot capture on request work. Its
existing [historical plan lookup](authority-historical-replay.md) supports
configuration and key changes under the supported source contract; it does not
provide arbitrary old-binary compatibility.

The archive currently uses each historical configuration root during admission
but does not retain it in the frozen snapshot. The operation-specific resolver
must retain that independently authenticated root and the enrollment originals;
it cannot recover authority by accepting a root from a later journal record.
`control_plane_enrollment_bootstrap._EnrollmentMaterial` likewise contains only
the current operation material, so adding a resolver without its cold-startup
inventory would leave the public recovery path disconnected.
The existing sealed parent bootstrap is also capped at 4 MiB: archived originals
must fit that aggregate, not acquire a second allowance. Its generation summary
does not carry the complete historical archive admission interval, so that
provenance must be supplied through genuine cold admission rather than invented
from a record timestamp or the current clock.

Registration recovery still obtains `payload`, `configuration_digest`,
`generation`, `runtime_role_identities`, `root_public_key` and caller/grant/state
enrollment originals from the **current** cold owner. Its retained pair must
also carry the current source revision. Finalization and activation have related
current-cohort restrictions. A record codec preserving an old source label does
not close any of these authority joins.

The existing genuine replay entry points are reusable:

- `authority_webauthn_registration_signer_history._verify_subject_on_configuration`
  authenticates the original signer request/response and derives the subject.
- `authority_registration_history_exchange._verify_on_configuration`
  authenticates the original planning/caller/grant exchange using independently
  supplied configuration, root and three enrollment originals.
- `control_plane_registration_recovery_subject._replay_on_owner` is the first
  public-workflow consumer to connect to independent historical resolution.

## Required implementation sequence

1. Cold-admit the operation-specific historical enrollment originals alongside
   their exact configuration/root/cohort inventory. Bind the inventory to the
   current independently admitted startup scope and its nonrenewing lifetime.
   Retained request data may select an admitted entry, never enroll one.
2. Bound the complete selected association and held enrollment/configuration
   representations before reading or copying their bodies. Preserve the
   existing original bytes and source labels; a new work object must not reset
   the caller's cumulative allowance.
3. Resolve the admitted historical scope, authenticate the original controls,
   and genuinely replay the signer and exchange semantics. Cross-check the
   independently derived user, session, operation and request before returning
   subject observations. Present actor permission remains a separate decision.
4. Connect the same authority rule to finalization and activation recovery,
   including nested evidence and completion originals. One registration-only
   consumer is not H05 completion.
5. Admit older source revisions only through explicit versioned replay code
   covering their original schemas and semantics. Unsupported revisions and
   unknown or ambiguous cohorts continue to fail closed. Do not rewrite signed
   source fields, mutate a global source constant, or reuse current pins as a
   compatibility shortcut.

Historical validity is evaluated against the authenticated original intervals;
current processing retains its actual live clock, inherited deadline and current
archive authorization. Recovery does not renew an original grant, activate an
old generation, retry uncertain SQL, or establish present witness currentness.
Use the genuine historical enrollment verification path for expired originals;
do not disable expiry checks in a live enrollment admission function.

Source closure requires the real startup-to-consumer joins above. Frozen
verification must subsequently exercise retired-key/configuration transitions,
supported and unsupported source revisions, ambiguous/missing inventory,
mixed-cohort originals, expiration, interrupted recovery and denial controls.
No build, execution, provisioning or production acceptance is claimed here.
