# Current-authority recovery over retained RI outcome evidence

Status: source implementation only, unbuilt and unexecuted. This adds an explicit
recovery counterpart to [current-authority retained-RI LIVE delivery](control-plane-current-authority-retained-ri-delivery.md).
It does not invent a signed outcome or an outcome-signing root. A current root
independently authorizes recovery of one exact existing record; the actual
protected checkpoint-one store must read back that unchanged original.

## Current permission and historical evidence

RI denotes the independently archived authority for the original custody,
intent and proof. Those originals authenticate history, not fresh delivery
permission. Fresh custody v2 and current-root recovery grants remain separate.

| Field | Required identity |
| --- | --- |
| Recovery issuer policy v2 `currentReleaseCustodyDigest` | Exact independently selected fresh current custody v2. |
| Policy `expectedEvidence.releaseCustodyDigest` | Original RI evidence custody used by the retained proof. |
| Recovery authorization v2 `currentReleaseCustodyDigest` | The same current custody selected by policy. |
| Recovery authorization v2 `releaseCustodyDigest` | Historical RI custody, not a relabeled current grant. |
| RECOVERY bootstrap v3 `releaseCustodyDigest` | Current delivery-custody identity. |
| Bootstrap `evidenceCustodyDigest`, storage/recovery scopes' `releaseCustodyDigest` | Unchanged historical evidence-custody identity. |
| Policy `expectedOutcomeDigest`, recovery `outcomeDigest`, storage checkpoint digest | One exact retained outcome; all must match actual protected readback. |

The current custody's independent RI root, archive interval, enrollments and
original custody are admitted through the existing retained-authority owner.
Current and historical planner/state associations, complete state, delivery key,
exact release target and original delivery lifetime must remain compatible.
No root is selected from an outcome, returned grant or caller-provided verdict.

## Four explicit profiles

The [closed bundle](../schemas/oidc-session-activation-retained-outcome-recovery.v1.schema.json)
adds only these profiles; old recovery formats retain their current-only interpretation:

- `ReleaseRecoveryIssuerPolicy/v2` adds `currentReleaseCustodyDigest` to the
  existing policy. The current signature separately pins historical proof/intent
  enrollments, evidence, exact outcome, client, endpoint and launch resources.
- `ReleaseRecoveryAuthorization/v2` adds the current digest to its existing
  historical custody, outcome, caller, receiver, delivery-key and directory scope.
- `ReleaseBootstrap/v3` is RECOVERY only. It retains the separate
  `evidenceCustodyDigest`; recovery scope and original authorization are required
  and non-null. Storage checkpoint is exactly one record with the authorized
  outcome digest. LIVE v2 remains LIVE only with checkpoint zero.
- `ControlPlaneOidcSessionActivationReleaseRecoveryGrantAcquisition/v2` keeps
  the existing six-field cold object and two-field original wrappers. It
  explicitly selects policy v2/current custody v2 before contacting the fixed
  `recovery-grants.sock`; it is not a permission token or a signed envelope itself.

Wire names retain their actual `catchplate.` prefix and casing as specified in
the schema. The three signed envelopes remain exactly
`schema`/`payload`/`signatureBase64Url`. Existing canonical no-LF encoding and
framed original signature verification are retained, with the explicit envelope
version selected for signing and admission; no old signed bytes are relabeled.
Existing storage/client formats are not widened into generic history authority.

## Exact checkpoint-one recovery

Fresh public recovery authorization and current authentication remain mandatory.
The actual actor selects the retained-authority profile from genuine cold
material before the human action. Its separately versioned retained-delivery
intent binds `retainedIntentOnly` and the exact `retainedIntentRecordDigest` into
that fresh approval; changing the retained selection changes the approved
binding. This internal action binding is not an outcome signature or a wire
field added to the six-field acquisition object.
The issuer consumes independently provisioned policy/current custody and archived
evidence; it neither recreates missing intent/proof nor signs with a retired key.
Returned grants are independently admitted against the selected originals and
exact request before actual recovery delivery.

The protected store retains its existing directory, ownership and exact-original
checks. A signed digest or checkpoint claim alone is not an observed record.
Actual checkpoint-one readback must match the expected outcome and historical
custody association before the retained recovery owner can release the unchanged
result under current guards. This does not execute COMPLETE again, generate a
replacement outcome, repeat SQL, repair storage or infer success from absence.

Original old-token possession, delivery-key association and the still-live
original delivery expiry remain required. Fresh outer grants only narrow the
inherited work/window/deadline. The fixed 1–30 second endpoint timeout cannot
start a new allowance. Uncertain exchange never permits automatic resubmission,
plaintext replay, token regeneration or expiry renewal; recovery is a separately
authorized purpose, not a retry result.

## Bounds and remaining scope

The paired policy is bounded to 64 KiB; recovery authorization to 16 KiB; server
bootstrap to 16 MiB. Cold acquisition is bounded to 4 MiB in its containing owner,
even though an individual custody wrapper permits an 8 MiB decoded original.
Canonical decoding, exact integer types, signature checks, field-specific limits,
node/depth bounds and aggregate original/work reservation remain enforced by the
actual owners. A schema-valid bundle can still exceed those combined limits.
Schema validation, operator metadata and serialized identities are never custody
or currentness proof.

This is not state/configuration migration, an older-source adapter, arbitrary
historical-root discovery, a retired-key signing path or general storage repair.
Same-source and compatible-state/key restrictions remain. Independent provisioning,
runtime recovery/cookie evidence, interruption acceptance, off-host rollback
protection and all production gates remain open. No build, test, runtime, pilot,
cloud deployment or parent-completion credit follows from this source connection.
