# Authority artifact identities

Source revisions `.108` through `.116` separate file, policy, generation, role,
bootstrap-control, runtime credential, evidence-delivery and admitted receipt identities.
Direct final-generation and final-launch
configuration pins are replaced by static commitments. The launch manifest no
longer contains a credential hash of itself, and configuration no longer declares
a digest of the credential set containing that configuration. The final launch
no longer hashes its attestation receipt as a credential. Service configuration
v6 no longer pins the receipts that attest that same configuration; their identities
come from independently admitted runtime evidence. This is an implementation checkpoint, not a
successful build, launch or production release.

## Operation contract

`authority_contract.operation_contract_document()` exposes the complete source
contract: operation registry, source revision, table and capability contracts,
proof primitives, and the remaining source-defined admission rules. The smaller
`operation_manifest()` dispatch map is only one part of that document.

The artifact reference has exactly four fields:

| Field | Meaning |
| --- | --- |
| `path` | Relative path of the measured canonical JSON file |
| `sha256` | Ordinary SHA-256 of its exact file bytes |
| `manifestSchema` | The source `CONTRACT_SCHEMA` |
| `contractDigest` | Domain-framed digest of the complete canonical contract |

These identities have different consumers:

```text
Complete canonical operation-contract file
  |-- ordinary file SHA-256 --> measured file inventory / artifact closure
  `-- CONTRACT_SCHEMA-framed digest --> migration operationContractDigest
                                   --> generation operationManifestDigest
                                   --> stage-zero source/generation admission
```

Generator input still contains only `path` and `manifestSchema`; a supplied
`contractDigest` is not accepted. The generator reads the actual file under its
byte bound, checks its measured size and hash, requires canonical bytes equal
to the complete source document, and derives the semantic digest. The artifact
validator and stage-zero admission independently enforce the source and
generation commitments. Neither identity substitutes for the other.

The current closed contracts are `catchplate.authorityArtifactBundle/v7`,
`catchplate.authorityGenerationStatement/v7`,
`catchplate.signedAuthorityArtifactPackage/v7`, and
`catchplate.unsignedAuthorityArtifactPackage/v7`. Revision `.108` introduced v3
for the operation contract; `.109` added configuration identities in v4; `.110`
binds configuration v3 in v5 packages; `.111` binds configuration v4 in v6 packages.
Revision `.113` binds service configuration v5 and witness configuration v4 in
v7 packages; generation launch context retains its unchanged v4 shape.
Revision `.115` advances the service configuration to v6, with artifact/package
v7, witness configuration v4, launch v7 and stage-zero v5 shapes unchanged.
Existing digest domains remain unchanged;
each canonical body carries its schema version. Older packages are not admitted
through a compatibility fallback.

## Configuration file and payload identities

Each configuration reference now contains exactly `path`, `sha256`, `name`,
`role`, `payloadSchema` and `payloadDigest`. The raw `sha256` still measures the
complete file. For `authority-service` and `witness`, the generator reads the
actual bounded canonical signed envelope and computes `payloadDigest` by
framing its canonical payload with the source-defined `payloadSchema`.
Other configuration roles must carry null for both payload fields; no raw hash
is substituted for an unsupported semantic identity. Generator inputs cannot
supply either payload field.

Service configuration uses its existing service protocol framing (ASCII domain,
NUL, then length-framed canonical payload). Witness configuration uses its existing
artifact-style length-prefixed domain. Source `.116` corrects the generator's
service projection to match the actual loader; these two framings cannot be
substituted for each other merely because both identities are SHA-256 strings.

The generation retains its raw `configurationDigests` inventory and adds
`configurationPayloadBindings`. Each binding contains exactly `fileDigest`,
`payloadDigest`, `payloadSchema` and `role`. The list is bounded to 4096, sorted
by `(fileDigest, role, payloadDigest, payloadSchema)` and unique by file digest.
Its files must belong to the raw inventory; package validation requires exact
equality with the supported configuration references, not a caller-selected
subset. Schema and role must match the source-defined pair.

Launch context v4 carries these bindings from the independently verified
generation statement. Service and witness loaders separately verify the root
signature, hash the original file bytes and compute the payload commitment,
then require the exact role/schema/raw/payload tuple in that admitted context.
The shared service mapper captures nine selected launch fields on its
existing work allowance; its semantic-membership scan now uses the owned
binding graph. That consistency check does not independently admit a root,
launch or configuration file.

The witness's `authorityConfigurationDigests` contains only semantic
`authority-service` identities. Current and historical requests are checked
against their respective admitted generation's service identities; a digest
with the right shape alone is no longer sufficient for historical requests.
Generator payload validation checks shape and derives bytes, not root-signature
authority. The real loaders perform signature and admission checks.

## Predeclared generation binding

Service and witness configuration bind `generationBindingDigest` rather than
embedding the final generation digest or statement. This is the domain-framed
digest of a nine-field `catchplate.authorityConfigurationGenerationBinding/v1`
document: `schema`, `generationId`, `sequence`, `predecessorDigest`,
`minimumRollbackSequence`, `validFrom`, `validUntil`, `operationManifestDigest`
and `trustMode`. All are available before configuration files and the artifact
bundle are finalized. Trust mode flags are validated as an exact source-defined
combination; the document commits the corresponding mode.

`configuration_generation_binding()` and its digest helper validate and project
these selected fields. They do not validate or authorize a complete generation.
The generator derives the expected binding from its original generation metadata,
current source contract and trust mode before file reads. Both actual signed
configuration payloads must join it; service sequence, predecessor and rollback
floor must also match.

The launcher independently verifies the complete signed generation, artifact
package and external high-water evidence, then derives `configurationBindingDigest`
for its launch context. Runtime loaders compare the signed configuration's
predeclared binding with this derived value, while preserving original-file and
payload membership in the final generation. The binding is not a substitute for
the final generation digest in requests, receipts, capabilities or journal state.

The witness receives and deep-owns the admitted final generation separately from
its static signed payload; it never injects runtime state into that payload.
The writer continuation likewise returns the real persistence owner alongside
an immutable sequence/final-digest pair captured from the same generation-last
launch observation. Commitment processing uses that pair, not a configuration
claim or a second launch read after key callbacks.

Historical projection preserves the recorded operation digest rather than
substituting today's source contract. This is only recomputation of already
admitted history: current source pins, signed statements, journal lineage and
generation admission remain separate requirements.

## Static role and runtime-closure commitments

Configuration v4 removes `launchManifestDigests` and `runtimeClosureDigests`.
The service instead signs `roleBindingDigests` and `roleRuntimeClosureDigests`,
each containing exactly the five service roles. Witness configuration signs its
own `roleBindingDigest`. None of these values depends on a final launch manifest.

`role_binding_digest()` frames the full canonical 14-field artifact role entry
under `catchplate.authorityRoleBinding/v1`. This covers the raw role-file hash
and path, role, UID/GID, process mode, entrypoint, listener, credential names,
working directory, PATH, argv, environment allowlist and mutable-state policy.
Factored role validation preserves all prior bounds and restrictions; bundle
executable and raw-file closure checks remain separate and mandatory. A raw
role-file checksum alone cannot substitute for this semantic commitment.

`role_runtime_closure_digest()` frames an exact document under
`catchplate.policyAuthorityRoleRuntimeClosure/v1`: `schema`, `roleBindingDigest`
and `packageVersions`. The version map is bounded to 4096 nonempty ASCII
name/version pairs of at most 256 characters each. The generator derives measured
role references before configuration reads, then checks all signed static pins
against those actual references and configured package versions.

Launch context v4 has 24 fields: it carries the full bounded, ordered
`roleManifests` list and derived `roleBindingDigests`, alongside the unchanged
raw `roleManifestDigests`. Witness validation recomputes the existing signed
`roleSetDigest` from the full metadata, derives both role maps and joins them
to the generation statement. Historical records require this same recomputation;
a semantic map without its committed metadata is insufficient. Existing
launch, transport and journal byte ceilings are not widened.

Service startup joins all five role pins to the admitted generation and checks
the static closure against the launch-admitted package map. The private mapper
uses its original work allowance for an owned role-map scan and fixed five-pin
comparison; it does not hash roles off-ledger or claim launch admission itself.

Dynamic attestation remains distinct: it still checks `launchManifestDigest`
against the actual active launch and computes `runtimeClosureDigest` using the
existing `catchplate.policyAuthorityRuntimeClosure/v2` framing of that final
launch digest and admitted package versions. The static closure never replaces
those runtime values. Root launch signature, complete artifact/package and
credential admission, generation high-water, and active role checks remain.

## Root-verified bootstrap control

Signed launch manifest and payload v7 separate the manifest's delivery from
ordinary credentials. Stage-zero request v5 requires an exact `bootstrapControl`:

| Field | Required meaning |
| --- | --- |
| `name` | `CATCHPLATE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD` |
| `fd` | The planned, separately preserved descriptor, at least 3 |
| `envelopeSchema` | `catchplate.signedPolicyAuthorityLaunchManifest/v7` |
| `maximumBytes` | 67108864, the unchanged manifest byte ceiling |

The slot contains no manifest hash. It identifies a document to admit, not an
assertion that its contents were verified. Its descriptor must be unique across
the full stage-zero descriptor inventory and both future launch-identity outputs.
The exact environment binding and handoff-preservation set include it.

Every artifact role includes the control name in `environmentAllowlist` and
excludes it from `credentialNames`. Stage-zero rejects it as an ordinary
credential, and the launcher rejects it in `retainedCredentialDescriptors`.
Ordinary credential name, owner, mode, seal, size and raw-hash checks remain;
runtime evidence has its own mandatory admission described below.
The entrypoint still delivers the real root-owned manifest through its sealed
descriptor and existing `--descriptor` transport; it does not invent a manifest
or declare successful admission.

```text
stage-zero request: planned bootstrap slot, ordinary credential hashes
                         |
                         v
signed final launch manifest: request plus complete launch evidence
                         |
                         v
launcher: original canonical bytes + independent root signature
                         |
                         v
retained bootstrap identity: observed only after admission
```

The launcher preserves the separately verified original descriptor and checks
its sealed, root-owned file identity through launch activation. The guard holds
that immutable observation separately and rechecks descriptor continuity when
requiring an active launch. An observed raw checksum is not inserted into the
manifest or request, nor does it substitute for the signature. Stage-zero
interface, handoff, launch-identity schemas and their changed signature/digest
domains are v5. The initial split used launch v5/stage-zero v3; `.113` added
root custody with launch v6/stage-zero v4, and `.114` adds the explicit runtime
evidence slot with launch v7/stage-zero v5. Old documents are not
silently adopted.

## Runtime credential custody

Service configuration v5 removes the role field `credentialSetDigest`. The
earlier generator and loader only shape-checked that field; they did not join it
to the actual runtime set. Treating it as the full set digest would require the
configuration to contain a hash depending on its own bytes. No replacement
policy object or unchecked digest is introduced.

Static policy remains the existing role commitment: the complete admitted
role manifest binds the exact ordinary credential names, and the configured
`roleBindingDigests` join those roles. Runtime content identity remains the
actual signed request/certificate commitment, including each credential's size
and raw file hash. `credential_set_digest` accepts only a list or tuple bounded
to 256 before copying, validates every exact descriptor and sorted unique name,
then hashes the unchanged nine-field public projection under
`catchplate.authorityCredentialSet/v1`. The descriptor number remains a separate
request binding, not part of that content-set projection.

Stage-zero v4 distinguishes custody from assignment: `ownerUid` must be zero,
matching the existing root-owned sealed delivery and service readers, while
`ownerRole` still must equal the exact admitted service role. The previous
runtime-UID equality conflicted with those real delivery requirements. Ordinary
file ownership, private mode, seals, size, raw hash and role/name checks remain;
no writable file or additional credential is granted to a service.

Before loading its launch private key, `AuthorityProcess` captures the genuine
guard request and generation, checks current role/process and generation
sequence/digest, and computes the actual credential-set digest. It holds these
expected scalars with the admitted stage-zero request digest, then compares the
original launch certificate's corresponding fields after key construction.
Canonical original bytes and the launch public-key binding remain checked.
This repeats consistency at service startup; root signature, authorized issuer,
complete request and certificate admission still belong to the actual launcher.
Nothing is inserted into the signed configuration payload. Public credential
release evidence retains its separate runtime `credentialSetDigest`.

## Separately held runtime evidence

Stage-zero v5 adds `runtimeEvidence`. For verifier, planner, planner-writer,
issuer and executor it is a mandatory exact four-field object:
`name` is `CATCHPLATE_POLICY_AUTHORITY_ATTESTATION_FD`, `fd` is the planned
descriptor, `purpose` is `authority-attestation`, and `maximumBytes` is 4194304.
For every other role the field must be null. The corresponding environment name
is present only for those five roles and must contain the same descriptor.

This slot has no content hash. Its descriptor participates in complete numeric
collision rejection and exact exec/handoff preservation, including separation
from bootstrap control and both launch-identity outputs. The ordinary credential
validators reject both the attestation name and the old `attestation-evidence`
purpose. Static role metadata and generator inventories follow the same split;
all other ordinary credential content commitments remain intact.

The existing systemd entrypoint still opens the actual root-owned attestation
file and delivers its sealed descriptor with the existing CLI. The launcher
checks bounded, private, sealed anonymous bytes and stable identity, then keeps
its ten-item descriptor/stat/raw-SHA observation outside the signed launch and
request. The guard requires that separately retained observation for exactly
the five service roles, joins it to the declared slot and checks continuity.
It does not declare that a receipt is genuine or that its claimed runtime exists.

Before receipt verification, the service obtains that held identity, reads the
exact bounded bytes at offset zero, checks their size and raw SHA, and rechecks
the guard identity. Actual root signature, canonical receipt, configuration,
generation, role, measurement, final launch, freshness and trust-mode checks
still run afterward. No pathname fallback or arbitrary callback replaces them.
The unsupported native/HSM/TEE/external-witness path remains denied.

```text
request: ordinary hashes + bootstrap slot + runtime-evidence slot
                              |
                              v
                    final signed launch identity
                              |
                              v
                 original signed attestation receipt
                              |
                              v
           separate sealed delivery -> actual receipt admission
```

This removes the final-launch-to-receipt content-hash back-reference. Revision
`.115` separately removes the configuration-to-receipt back-reference below.
Neither change creates an independent attestation producer. Source presence is
not successful delivery or serving evidence.

## Runtime attestation cohort

Service configuration v6 contains static measurement, role, package, key, TLS,
freshness and trust-policy pins. It contains neither role receipt digests nor
the issuer session digest that is derived from those receipts. Other existing
predeclared session and credential-issuance pins remain; they are not replaced
with fabricated runtime observations.

```text
static signed configuration + admitted generation/launch observations
                      |
                      v
             five root-signed role receipts
                      |
                      v
          root-signed exact five-role cohort
                      |
            separate sealed evidence slot
                      |
                      v
         signature, scope and local launch admission
                 /                    \
                v                      v
   original local receipt      separate runtime identity map
   for existing protocols      for configured operation mappers
```

Within the unchanged 4 MiB evidence slot, source `.116` uses a canonical
`catchplate.authorityRuntimeEvidence/v1` wrapper containing the current cohort
and a separately root-authorized historical archive. See
[historical replay](authority-historical-replay.md) for admission and lifetime
boundaries. The current cohort remains canonical
`catchplate.signedTrustedHostLocalAttestationCohort/v1`: the exact
`schema`, `payload`, `signature` envelope. Its payload has ten fields: schema,
source revision, configuration digest, generation digest, operation-manifest
digest, artifact-package digest, role-binding digests, receipts, issuance time
and expiry. Receipts are the five existing signed local-attestation envelopes,
ordered by role (`executor`, `issuer`, `planner`, `planner-writer`, `verifier`).
All six signatures are verified with the independently admitted configuration
root. Signature and receipt identities use the existing service protocol's
domain-plus-NUL and length-framed hashing, not artifact-package framing.

Every receipt joins the admitted configuration/generation/package and static
role measurement/key pins. Its runtime closure binds its signed launch digest
to the actual admitted package inventory. The selected local receipt additionally
matches the active guard's launch and stage-zero observations. Peer launch
claims are assertions of the trusted root signer, not local observations of
peer liveness. The cohort's original validity interval cannot exceed any inner
receipt interval, and all intervals are rechecked after signature admission.
This profile explicitly remains trusted-host-local: it asserts no native stage
zero, HSM, TEE or independently operated witness assurance.

The service retains the original cohort bytes and derives a separate bounded
runtime map. Configured mappers capture that map on their existing work allowance
before key callbacks and join its configuration, generation and static role pins.
They perform consistency checks, not root enrollment. The signed configuration
payload is never amended. The issuer session digest keeps its existing derivation
over DB/TLS identity, measurement, the admitted receipt and the predeclared
credential-issuance pin. Historic expectations are not refreshed from this map.

Supported-version historical configuration/key resolution is integrated in
source `.116`; unsupported old source/schema replay remains denied.
Independent receipt/cohort/archive production, cross-source replay,
durable caller recovery and successor execution remain implementation or
provisioning work. Caller-supplied digest maps and retained history do not acquire
admission authority from this split. Broad fixture adaptation and consolidated
runtime verification are deferred until implementation is complete.

The runtime client's signed trust document is also post-package material: it
contains verifier attestation evidence and is loaded independently from a
root-owned sealed credential. Its bytes remain committed by the later runtime
launch. Do not place that current-generation trust document in the artifact
package whose identity its receipt already binds; generic raw configuration
references do not currently prohibit that circular construction automatically.

Older launch-context and journal snapshots do not satisfy context v4. They need
an explicitly admitted migration before reuse; no automatic adoption is added.

All implementation and integration must finish before the exact source freeze,
one preparation/build phase and consolidated sequential no-build verification.
Independent Nitro/KMS, signing and witness services remain unprovisioned.
