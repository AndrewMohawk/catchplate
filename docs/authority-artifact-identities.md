# Authority artifact identities

Source revisions `.108` through `.113` separate file, policy, generation, role,
bootstrap-control and runtime credential identities. Direct final-generation and final-launch
configuration pins are replaced by static commitments. The launch manifest no
longer contains a credential hash of itself, and configuration no longer declares
a digest of the credential set containing that configuration. Attestation-linked
cycles remain. This is an implementation checkpoint, not a
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

The current closed contracts are `serverware.authorityArtifactBundle/v7`,
`serverware.authorityGenerationStatement/v7`,
`serverware.signedAuthorityArtifactPackage/v7`, and
`serverware.unsignedAuthorityArtifactPackage/v7`. Revision `.108` introduced v3
for the operation contract; `.109` added configuration identities in v4; `.110`
binds configuration v3 in v5 packages; `.111` binds configuration v4 in v6 packages.
Revision `.113` binds service configuration v5 and witness configuration v4 in
v7 packages; generation launch context retains its unchanged v4 shape.
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
digest of a nine-field `serverware.authorityConfigurationGenerationBinding/v1`
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
under `serverware.authorityRoleBinding/v1`. This covers the raw role-file hash
and path, role, UID/GID, process mode, entrypoint, listener, credential names,
working directory, PATH, argv, environment allowlist and mutable-state policy.
Factored role validation preserves all prior bounds and restrictions; bundle
executable and raw-file closure checks remain separate and mandatory. A raw
role-file checksum alone cannot substitute for this semantic commitment.

`role_runtime_closure_digest()` frames an exact document under
`serverware.policyAuthorityRoleRuntimeClosure/v1`: `schema`, `roleBindingDigest`
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
existing `serverware.policyAuthorityRuntimeClosure/v2` framing of that final
launch digest and admitted package versions. The static closure never replaces
those runtime values. Root launch signature, complete artifact/package and
credential admission, generation high-water, and active role checks remain.

## Root-verified bootstrap control

Signed launch manifest and payload v6 separate the manifest's delivery from
ordinary credentials. Stage-zero request v4 requires an exact `bootstrapControl`:

| Field | Required meaning |
| --- | --- |
| `name` | `SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD` |
| `fd` | The planned, separately preserved descriptor, at least 3 |
| `envelopeSchema` | `serverware.signedPolicyAuthorityLaunchManifest/v6` |
| `maximumBytes` | 67108864, the unchanged manifest byte ceiling |

The slot contains no manifest hash. It identifies a document to admit, not an
assertion that its contents were verified. Its descriptor must be unique across
the full stage-zero descriptor inventory and both future launch-identity outputs.
The exact environment binding and handoff-preservation set include it.

Every artifact role includes the control name in `environmentAllowlist` and
excludes it from `credentialNames`. Stage-zero rejects it as an ordinary
credential, and the launcher rejects it in `retainedCredentialDescriptors`.
All other credential name, owner, mode, seal, size and raw-hash checks remain.
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
domains are v4. The initial split used launch v5/stage-zero v3; `.113` advances
these versions with the explicit root-custody contract. Old documents are not
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
`serverware.authorityCredentialSet/v1`. The descriptor number remains a separate
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

## Remaining attestation dependencies

Direct generation and role-launch pins no longer force the static configuration
to contain those final identities. The receipt back-reference remains enforced:

```text
configuration --> attestation receipt --> configuration payload digest
                                     --> final launch/package/generation identities
```

The trusted-host path compares a configured `attestationReceiptDigest` with a
receipt that binds the configuration payload itself and final runtime identities.
The role split does not make that receipt constructible or remove its verification.
Attestation is still an ordinary hashed credential: its receipt binds final
launch identity, while the launch commits that receipt's original bytes.
These receipt dependencies still require explicit phase separation; no receipt
or runtime credential digest check is bypassed by the bootstrap/custody changes.

The next implementation must version and integrate an acyclic binding across
static policy production, artifact verification, launch and runtime attestation.
Static policy commitments must precede final generation/launch identities;
runtime evidence must retain genuine independent signature, role, measurement,
nonce, generation and rollback admission without embedding its own final hash.
Current and peer-role runtime receipts must be separately admitted before their
identities reach operation mappers; inserting derived values into the signed
configuration payload would change its identity and is not a valid handoff.
Skipping membership checks, treating a caller-supplied digest as authority, or
enrolling historical configuration from retained data is not a remedy. Durable
caller recovery and historical resolution remain pending that admission work.

Older launch-context and journal snapshots do not satisfy context v4. They need
an explicitly admitted migration before reuse; no automatic adoption is added.

All implementation and integration must finish before the exact source freeze,
one preparation/build phase and consolidated sequential no-build verification.
Independent Nitro/KMS, signing and witness services remain unprovisioned.
