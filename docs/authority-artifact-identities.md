# Authority artifact identities

Source revisions `.108` through `.110` separate file, policy and generation
identities. The final-generation back-reference is removed; launch-manifest and
attestation cycles remain. This is an implementation checkpoint, not a successful
build, launch or production release.

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

The current closed contracts are `serverware.authorityArtifactBundle/v5`,
`serverware.authorityGenerationStatement/v5`,
`serverware.signedAuthorityArtifactPackage/v5`, and
`serverware.unsignedAuthorityArtifactPackage/v5`. Revision `.108` introduced v3
for the operation contract; `.109` added configuration identities in v4; `.110`
binds configuration v3 in v5 packages. Existing digest domains remain unchanged;
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

Launch context v3 carries these bindings from the independently verified
generation statement. Service and witness loaders separately verify the root
signature, hash the original file bytes and compute the payload commitment,
then require the exact role/schema/raw/payload tuple in that admitted context.
The shared service mapper captures eight selected launch fields on its
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

Service and witness configuration v3 bind `generationBindingDigest` rather than
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
for its 22-field context v3. Runtime loaders compare the signed configuration's
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

## Remaining circular dependencies

The direct configuration-to-final-generation edge is removed, but configuration
v3 still cannot be constructed through a fully acyclic production sequence. These checks
are deliberately still enforced:

```text
configuration --> final launch manifest --> artifact package --> configuration file
configuration --> attestation receipt --> configuration payload digest
```

The witness still pins its final launch-manifest digest. Service configuration
pins final role launch digests and runtime closures derived from those launch
digests. The trusted-host attestation path also compares a configured receipt
digest with a receipt that binds the configuration payload itself. The new
generation binding does not erase these separate back-references.

The next implementation must version and integrate an acyclic binding across
static policy production, artifact verification, launch and runtime attestation.
Static policy commitments must precede final generation/launch identities;
runtime evidence must retain genuine independent signature, role, measurement,
nonce, generation and rollback admission without embedding its own final hash.
Skipping membership checks, treating a caller-supplied digest as authority, or
enrolling historical configuration from retained data is not a remedy. Durable
caller recovery and historical resolution remain pending that admission work.

Older launch-context and journal snapshots do not satisfy context v3. They need
an explicitly admitted migration before reuse; no automatic adoption is added.

All implementation and integration must finish before the exact source freeze,
one preparation/build phase and consolidated sequential no-build verification.
Independent Nitro/KMS, signing and witness services remain unprovisioned.
