# Authority artifact identities

Source revisions `.108` and `.109` separate operation-contract and configuration
payload commitments from the checksums of the files carrying them. This is an
implementation checkpoint, not a successful build, launch or production release.

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

The current closed contracts are `serverware.authorityArtifactBundle/v4`,
`serverware.authorityGenerationStatement/v4`,
`serverware.signedAuthorityArtifactPackage/v4`, and
`serverware.unsignedAuthorityArtifactPackage/v4`. Revision `.108` introduced v3
for the operation contract; `.109` adds configuration identities in v4. Existing
digest domains remain unchanged; each canonical body carries its schema version.
There is no compatibility fallback that admits an older package as v4.

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

Launch context v2 carries these bindings from the independently verified
generation statement. Service and witness loaders separately verify the root
signature, hash the original file bytes and compute the payload commitment,
then require the exact role/schema/raw/payload tuple in that admitted context.
The shared service mapper still captures seven selected launch fields on its
existing work allowance; its semantic-membership scan now uses the owned
binding graph. That consistency check does not independently admit a root,
launch or configuration file.

The witness's `authorityConfigurationDigests` contains only semantic
`authority-service` identities. Current and historical requests are checked
against their respective admitted generation's service identities; a digest
with the right shape alone is no longer sufficient for historical requests.
Generator payload validation checks shape and derives bytes, not root-signature
authority. The real loaders perform signature and admission checks.

## Remaining circular dependencies

The identity mismatch is repaired in source, but configuration v2 still cannot
be constructed through an acyclic production sequence. The remaining checks
are deliberately still enforced:

```text
configuration --> final generation --> artifact bundle --> configuration file
configuration --> final launch manifest --> artifact package --> configuration file
configuration --> attestation receipt --> configuration payload digest
```

The witness embeds the full generation and final launch-manifest digest.
Service configuration embeds the final generation digest, final role launch
digests and runtime closures derived from those launch digests. The trusted-host
attestation path also compares a configured receipt digest with a receipt that
binds the configuration payload itself. Removing only the generation witness
checkpoint does not remove any of these configuration back-references.

The next implementation must version and integrate an acyclic binding across
static policy production, artifact verification, launch and runtime attestation.
Static policy commitments must precede final generation/launch identities;
runtime evidence must retain genuine independent signature, role, measurement,
nonce, generation and rollback admission without embedding its own final hash.
Skipping membership checks, treating a caller-supplied digest as authority, or
enrolling historical configuration from retained data is not a remedy. Durable
caller recovery and historical resolution remain pending that admission work.

Older launch-context and journal snapshots do not satisfy context v2. They need
an explicitly admitted migration before reuse; no automatic adoption is added.

All implementation and integration must finish before the exact source freeze,
one preparation/build phase and consolidated sequential no-build verification.
Independent Nitro/KMS, signing and witness services remain unprovisioned.
