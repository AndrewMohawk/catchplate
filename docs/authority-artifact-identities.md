# Authority artifact identities

Source revision `.108` separates an operation-contract commitment from the
checksum of the file carrying that contract. This is an implementation
checkpoint, not a successful build, launch or production release.

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

The changed closed contracts are `serverware.authorityArtifactBundle/v3`,
`serverware.authorityGenerationStatement/v3`,
`serverware.signedAuthorityArtifactPackage/v3`, and
`serverware.unsignedAuthorityArtifactPackage/v3`. Their existing digest domains
remain unchanged; each canonical body carries its new schema identifier.
There is no compatibility fallback that admits a v2 package as v3.

## Remaining configuration blocker

Service configuration v2 is not repaired by this change. The generator's
configuration references and generation list use raw signed-file hashes, while
the service loader and shared configuration mapper compare a domain-framed
payload digest with that list. They are different identities.

Additionally, the service payload embeds the final generation digest even
though the generation commits that configuration file and its artifact bundle.
The witness configuration embeds a generation context with the same circular
dependency. Removing only the witness checkpoint from a generation digest does
not remove its configuration commitments.

The next implementation must version and integrate an acyclic binding across
configuration production, artifact verification, launch and runtime admission.
Skipping membership checks, treating a caller-supplied digest as authority, or
enrolling historical configuration from retained data is not a remedy. Durable
caller recovery and historical resolution remain pending that admission work.

All implementation and integration must finish before the exact source freeze,
one preparation/build phase and consolidated sequential no-build verification.
Independent Nitro/KMS, signing and witness services remain unprovisioned.
