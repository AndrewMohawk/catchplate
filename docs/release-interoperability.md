# Release interoperability and remaining readiness boundaries

## Sigstore JSON boundary

Sigstore/Rekor counters use ProtoJSON int64 representations. The release tools
must accept canonical nonnegative decimal strings or JSON integers for the
recognized foreign-protocol counter fields, bounded to signed 64-bit range.
Serverware-owned generation, sequence, epoch, index and tree-size fields remain
integer-only. `scripts/sigstore_json.py` defines explicit bundle, response,
transparency and image-signature scopes; it is not a general relaxation of the
Serverware canonical profile.

Validation preserves representations. Changing `"0"` to `0` changes the outer
signed statement and its digest, even though both parse to the same counter.
The tools never rewrite decoded canonicalized bodies, inclusion promises,
checkpoint text or signatures to make a proof pass. Cryptographic verification
still requires independent trusted signing and Rekor keys and all existing
statement, inclusion and checkpoint bindings. Parsing success is not authority.

The helper must accompany the externally frozen verifier installation, not only
the candidate application image. The final-v1 preflight checks its presence;
this is not an authentication or immutability proof for that external install.
Its owner must bind the whole verifier/import closure independently. The legacy
launcher separately measures and retains complete import-root trees.

The source schemas are the [Sigstore Rekor protobuf definition](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_rekor.proto)
and [ProtoJSON int64 mapping](https://protobuf.dev/programming-guides/json/#strings-for-int64).

## Authenticated checkpoint sequences

External checkpoint sequences must be JSON integers from 1 through
9007199254740991. The reported sequence must equal the sequence authenticated by
the Ed25519 receipt. Updating both values without a fresh valid signature still
fails. Local source sequences and tree sizes use the same positive integer
bound; booleans, numeric strings and fractional values are not integers here.

At the external adapter boundary only, `checkpoint_id` remains a sole-field
transport alias for that bounded integer. Supplying both aliases is rejected,
even if equal. The signed payload and normalized artifact use only
`external_sequence`. This differs deliberately from the foreign Sigstore int64
counter representation described above.

Opaque receipts are no longer supported. Setting
`SERVERWARE_TRANSPARENCY_REQUIRE_VERIFIABLE_RECEIPT=0` fails explicitly before
publication or fixture signing; operators must supply the verifiable receipt
protocol. Valid receipt signatures do not by themselves establish trusted log
identity: final verification still uses independently pinned log keys/provider.

## Static Compose versus runtime evidence

Release provenance must account for the exact eighteen services declared in
`docker-compose.production.yml`, each using its required control or gate image.
The gate shares the control-plane network namespace. Both published ports belong
to `serverware`: loopback control port 3000 and the explicitly configured proxy
address on port 8080, targeting 9090. The management listener is not published.
Custody group memberships and the isolated healthcheck command are closed
contracts, not arbitrary caller-selected values.

Render-only fixtures supply syntactically valid IPs, GIDs and nonexistent bind
paths. They provision no authority services, keys, sockets, files or credentials.
Their environment is separate from host-readiness configuration evidence.

The legacy runtime verifier remains incompatible with this topology: it expects
four continuously running services and compares Docker's initial configured user
with a final runtime identity. The current Compose model also contains one-shot
generation jobs and root-starting authority bootstraps that drop privileges.
Changing expected users to root, accepting stopped services wholesale or simply
expanding the four-service list would not prove the required lifecycle or final
process identity. These checks remain fail-closed pending an explicit contract
for completed jobs and independently checked post-bootstrap runtime identity.

Neither the static topology repair nor cryptographically valid local fixtures
establishes production completion. The WebAuthn startup, authenticated predicate
and root-authority, real enclave custody, independent release services and live
verification requirements in `goal.md` remain in scope.
