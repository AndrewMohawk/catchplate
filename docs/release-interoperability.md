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

## Readiness checksum publication

Readiness `completionProof/v6` uses a closed `integrity_metadata` object with
`apiVersion: serverware.readinessChecksum/v1`. Its `publicationToken` is exactly
32 lowercase hexadecimal characters: a random publication identifier, not a
generation or rollback counter. The token selects the `<proof>.sha256.<token>`
sidecar. Owner-only atomic publication and local readers' exact path,
canonical-byte digest, and current-invocation token/inode checks remain required.

Unversioned metadata and the old string-valued `generation` field are rejected,
not aliased or coerced. Regenerate readiness output through the current writer;
do not rewrite retained evidence. Serverware generation, sequence and epoch
counters remain integer-only. A checksum supplies no independent authentication:
this metadata and any embedded host-readiness context remain readiness-only,
never final release or action authority.

## Exact latency policy units

`--p99-limit-ms` and `SERVERWARE_COMPLETION_P99_LIMIT_MS` accept canonical decimal
text with at most six fractional millisecond digits. Conversion is exact, never
through binary floating point, and must produce a positive integer nanosecond
value no greater than 9223372036854775807. Exponents, signs, leading zeroes,
sub-nanosecond precision and out-of-range values are rejected. Equivalent
spellings such as `20` and `20.000000` agree; conflicting configured CLI and env
thresholds are rejected in both manual and launcher-enforced readiness. The
runner preserves the selected text when forwarding it to the verifier.

The persisted policy remains the existing integer `p99_limit_ns` field, with no
millisecond alias or schema-version change. `scripts/exact_latency.py` is shared
by producer and consumer; benchmark JSON retains its separate exact-decimal
adapter. The helper is included in the verified source archive and legacy
launcher's whole import-root measurement. External final-v1 preflight also
requires its presence, which does not authenticate that installation: its owner
must independently bind the whole verifier/import closure.

## Streaming authorization commitments

A public streaming proof carries an operation-context digest, not the full
authorization-binding preimage retained inside custody. Do not pass that
projection to the full-binding validator or hash it as though it were the full
binding. The streaming consumer checks the independently expected context
digest and exact public commitment, then uses the explicit signed custody
envelope to bind the consumption identity and exact control-plane receipt.

The envelope must carry the actual statement, digest and signature under the
independently pinned, attested response key. Custody checks the full binding and
reconstructs its projection before signing. The public consumer still verifies
the control-plane receipt signature, request/response bindings, JIT and quota
claims, and proof-role key separation. Full-binding and custody-envelope inputs
are distinct trust paths; supplying both is rejected. None of this establishes
production custody or independent attestation merely because a local signed
fixture verifies.

## Provider media and operation-field contracts

`Content-Type` is a reserved, separately checked request field, not a configurable
ordinary header. Gmail, X and npm fixed request profiles therefore omit it from
`allowedHeaders`, as the shared schema requires. Requests still undergo exact
media-type parsing, physical duplicate checks and body-size/presence checks.
Removing the header from ordinary profiles is not permission to forward an
unchecked media declaration. The same reserved-header rule applies to generic
routes without changing their existing media validation.

Typed adapter fields cannot be overwritten by request-value captures. A capture
must not collide with a field emitted by *any* operation admitted by the route.
By contrast, reading an `operationField` requires it to be available for *every*
admitted operation. Gmail list/get both emit `gmailUser`; only get emits
`messageId`. Keep those union-versus-intersection checks distinct. A path rule
that requires Gmail user `me` does not also need to capture `gmailUser`.

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
