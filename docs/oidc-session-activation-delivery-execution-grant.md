# Consume-only execution grant wire

[`authority_oidc_session_activation_delivery_execution_grant.py`](../serverware/authority_oidc_session_activation_delivery_execution_grant.py)
defines a separate, closed grant format for
`oidc.session.activation-delivery.consume`. It does not add consumption to the
generic seven-operation grant or replay inventory. This source is unbuilt and
unexecuted; the private signing primitive is not a public signing endpoint or
proof of enrolled-role admission.

## Original commitments and bounds

The envelope schema is
`serverware.signedOidcSessionActivationDeliveryExecutionGrant/v1`; its payload
schema is `serverware.oidcSessionActivationDeliveryExecutionGrant/v1`.
The separate signature and signed-original identity domains are respectively
`serverware.oidcSessionActivationDeliveryExecutionGrantSignature/v1` and
`serverware.oidcSessionActivationDeliveryExecutionGrantIdentity/v1`.

The exact 23 payload fields commit source revision, consume operation, grant
and current-root enrollment identities, configuration/database/generation,
authorizer measurement, request/operation/caller-authorization identities,
journal/retained-record/plan identities, before/after vectors, result, the two
original frame descriptors and original/grant issue-expiry pairs. There are no
generic signed-snapshot or capability fields, plaintext tokens, keys, proof
graphs or accepted successful-verification carriers.

`originalFrames` is exactly an ordered pair for the signed consume plan and
encrypted consume-original bundle. Each descriptor has only `position`,
`bytesDigest` and `byteCount`; positions must be 0 and 1. Counts use the actual
consume plan and bundle caps, including the bundle's minimum framing overhead,
and share the 64 MiB original aggregate ceiling. These are commitment claims:
the actual producer and receiver must derive and compare them against genuine
immutable originals; a descriptor is not proof of a decrypted or replayed plan.

The complete signed grant is bounded to 64 KiB, 128 JSON nodes and depth four.
The grant issue instant must equal the original plan's issue instant, and its
positive expiry can only narrow that original interval. The original interval
must fit the source plan-age ceiling. No current clock is invented here and no
expired original is renewed; actual role/enrollment/caller/current-lifetime
admission remains the composing owner's responsibility.

## Private interfaces

- `_read_on_work(raw, work)` returns an owned exact-shape canonical envelope;
  it does not authenticate a signature.
- `_verify_signature_on_work(raw, public_key, work)` verifies actual Ed25519
  over the fixed signature domain and returns ordinary `(payload, grant_digest)`.
  The digest binds the exact signed original bytes under the identity domain.
- `_sign_on_work(payload, private_key, public_key, work)` captures the bounded
  graph before key/crypto callbacks, checks the actual key pair, signs and
  verifies the fixed-domain message, then reads back the canonical output and
  joins its exact payload before returning immutable bytes.

All encoding, hashing and callbacks use the caller's existing cumulative work;
none creates a budget, processing window or authority object. Actual production
must first authenticate independent enrolled-role and caller originals and
genuinely replay the consume plan under receiving custody. Signature checking
alone is not that admission. Reservation, one-use SQL, committed-original
completion/recovery, token release and a cold grant service are separate steps.
