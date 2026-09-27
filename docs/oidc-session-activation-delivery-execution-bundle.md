# Encrypted consume execution originals

[`authority_oidc_session_activation_delivery_execution_bundle.py`](../serverware/authority_oidc_session_activation_delivery_execution_bundle.py)
is a distinct private AES-GCM codec for `oidc.session.activation-delivery.consume`.
It seals the exact canonical sixteen-field
`serverware.oidcSessionActivationDeliveryPrivateOriginals/v1` document from the
[delivery journal](oidc-session-activation-delivery-journal.md). It does not
accept the activation journal format or grant execution/release authority.
This source is unbuilt and unexecuted; no tests or runtime checks were run.

## Fixed originals and context

```text
_seal_on_work(*, original_bytes, bundle_key, context,
    live_window, transport_deadline_ns, work) -> bytes

_open_on_work(*, bundle_bytes, bundle_key, expected_context,
    live_window, transport_deadline_ns, work) -> exact canonical original bytes
```

The immutable original bytes and key, and a copied closed seven-scalar context,
are held before clock, hash or cryptographic callbacks. The context is exactly:

| Field | Binding |
| --- | --- |
| `schema` | `serverware.oidcSessionActivationDeliveryExecutionOriginalsContext/v1` |
| `operation` | `oidc.session.activation-delivery.consume` |
| `sourceRevision` | Current source revision |
| `configurationDigest` | Independently admitted configuration |
| `requestDigest` | Original consume request identity |
| `planDigest` | Original signed consume-plan identity |
| `journalDigest` | Independently expected journal ciphertext locator |

Only `sourceRevision`, `configurationDigest`, `requestDigest` and `planDigest`
form the journal scope. The genuine delivery-journal decoder checks its own
closed grammar, canonical bytes, original request/configuration/plan joins and
bounded read/write/state/activation-provenance inventory before sealing and
after opening. These checks are not signature verification, complete-proof
replay, permission, currentness, committed consumption or token release. The
original old token stays inside the ciphertext; no custody key is in the
private document or public frame.

## Distinct frame and work bounds

The fixed frame is `SWODX001`, an unsigned 64-bit big-endian plaintext length,
a fresh 12-byte nonce, and AES-256-GCM ciphertext including its 16-byte tag.
The overhead is exactly 44 bytes. No plaintext, key or context graph is
serialized into the frame. Associated data is the distinct byte domain
`serverware.oidcSessionActivationDeliveryExecutionOriginals/v1` followed by
NUL, the exact magic/length header and the canonical independent context.
Opening uses the caller's expected context, never expectations learned from
ciphertext. Wrong magic, length, key, context or tag fails closed; there is no
old-role or old-format fallback.

`_bounded_frame(raw)` checks only immutable bytes and exact fixed framing; it
does not decrypt or authenticate authority. `_capture(key, context)` copies
the closed scalar context and returns the held key/context/journal scope,
not an admitted owner. `KEY_BYTES` is 32, `MAX_CONTEXT_BYTES` is 4096 and
`MAX_CONTEXT_NODES` is 32. `MAX_BYTES` is the journal's 64 MiB original cap
plus `OVERHEAD_BYTES` (44); it does not enlarge an enclosing 64 MiB packet or
the supplied cumulative work allowance. Large originals may therefore fail
the actual remaining allowance well below the standalone frame ceiling.

All slices, associated-data construction, cryptographic inputs and possible
outputs are charged before their corresponding substantial allocations.
The original supplied live window and positive inherited monotonic deadline
remain in force, with sticky current epoch/monotonic checks around native
operations and before return. No new work allowance or clock opening is
created. Sealing genuinely opens its own result through the same guarded
path and compares exact canonical original bytes. It does not renew any
signed plan, observation, delivery or historical-custody interval.

`RECORD_IDENTITY_DOMAIN` is the string
`serverware.oidcSessionActivationDeliveryExecutionRecordIdentity/v1` for a
separate exact raw2 `(signed consume plan, encrypted bundle)` commitment.
Exporting that constant does not add replay, grant production or execution;
framing a ciphertext pair is not proof that its plaintext was admitted.

## Owning caller and unfinished integration

The bundle key must be an independently admitted exact 32-byte secret with
its own purpose and separation from journal, historical bundle and delivery
keys. This codec holds only that key; independent provenance and key
separation are owning-caller preconditions, not claims established here.
There is no key generation, key derivation, ambient key lookup or secret
serialization.

This module neither reads nor changes the private journal, and authenticating
the context does not prove that `journalDigest` names a retained record.
It does not implement durable first-exact ciphertext publication, export,
receiving key custody, original consume-plan replay, authorization/issuance,
reservation, SQL, completion/recovery or a public handoff. Repeated explicit
seals may produce different ciphertext; no retry or automatic reseal path is
provided. Those distinct integrations must preserve actual original evidence,
independent scope and remaining lifetime before this codec can participate in
protected consumption. Step 20 and the authorization/issuance detail remain
partial; no production gate closes.
