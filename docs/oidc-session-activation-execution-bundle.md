# Encrypted activation execution originals

[`authority_oidc_session_activation_execution_bundle.py`](../serverware/authority_oidc_session_activation_execution_bundle.py)
is a source-only, private ciphertext codec. It seals the exact canonical
`serverware.oidcSessionActivationPrivateOriginals/v2` document retained by the
[activation journal](oidc-session-activation-journal.md). It does not export a
key, expose tokens in a generic SQL packet, authenticate the document's alleged
authority, or execute activation. No build, test or runtime verification was run.

## Fixed interfaces and frame

```text
_seal_on_work(*, original_bytes, bundle_key, context,
    live_window, transport_deadline_ns, work) -> bytes

_open_on_work(*, bundle_bytes, bundle_key, expected_context,
    live_window, transport_deadline_ns, work) -> exact original bytes
```

Only immutable bytes and a closed, owned seven-scalar context are accepted.
The context is exactly:

| Field | Binding |
| --- | --- |
| `schema` | `serverware.oidcSessionActivationExecutionOriginalsContext/v1` |
| `operation` | `oidc.session.activate` |
| `sourceRevision` | Current fixed source revision |
| `configurationDigest` | Independently admitted configuration |
| `requestDigest` | Exact original request identity |
| `planDigest` | Exact signed-plan identity |
| `journalDigest` | Exact local journal ciphertext locator, not authority |

The binary frame is `SWOAX001`, an unsigned 64-bit big-endian plaintext length,
a fresh 12-byte nonce, and AES-256-GCM ciphertext with its 16-byte tag. Overhead
is exactly 44 bytes. No plaintext, key or context graph is serialized into it.
The canonical context is bounded to 4 KiB and used only as associated data,
after the distinct `serverware.oidcSessionActivationExecutionOriginals/v1` NUL
domain and exact magic/length header. Opening uses the independently supplied
expected context; nothing received supplies those expectations.

The private original cap stays 64 MiB; the standalone frame ceiling is that cap
plus 44 bytes. This does **not** enlarge the caller's cumulative work allowance
or any enclosing 64 MiB packet limit. Both must still fit. Exact frame lengths
are checked before cryptographic allocation; trailing bytes, alternate magic,
wrong context/key and unauthenticated ciphertext fail closed.

## Original and lifetime preservation

The actual journal decoder validates the closed v2 document, canonical bytes,
request/operation/configuration/plan joins and existing bounded original
inventories before sealing and after opening. This is storage grammar, not
genuine signature, proof, state-currentness or permission replay. Old/new tokens,
assertion, delivery envelope, read/write evidence, plan and state originals stay
inside the encrypted document. Opening returns its unchanged private bytes,
never a successful replay object.

Inputs are captured before clock or cryptographic callbacks. Each call uses the
supplied work and original live window, narrows to the required inherited
monotonic deadline, and checks sticky epoch/monotonic continuity around native
operations. Allocations are charged before encryption/decryption. Sealing opens
the result through the same guarded path and compares exact plaintext bytes.
It creates no replacement window or new original expiry; downstream authority
replay must still enforce all signed plan/head/delivery intervals.

## Owning caller and remaining boundary

The bundle key is an independently admitted exact 32-byte secret, distinct from
both journal and token-delivery keys. The codec holds only the bundle key, so
its provenance and separation are mandatory **owning-caller preconditions**,
not checks it can establish from ciphertext or a supplied assertion. No key is
generated, derived from another secret, serialized or loaded from an environment
fallback here.

The [configured planner's candidate preparation](oidc-session-activation-plan-owner.md)
uses the journal's bound read to join the actual retained ciphertext to the
independently expected locator before decryption, repeats original plan replay,
checks key separation and then calls this codec. This codec itself neither reads
storage nor changes the journal's 0700 directory, 0400 immutable records,
no-replacement publication, quotas or local retention. Encryption does not prove
the claimed journal locator exists or make an exported copy durable. Repeated
candidate preparation can produce different ciphertext. The separate
[first-exact exporter](oidc-session-activation-execution-export.md) now reads
the durable store before sealing, replays actual originals, and either returns
the matching first ciphertext or publishes a first candidate. The
[private planner service](oidc-session-activation-planner-service.md) connects
that path under independently root-admitted v3 key/directory pins. This is
not an automatic lost-response recovery endpoint or historical admission.

The [private execution replay adapter](oidc-session-activation-execution-replay.md)
authenticates the known plan before opening, joins independent originals and
replays genuine effects and complete roots. Receiver configuration/key admission,
independent action-time state, irreversible one-use execution, transport,
durable outcomes and separately authorized recovery remain caller responsibilities.
This module supplies no public service, historical admission, retry permission,
SQL action, token delivery or session-activation claim.
