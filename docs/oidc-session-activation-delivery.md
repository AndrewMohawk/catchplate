# Original OIDC activation token delivery

This source-only private contract is a prerequisite for protected activation,
not a provisioned custody service, public token response or completed F08 flow.
It is separate from the legacy `crypto.encrypt_secret` environment-key path.
No build, cryptographic execution, database verification or deployment is
claimed for this source checkpoint.

## Fixed originals and independently admitted scope

[`oidc_session_activation_delivery.py`](../catchplate/oidc_session_activation_delivery.py)
uses the pinned `cryptography` AES-GCM primitive with an independently supplied
exact 32-byte custody key. It neither generates that key nor loads an environment
secret, key file, configuration fallback or caller-selected crypto provider.
The separate [release-custody owner](oidc-session-activation-release-custody.md)
now admits original key/scope provenance for metadata inspection only; actual
cold release-key delivery and one-use plaintext egress remain open.

The original encrypted envelope is exactly 100 immutable bytes:

| Component | Bytes |
| --- | ---: |
| Fixed version `SWOAT001` | 8 |
| Fresh internally generated AES-GCM nonce | 12 |
| Encrypted 64-byte token and authentication tag | 80 |

The exact token alphabet is ASCII `A–Z`, `a–z`, `0–9`, `_`, `-`.
`_new_token_on_work` generates 48 fresh bytes and encodes them as 64 URL-safe
characters. Neither arbitrary token shape nor a successful encryption result
proves server custody: the caller must use the real private producer and retain
the original token through the genuine activation composition.

Authenticated associated data has the fixed
`catchplate.oidcSessionActivationDelivery/v1` domain and an exact closed scope:
`deliveryId`, `userId`, `sessionId`, `credentialId`, `credentialRecordId`,
`challengeId`, `assertionDigest`, `oldTokenDigest`, `newTokenDigest`, `createdAt`,
`expiresAt`. Digests are canonical `sha256:` strings; credential IDs retain the
actual canonical unpadded base64url 1–1024-byte bound. Timestamps are canonical
UTC `datetime.isoformat()` originals. Token rotation is required.

The protected transition must independently derive this scope, including the
request-bound deterministic delivery ID, from its genuine request/current-row
replay. It supplies the exact selected database creation time and expiry
`min(database time + independently configured 5–60-second retry TTL, session expiry)`.
This module enforces a positive interval no longer than 60 seconds, current
processing-clock bounds and expiry, but does not establish database-time
provenance, the selected TTL, session currentness or one-use consumption.

## Private calls and row derivation

All calls use the caller's existing `live_window`, exact shared `work`, and
optional inherited `transport_deadline_ns`; none opens a new allowance.

- `_new_token_on_work` returns one private 64-byte token original.
- `_seal_on_work` takes `new_token_bytes`, `custody_key`, and `scope`, seals the
  original, then genuinely decrypts it and compares both the token and its bound
  digest before returning the exact encrypted original.
- `_open_on_work` takes `envelope_bytes`, `custody_key`, and `scope`; it verifies
  AES-GCM authentication, the exact token format and the expected new-token
  digest. Its plaintext result is private original data, never an HTTP response
  or reusable authorization token.
- `_delivery_row_on_work` takes the same original/key/scope arguments and
  independently opens the original before returning the existing exact
  eleven-column delivery row, with `consumed_at=None`. The row contains no
  plaintext token and is ordinary data, not a successful admission carrier.

Stored `encrypted_active_token` is
`oidc-activation-v1:` followed by the canonical unpadded base64url encoding of
the 100-byte original. It is deliberately not legacy `v1:` ciphertext. No
legacy decryption or downgrade fallback is implemented.

The caller must retain the exact ciphertext as a private plan input. It is not
an `envelopeDigest` request argument: the request first commits the target,
old/new token digests, original assertion digest, TTL and business intent, then
its digest determines the delivery ID used in the encryption scope. Genuine
result mutations and the signed plan later commit the exact ciphertext. This
ordering avoids a request-digest/ciphertext cycle; a posted envelope is never a
proof of the request or of authorization.

## Bounds and remaining authority

Every scope field is bounded and copied before clock/codec/crypto callbacks;
the canonical scope is capped at 128 KiB. Key and envelope inputs require exact
immutable bytes. Native RNG, hashing and AEAD operations retain cumulative work
and receive live checks before and after; the original clock opening and
inherited monotonic deadline cannot be renewed. These are synchronous checks,
not a hard watchdog, guaranteed memory erasure or hardware-backed key custody.

There is no database write, delivery claim, consumption, token cookie, public
route, automatic retry or recovery here. A future explicit recovery path must
authenticate the exact current caller and retained originals, and enforce the
one-use delivery transition in the protected database transaction. An absent
response cannot mean the activation did not commit. See the separate
[original assertion admission](oidc-session-activation-admission.md) and
[retained finalization prerequisite](retained-registration-activation.md).

## Protected consumption source checkpoint (.157)

The distinct `oidc.session.activation-delivery.consume` operation now has
[original read-proof admission](oidc-session-activation-delivery-reads.md),
[old-token/current-policy semantics](oidc-session-activation-delivery-consumption.md)
and a genuine [indexed-write adapter](oidc-session-activation-delivery-writes.md).
Actual current primary and complete-range proofs bind the active session,
unconsumed delivery, credential, used challenge, trust and RBAC state. The
original old token is independently hashed; a posted digest is insufficient.
Same-call replay derives the delivery consumption CAS, deterministic audit
insert and actual capacity CAS, with seven counted heads and five affected
delivery indexes. These three effects do not prove a committed consumption.
The typed-successor declaration intentionally lacks a real generic consume
program/factory and fails closed; no placeholder connects it to execution.

The dedicated [root-original release custody](oidc-session-activation-release-custody.md)
uses UID/GID 65502 and only the independently admitted delivery key. It verifies
historical planner/key provenance, fresh root-owned scope and exact live AEAD
metadata, but returns no plaintext and has no release method. Expected
release-intent/consume-request identities are not verified original authority.

The design reuses the existing immutable protected execution packet and commit
marker for the exact outcome and unchanged encrypted delivery. There is no new
outcome table or legacy direct-UPDATE/decryption fallback. Real consume planning
and retained originals, authorization, reservation and protected execution remain
next, followed by genuine original commit admission and one-use plaintext
release/cold handoff. Public permission and portal/current-auth confirmation
remain separate. Step 20 is in progress; source-only counts remain **19/26
landed, 1 in progress, 6 other open**, execution **6/7**, parent **34/46** and
production **0/6**. No build, test, runtime execution or provisioning was run.
