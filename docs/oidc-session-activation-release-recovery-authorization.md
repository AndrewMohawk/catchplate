# Fresh authority for unchanged release recovery

This distinct root-signed authorization binds recovery to one independently
known, unchanged release outcome. It is not a renewed old intent, proof,
execution grant or storage-generation-zero permission. Source is unbuilt,
unexecuted and unprovisioned; this module opens no key, directory or token.

The fixed purpose is `recover-oidc-session-activation-release`. The envelope
schema and signature domain are
`serverware.signedOidcSessionActivationReleaseRecoveryAuthorization/v1`; the
payload schema is
`serverware.oidcSessionActivationReleaseRecoveryAuthorization/v1`. Exact
canonical original identity uses
`serverware.oidcSessionActivationReleaseRecoveryAuthorizationIdentity/v1`.
Neither the existing release-custody schema nor the separate
[storage authorization](oidc-session-activation-release-outcome-authorization.md)
accepts this new purpose as a fallback.

The flat, closed payload has twenty fields: `schema`, `sourceRevision`,
`purpose`, `serviceUid`, `serviceGid`, `processMode`, `trustMode`,
`issuedAtEpochNs`, `expiresAtEpochNs` and the following eleven scope fields:

- `configurationDigest`, `databaseId`, `generationDigest`,
  `runtimeClosureDigest` and `receiverIdentity`;
- `callerId`, `releaseCustodyDigest`, `deliveryKeyDigest`, `deliveryId`,
  `outcomeDigest` and `directory`.

Mode is fixed to `oidc-session-activation-token-release`, UID/GID to 65502 and
trust mode to `trusted-host-local`. Receiver identity is the existing exact
three-digest shape, not measured-runtime evidence. Caller/database IDs use the
existing bounded ASCII-token grammar; delivery ID uses the actual bounded
delivery-scope grammar. `outcomeDigest` is mandatory and non-null.

`directory` is exactly `device`, `inode`, `uid`, `gid`: a nonnegative UInt64
device, positive UInt64 inode and owner 65502:65502. All pins, including the
outcome identity and directory binding, are independently supplied expected
scope, never inferred from a directory or a successful verification object.

```text
_scope(value, work) -> owned independent scope11
_read(original, work) -> owned canonical envelope data
_digest_on_work(original, work) -> exact-original domain identity
_verify_on_work(*, authorization_bytes, root_public_key, expected_scope,
                live_window, transport_deadline_ns, work)
  -> _Authorization(payload, authorization_digest, live)
_produce_on_work(*, payload, root_private_key, root_public_key,
                 live_window, transport_deadline_ns, work) -> original bytes
```

`_read` and `_digest_on_work` do not authenticate. Verification captures the
complete independent scope before cryptographic callbacks, checks the actual
root signature and exact canonical original, then joins all eleven fields.
The returned payload is ordinary same-call data, not an accepted authority
input. Its sticky `live` guard retains immutable interval scalars and rejects
reversed sampled epoch/monotonic time, expired processing, or an expired/future
recovery interval. Mutating returned diagnostics cannot renew that guard.

The positive signed interval is at most the existing planner
`MAX_RECEIPT_AGE_NS` of 300 seconds. Every use still requires the caller's
original shorter processing window and positive transport deadline. The
verifier preserves that first epoch/monotonic bracket, lifetime and skew,
clipping only to the signed expiry; it opens no new clock or work allowance.
Root production binds the actual private/public key pair, reserves the complete
output, signs this fixed domain and genuinely verifies its exact output under
the same supplied allowance. All originals and outputs are limited to 16 KiB,
256 JSON nodes and depth four; all work shares the caller's cumulative budget.

Actual recovery must additionally authenticate the separate scope-nine storage
grant with checkpoint exactly `recordCount: 1` and the same `outcomeDigest`,
join its directory binding, and read the unchanged retained bytes. This grant
cannot create an outcome or accept an empty checkpoint. Old root custody,
intent and proof originals remain historical evidence of that exact outcome,
not fresh execution or old-permission renewal. The actual recovery owner must
also bind the real delivery key and enforce the still-live original delivery
expiry before and after opening; the recovery authorization alone does not
contain or extend that expiry.

No latest-state/off-host witness, network receipt, delivery acknowledgement,
cold service, public handoff, fresh session or production claim follows from
this root original. Resource ownership, genuine readback and any private token
return belong to the actual recovery composition, not this contract.
