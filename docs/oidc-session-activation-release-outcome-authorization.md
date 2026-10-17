# Release-outcome storage authorization

This separate, fresh root-signed original authorizes a fixed release-outcome
storage scope. It does not change release-custody v1, inspect or create files,
create a checkpoint, provision a service or authorize plaintext disclosure.
Implementation is source-only: unbuilt, unexecuted and unprovisioned.

The purpose is `bind-oidc-session-activation-release-outcome`. The envelope
schema and signature domain are
`catchplate.signedOidcSessionActivationReleaseOutcomeAuthorization/v1`; the
payload schema is
`catchplate.oidcSessionActivationReleaseOutcomeAuthorization/v1`. Exact canonical
original identity uses
`catchplate.oidcSessionActivationReleaseOutcomeAuthorizationIdentity/v1`.

The flat, closed payload has eighteen fields: `schema`, `sourceRevision`,
`purpose`, `serviceUid`, `serviceGid`, `processMode`, `trustMode`,
`issuedAtEpochNs`, `expiresAtEpochNs`, and these nine scope fields:

- `configurationDigest`, `databaseId`, `generationDigest`,
  `runtimeClosureDigest` and `receiverIdentity`;
- `deliveryId`, `releaseCustodyDigest`, `directory` and `checkpoint`.

Mode is fixed to `oidc-session-activation-token-release`, UID/GID to 65502 and
trust mode to `trusted-host-local`. Receiver identity uses the existing exact
three-digest grammar, not a measured-runtime proof. The delivery ID uses the
existing bounded delivery-scope text grammar.

`directory` is exactly `device`, `inode`, `uid`, `gid`. Device is a nonnegative
UInt64, inode a positive UInt64, and both owner IDs are fixed to 65502.
`checkpoint` is exactly `recordCount`, `outcomeDigest`: either `0` with `null`,
or `1` with a canonical digest. Both directory and checkpoint come from the
independently expected root-authorized scope. The verifier never infers a
checkpoint from whatever a directory happens to contain. This retained root
checkpoint is neither proof of latest state nor an off-host witness; actual
storage recovery must separately compare its genuine bytes against that pin.

```text
_scope(value, work) -> owned independent scope9
_read(original, work) -> owned canonical envelope data
_digest_on_work(original, work) -> exact-original identity
_verify_on_work(*, authorization_bytes, root_public_key, expected_scope,
                live_window, transport_deadline_ns, work)
  -> _Authorization(payload, authorization_digest, live)
_produce_on_work(*, payload, root_private_key, root_public_key,
                 live_window, transport_deadline_ns, work) -> original bytes
```

`_read` and `_digest_on_work` do not authenticate. Actual verification owns the
complete expected scope before native callbacks, verifies the root signature
and canonical original, and compares all nine independent fields. The returned
payload is ordinary same-call data, not an accepted authority input. Its `live`
guard retains immutable interval scalars, so mutating output cannot renew time.

The positive signed interval is bounded by the planner's existing
`MAX_RECEIPT_AGE_NS` (300 seconds). Use still requires the supplied current
processing window and positive transport deadline. The implementation never
opens a replacement window: it retains the original epoch/monotonic bracket,
clips to the signed expiry, rejects reversed sampled clocks, and checks current
liveness through final output. The original shorter processing lifetime and
skew remain in force; a 300-second authorization is not a 300-second request
allowance. Root production preserves the same work/window, binds the actual
root key pair, precharges the complete signature output and genuinely verifies
the exact signed original before returning it.

All originals and outputs are capped at 16 KiB, 256 JSON nodes and depth four;
capture, canonical wire work and signatures use the caller's cumulative budget.
No filesystem, storage lease, release proof, one-use outcome, token opening or
public/private handoff is supplied by this contract. Those require their own
actual composition and cannot be inferred from a root-signed directory pin.
