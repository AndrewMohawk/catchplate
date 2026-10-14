# Managed workload renewal — implementation contract

This feature is deployed in the ordinary instance at `b5cc5f6f` / normal Rust
`116dc526`. Existing clients remain manual-only unless explicitly enrolled.
Isolated stock-Requests/normal-proxy checks and deployed read-only UI checks have
passed; the helper's default HTTPS transport with its locked dependencies and a
real enrolled workload job remain separate acceptance work. See the
[current checkpoint](project-completion.md#current-checkpoint--october-13-workload-renewal-rollout).
This feature does not confer native or hardware-backed authority.

An administrator explicitly enrolls one workload Ed25519 public key with a
finite 1–90 day grant and a 1–24 hour token lifetime. The workload retains its
private key locally. Enrollment replacement, cancellation, manual token rotation
and client revocation invalidate the enrollment and any previous-token overlap.
Renewal never changes provider credentials or permissions or extends its grant.

The fixed machine endpoint is `POST /v1/workload/renew` on the configured HTTPS
proxy origin. The ordinary TLS-edge gate forwards a bounded signed request once
to `/api/operator-demo/workloads/renew` on its fixed control-plane origin. It
does not forward browser, administrator or proxy credentials. Native profiles,
other methods, query strings and alternate target forms cannot use this path.
No Traefik, nginx or SSO exception is part of this feature.

The closed request and signing domain are defined in
`serverware/operator_workload_renewal.py`. Its audience is the configured
`proxy_url` with trailing slashes removed plus the fixed public path. The proof
binds client, unique enrollment, expected token generation, operation UUID,
verifier, absolute token expiry and a request validity interval of at most one
minute. The public key and signature use lowercase hex. The token stays private.

This audience identifies the ordinary deployment, not a hardware-bound or
rollback-resistant instance. A restored copy with the same database and origin
must remain isolated; explicitly replace enrollments before letting workloads
use a replacement instance. Do not run two independent copies as renewal owners.

The optional application `client_renewal` metadata contains exactly:

- `version: 1`, `enrollment_id`, `public_key`, `enrolled_at_epoch_ms`,
  `expires_at_epoch_ms`, `token_lifetime_seconds`, `overlap_seconds: 300`;
- `previous_token`: null or `token_sha256`, `token_generation`,
  `original_expires_at_epoch_ms`, `accept_until_epoch_ms`;
- `last_operation`: null or an immutable public operation receipt.

After cancellation, manual token rotation or revocation of a formerly enrolled
client, the enrollment object is removed and the optional application field
`client_renewal_cancelled_at_epoch_ms` records the cancellation time. It contains
no old key or verifier, is projected publicly, and is removed by explicit
re-enrollment. Never-enrolled rows are not rewritten. Cancellation removes the
previous-token overlap but leaves the current finite token for manual use.

Before downgrading to a version without renewal support, cancel all enrollments
and confirm their previous-token slots are gone. Older application code does
not understand these lifecycle semantics and must not manage enrolled clients.
Do not erase retained state or restore an old database to perform this step.

The receipt contains `operation_id`, `request_sha256`, `application_id`,
`enrollment_id`, `previous_generation`, `token_generation`, `token_sha256`,
`issued_at_epoch_ms`, `rotated_at_epoch_ms`, `expires_at_epoch_ms`,
`previous_accept_until_epoch_ms`. Issuance is the signed request timestamp;
rotation is the transaction's observed time and determines overlap.
It contains neither a raw token nor a policy activation claim. Current policy
observation is returned separately from that receipt.

The transactional owner holds the existing publication lock and `BEGIN
IMMEDIATE`. It verifies current enrollment/client status, proof, generation and
deadlines before installing a verifier, recording one immutable receipt,
publishing policy, advancing catalog revision and appending one workload audit
event atomically. Exact last-operation recovery performs no write, reissuance
or deadline extension. Conflicting or older operations fail. Only one renewal
owner is supported per client; separate replicas should use separate clients.
Another renewal is refused while the previous overlap remains valid.

Requested expiry must equal the lesser of request issuance plus the enrolled
token lifetime and the enrollment deadline. The previous token is accepted only
until the earlier of its original expiry and commit time plus five minutes.
The signed principal has an optional `managedRenewal` object containing
`schema: serverware.proxyTokenRenewal/v1`, `enrollmentId`,
`enrollmentExpiresAtEpochMs`, `rotatedAtEpochMs`, and optional
`previousToken: {tokenSha256, originalExpiresAtEpochMs, expiresAtEpochMs}`.
The previous cutoff cannot exceed either original expiry or rotation plus five
minutes; current and previous expiry cannot exceed the enrollment deadline.
Explicit enrollment clips the existing token expiry to its grant deadline,
never extends it. Non-enrolled principals retain
their exact existing policy behavior.

CONNECT continuity is a separate opt-in projection, not a relaxation of the
general identity-policy digest. A session remains bound to its originally
authenticated verifier and original expiry and must still match a currently
accepted slot and all non-token identity restrictions. It never acquires a
replacement token's authority. Cancellation or manual rotation removes the
continuity marker. The client manager must refresh SDK connection pools within
overlap; existing connections are not immortal and provider writes are never
automatically retried.

Before dispatch the client persists its candidate token and exact signed
operation in a private, single-writer journal. Unknown outcomes recover only
that operation. The client installs the candidate only after validating the
receipt and observing matching current policy activation. A restart must retain
that journal. Normal TLS verification is mandatory; redirects are refused.

Acceptance requires transaction/race/replay/deadline controls, old and new real
CONNECT sessions, actual stock-library transport handoff, restart/lost-response
recovery, rendered enrollment/cancellation, audit, and state-preserving paired
deployment. None is established by this contract or a healthy process alone.
