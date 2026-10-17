# Original OIDC activation admission

[`authority_oidc_session_activation._derive_on_work`](../catchplate/authority_oidc_session_activation.py)
is a source-only prerequisite for separate OIDC activation. It verifies an
original WebAuthn assertion and returns ordinary, bounded CAS intent. It is not
a registered/plannable operation, permission token, currentness witness, SQL
executor, activation receipt or token-delivery mechanism.

The keyword-only inputs are `assertion_bytes`, the actual raw `session_row`,
`challenge_row` and `credential_row`, independently expected user/session/target
credential IDs, `rp_id`, `origin`, `authn_policy`, `trust_policy`, exact
`old_token_bytes` and `new_token_bytes`, and the caller's existing `live_window`,
`work` and optional `transport_deadline_ns`. No clock window or work allowance
is opened or renewed. Processing checks use that original dual-clock window,
the inherited monotonic cap, and the earlier challenge/pending-session expiry.
The returned epoch limit conservatively includes that cap using the original
opening bracket; it never replaces the original processing window/deadline.

The current-row and policy provenance is an explicit caller obligation. Inputs
are bounded and copied before native callbacks; they are not accepted as proof
of a database read, protected root, current role, signed/current trust bundle,
or retained finalized registration. Authentication policy is exactly
`userVerification: required`, a nonempty `allowedAuthenticatorClasses` list
drawn from hardware/yubikey/platform, and boolean `requireHardwareAttestation`.
Trust policy has `roots`, `currentBundleDigest` and `currentBundleSequence`;
each root uses the existing `RootTrustPolicy` descriptor fields, with a JSON
list for `aaguids`, and must belong to that same independently admitted bundle.
The live policy's hardware alias includes currently trusted YubiKeys, never
platform keys. There is no development-key exception.

Admission joins an unused session-binding challenge to its exact seven-field
payload and canonical payload hash (the actual options producer and DB use the
same sorted compact ASCII JSON for these fields), the pending/unactivated/unrevoked session,
the active target credential, current root classification, and all expiries.
The real existing WebAuthn primitives verify original client data, exact origin,
RP hash, user presence/verification and ES256 signature; the counter must move
forward, except the supported zero-to-zero case. Both assertion credential IDs
must match the target, and an optional non-null user handle must match the user.
The closed assertion profile is the existing portal's `id/rawId/type/response`
shape. Bounded ASCII JSON rejects duplicate keys; non-ASCII text must be escaped.
The assertion is capped at 128 KiB and captured context at 2 MiB/100,000 nodes.

The server token owner supplies two different, fresh-scope 64-byte URL-safe ASCII
token originals. The old digest must match the pending row; only their SHA-256
digests leave this helper. It does not generate randomness, establish new-token
uniqueness, encrypt/deliver a token, retain secret bytes, or claim zeroization.

The returned `catchplate.oidcSessionActivationCasIntent/v1` dict contains a
subject, separately domain-separated complete row/policy commitments, exact
original assertion digest, challenge payload digest, bounded validity, and
challenge/counter/session CAS data. Those predicates require a future genuine
protected transaction, including exact original-row rereads, token uniqueness,
database-owned mutation timestamps, one-use challenge consumption, counter CAS,
session CAS and durable token-delivery handling. The returned intent itself
cannot authorize any of these operations.

The [retained-finalization prerequisite](../catchplate/control_plane_registration_activation_subject.py)
is separate: its original replay is not called by this module. Same-call
composition with it, fresh caller/key permission, protected operation/query
contracts, action-time currentness, atomic persistence and delivery remain open.
Existing finalization completion does not activate an OIDC session.

No tests, builds or runtime validation were run. Planned frozen verification
covers changed row/scope/trust/counter originals, invalid signatures and
payload hashes, expired/reversed clocks, callback mutation and shared-work
exhaustion, token mismatch/reuse, and non-disclosure of token originals. These
are planned checks, not passing evidence or production acceptance.
