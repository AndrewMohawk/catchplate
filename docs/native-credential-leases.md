# Explicit native credential leases

This `.250` source profile connects native credential leases to the actual broker,
recipient owner and [native response authorization lifecycle](native-response-principal-profiles.md).
It is not an executed credential release, provider canary or production gate.
Legacy lease families and their diagnostic verifier contract remain unchanged.

## Explicit selection and wire families

The native data plane selects the profile from its genuine retained native
recipient preparation before constructing or hashing the request. Neither an
HTTP response, evidence field, copied success object nor principal length selects
the recipient profile. The broker accepts only closed versioned request shapes
and requires genuine recipient verification for native requests even in development.
Controlled routes cannot fall back to uncontrolled or legacy dispatch.

All names below have the `catchplate.` prefix. Envelopes and sets have no `kind`
field. Native request v1 is metadata or policy-permitted uncontrolled dispatch;
v2 is controlled dispatch, not a new way to bypass reservation or JIT authority.

| Family | Native versions | Exact boundary |
| --- | --- | --- |
| `nativeCredentialLeaseRequest` | [v1](../schemas/native-credential-lease-request.v1.schema.json), [v2](../schemas/native-credential-lease-request.v2.schema.json) | v1 omits authority/release fields, including null; v2 requires request authority and a present, nullable release authorization. |
| `nativeCredentialLeaseRequestAuthority` | [v1](../schemas/native-credential-lease-request-authority.v1.schema.json) | Exact reserved attempt/binding/request/operation/context/expiry; current broker state remains authoritative. |
| `nativeCredentialLeaseReleaseAuthorization` | [v1](../schemas/native-credential-lease-release-authorization.v1.schema.json), [v2](../schemas/native-credential-lease-release-authorization.v2.schema.json) | Ordinary v1 omits `durablePolicy`; durable v2 requires the genuine claim and exact binding/deadline joins. |
| `nativeCredentialLeaseEnvelope` | [v1](../schemas/native-credential-lease-envelope.v1.schema.json), [v2](../schemas/native-credential-lease-envelope.v2.schema.json) | v2 additionally authenticates dispatch purpose and both request hashes in AAD. |
| `nativeCredentialLeaseSet` | [v1](../schemas/native-credential-lease-set.v1.schema.json), [v2](../schemas/native-credential-lease-set.v2.schema.json) | Both require `releaseAuthorization`, null in v1; v2 also retains exact request authority and its hash. |

Only `principalId` admits up to **1024 UTF-8 bytes**, nonempty, trim-stable and
without Unicode `Cc` controls. Native route/credential IDs retain the existing
nonempty, trim-stable **256-byte**, no-`Cc` predicate. Other IDs retain their
existing limits. JSON Schema `maxLength` counts characters, so runtime byte and
cross-field checks are mandatory. No legacy ID is widened or remapped.

Both expected credential fields are present in native requests: null for metadata,
the actual version and metadata hash for dispatch. Public metadata has its existing
allowlist; metadata responses contain no secret. Decrypted sets contain exactly
one matching credential and dispatch alone requires the secret. These plaintext
sets must not become logs, public capture artifacts or verifier diagnostics.

## Independent recipient-verifier selection

[`verify_native_lease_recipient.py`](../scripts/verify_native_lease_recipient.py)
requires independently supplied exact-file SHA256 pins for its expectations and
trust-root originals before JSON parsing. New
[`nativeCredentialRecipientExpectations/v2`](../schemas/native-credential-recipient-expectations.v2.schema.json)
has the old twelve fields plus the fixed
`leaseRequestProfile: "catchplate.nativeCredentialLeaseRequest"`.
This pinned configuration, not stdin, selects native request handling. Old
expectations v1 rejects the new marker; v2 requires it. The shared `_expectations`
override used by other verifier scripts retains its prior API and behavior.

Deployment must independently provision the v2 expectations original and update
its configured `--expectations-sha256` pin before using these native lease
contracts. No producer in the targeted scripts, control-plane, ops or Rust source
generates or upgrades this expectations original. Keeping the v1 file and pin
fails closed on the native request marker; replacing the file without re-pinning
fails the independent digest check before parsing. There is no automatic upgrade,
fallback or learning of trust expectations from recipient evidence. The separate
trust-root original and its independent pin remain required and unchanged.

The app derives the full request hash from the actual validated request and sends
the existing purpose, hash, key/nonce, policy/binary and principal/route/credential
scope, original recipient evidence, and native-only `leaseRequestApiVersion`.
Native v1 forbids `requestAuthoritySha256`; v2 requires it and `dispatchSecret`.
The script returns exactly `ok: true`, `debug: false`, the same nine scope fields,
the native version marker, and the authority hash only when bound. The app checks
the exact native result key set and UTF-8 values against its own inputs. This
stdout result is a local process contract, not a signed or transferable credential.

The evidence remains `nativeCredentialRecipientEvidence/v1`: original Nitro COSE,
actual raw X25519 public key, role-2 runtime key binding, full request hash and
recipient nonce. The verifier repeats the independently pinned release, policy,
configuration, runtime CA, binary/PCR/EIF/module and current quote/chain checks.
Echoed scope is not a new standalone claim extracted from the quote. The trust
roots remain `nativeCredentialRecipientTrustRoots/v1`, with the existing native
PKI profile and empty CRL inventory; this supplies no vendor-CRL revocation proof.
Configuration provenance/currentness, app-process handoff and trusted local time
remain explicit operator responsibilities. The script reserves no nonce; the
real broker retains that responsibility after successful verification.

## Hashing, lifetime and effect boundaries

Native request/authority digests and envelope AAD use sorted compact Python
`ensure_ascii` JSON, including escaped DEL and UTF-16 surrogate-pair spelling.
The explicit native API version is included; old signed/encrypted bytes cannot
be relabeled. Legacy recipes remain unchanged. X25519, HKDF-SHA256, AES-256-GCM,
the original role-2 quote recipe and existing envelope HKDF domain are not replaced.
Successful decryption must still match the actual retained recipient owner, key,
nonce, request/authority, scope, credential generation and live authorization.

The same explicit native profile also selects the parent canonical-request and
operation digest recipe, including DEL escaping, through decision production,
reservation/lease validation, forwarding discard-header checks and Gmail parent
authorization checks. The latter use the actual native runtime or retained lease
profile, not a posted flag. Legacy helpers retain their original recipes; Gmail
child-request, child-authorization material and internal parent-decision-binding
v1 hashes are unchanged. This is an original-hash compatibility join, not new
provider, child-request or egress permission.

Existing limits remain: 96 KiB broker request, 64 KiB verifier stdin/stdout,
16 KiB expectations, 1 MiB trust roots, 12 KiB original quote, 64 KiB operation
context/public metadata, 4 MiB plaintext and 8 MiB envelope response. Requested
lease TTL is 1–5 seconds; actual current expiry and the original operation deadline
remain limiting bounds, not a renewed window. The schema definitions are data-only
and cannot replace original attestation, current policy/credential state, atomic
reservation, durable claims, fresh approval or the actual send-authority owner.

Native response compatibility does not authorize a provider call by itself.
Independent authorities, controlled dispatch and provider-specific policy still
apply. [Native egress](native-egress-installation-design.md) remains design-only;
scoped installation/network ownership, egress/canaries, full runtime acceptance,
lifecycle/recovery, off-host rollback protection and independent production gates
remain open. No build, test, interpreter, runtime, NSM or AWS/spend execution is
claimed for this source slice.
