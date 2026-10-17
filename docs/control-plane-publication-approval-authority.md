# Purpose-bound publication approval authority

The interrupted admin-token publication resolver has a dedicated cold-custody
approval path. It connects actual HTTP identity, raw WebAuthn assertions, current
physical authenticator trust, selected approval rows and controlled metadata
commits. It does not grant generic runtime database writes or turn verifier JSON
into authority. This is source integration only: unprovisioned, unexecuted, with
no browser, physical-authenticator, database-service or pilot success claimed.

## Independent prerequisites

The operator needs independently usable active OIDC administrator access and a
currently admitted hardware or YubiKey credential. Requester and approver must be
different current administrators. This purpose requires hardware attestation,
user presence and user verification for both people, even where ordinary actions
permit optional MFA. A stored class label or verifier signature alone is not
physical trust: actual assertion verification, the current proved trust state,
credential policy and independently validated attestation must agree.

[Cold control-plane custody](control-plane-custody-startup.md) must be genuinely
started with the independently provisioned authority services, protected current
configuration and pinned operation contract. The ordinary runtime metadata ACL
is not widened. Challenge issuance uses the actual `webauthn.challenge.create`
authority operation; approval changes use only the four purpose-bound operations
below. Missing custody, current hardware trust or an admitted service fails
closed. The new profile never falls back to generic development metadata DML.
Old generic callers are not silently promoted into this profile.

## Exact public ceremony

`POST /api/control-plane/mutations/webauthn/options` accepts the new closed input:

- `apiVersion`: `catchplate.publicationApprovalOptions/v1`.
- `action`: `control_plane.token.publication.resolve`.
- `resourceId`: `admin-token`.
- `payloadDigest`: SHA-256 of the existing canonical ASCII request binding.
- `request`: exactly `token: "admin"`, `publicationId`, `intentSha256`, `outcome`
  and required nullable `reason`.
- Optional `approvalId`, absent/null for the initial request and the exact
  selected row ID for either continuation.

The token selector remains `admin`; it is not the `admin-token` resource name.
The binding codec is sorted compact JSON with Python `ensure_ascii=True`, no LF,
and a maximum 8192 bytes. The two outcomes remain `finalize-installed` and
`abandon-uninstalled`; reason is null or at most 500 characters. The server checks
the digest rather than trusting a supplied hash.

With no approval ID the server selects `publication-approval.request`. With an
ID it rereads the exact row: the same requester and approved state select
`publication-approval.consume`; a different actor and pending state select
`publication-approval.decide`. No caller-provided phase or approver identity
overrides those joins.

The result is exactly `{publicKey, catchplate}`. `publicKey` has challenge, rpId,
one two-field public-key credential descriptor in allowCredentials, timeout
120000, and userVerification `required`. `catchplate` has exactly schema,
operation, operationId, challengeId, credentialRecordId, payloadDigest and
expiresAt. Operation/challenge IDs are prefixed SHA-256 values; the credential
record ID is opaque, not assumed to be a UUID. The authority-issued challenge is
canonical base64url, not the hash of an unsigned generic options payload.
These fields let the panel reject mismatched responses; they are not signature
verification or transferable permission.

The unchanged resolver route receives publicationId, intentSha256, outcome,
required nullable reason and mfa. The purpose MFA contains
`publicationProfile: "catchplate.publicationApprovalOptions/v1"` and the raw
assertion; only the continuing requester also supplies approvalId. The distinct
approver uses the existing `/api/control-plane/approvals/{id}/approve` route with
exactly `note: null` and purpose MFA. A fresh assertion is required separately for
request, decision and consumption. The requester must click explicitly after
the exact 428 continuation and distinct approval; there is no automatic resend.

The [panel guide](portal-admin-token-publication.md) describes cookie-only access,
manual bearer clearing, current-context invalidation and uncertain-response
blocking. The [schema bundle](../schemas/control-plane-publication-approval.v1.schema.json)
describes these closed producer bodies and source-owned argument/record shapes;
schema validation cannot establish identity, signature, currentness or commit.

## Controlled operations and durable resolution

`publication-approval.request`, `.decide` and `.consume` share seven exact
arguments: action, resource_id, payload_digest, actor_id, request, approval_id
and credential_policy. Approval ID is null only for request. Actual raw assertion
evidence is added by the retained caller for the isolated verifier, not replaced
by a successful-verification flag. The current credential policy has seven
fields: rpId, origins, allowedAuthenticatorClasses, hardwareRequired,
requireUserPresence, requireUserVerification and maxAssertionAgeSeconds.
The source translates hardwareRequired into the existing physical-trust policy
inside the retained verifier; it does not widen the generic authority input guard
or relabel old policy formats.

`publication-approval.settle` is audit-only. Its eight arguments replace
credential_policy with consumption_request_digest and completion_sha256; it
does not issue a new assertion, grant consumption or perform a filesystem effect.
The resolver can invoke it only after definite owned consumption and its exact
protected completion record. Signed response/commit bindings and actual selected
rows are checked by the cold client; a supplied operationId or success object is
not a substitute. All argument originals are canonical-bounded to 32 KiB.

The actual resolver retains its original wall/monotonic allowance, request,
actor, policy, files and locks. Challenge and approval expiries can only narrow
that allowance. Options and later human actions are separate fresh requests;
they do not renew an already executing resolver or replay a consumed attempt.

Before the single controlled consumption attempt, an append-only
`catchplate.adminTokenPublicationResolutionClaim/v2` record pins the actual
authorityRequestDigest and corresponding controlled audit UUID, alongside the
unchanged exact file/intent/approval bindings. A claim is not committed-approval
proof. Definite consumption permits fsync/readback of the already held token
originals, parent and journal, then the unchanged resolution-complete/v1 record.
Audit-only settlement returns its actual request commitment before
resolution-settled/v2 records that digest and controlled audit UUID. Old v1
records remain distinct; historical authority request digests are not recomputed
using a later operation manifest.

The unchanged public success has seven fields and reports server settlement,
not token disclosure or a running service. No token bytes are renamed or rewritten,
no plaintext is returned, and no records are pruned. Unknown consumption,
completion or settlement stays blocked without retry. Malformed/orphaned history,
off-host rollback, multi-host coordination, independent archival and other
provider/filesystem effects are outside this profile. A later rotation is a new
independent action anchored to definite terminal evidence.

Implementation: `control_plane_publication_authorization.py` retains HTTP/cold
owners; `authority_publication_approval.py` defines closed purpose originals;
`authority_transition_publication_approval.py` implements the purpose-specific
metadata transitions. The existing resolver and publisher retain actual file
custody. None of these source connections proves their independent production
provisioning or runtime acceptance.
