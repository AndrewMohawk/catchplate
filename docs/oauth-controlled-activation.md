# Cold-owned OAuth pending activation

This source profile connects an independently enrolled OAuth application to a
purpose-controlled approval and atomic activation path. It supports a new
credential only: the pending row must have no reconnect target and no setup
session association. It is not a completed consent-to-credential flow or a tested
pilot. The separate [enrolled exchange client](oauth-controlled-exchange-client.md)
now connects new-credential consent, one-shot exchange, retained material and
pending staging in source. Reconnect, refresh, setup and portal ceremonies remain
unfinished; unconfigured development behavior remains explicitly separate.

## Independently admitted originals

The HTTP adapter retains the actual cold OAuth application operation, custody
client, signed enrollment bytes, provider/client configuration and exact pending
row original. The authority independently admits that enrollment under the
purpose-specific root in its signed `oauthActivationPolicy`; it does not trust a
root or policy supplied by the HTTP caller. See
[OAuth application ownership](oauth-application-ownership.md).

The request binding has exactly `pendingCredentialId`, `pendingRowSha256`,
`enrollmentSha256` and `payloadDigest`. The pending digest covers all 26 SQL
columns, including the ciphertext, with canonical sorted ASCII JSON. The public
request does not contain that ciphertext. `payloadDigest` retains the existing
pending review/token commitment; it is not relabeled as the complete row digest.

Each HTTP ceremony starts a bounded wall/monotonic lifetime of at most 30 seconds,
narrowed by the retained application, pending row, selected approval and actual
WebAuthn challenge expiries. Checks repeat the original request, current actor,
configuration, physical credential trust and retained enrollment. A new
assertion cannot extend an enrollment or pending-row expiry.

## HTTP ceremony

Both people must be currently authenticated OIDC actors with the actual
`credential_owner` role. The ordinary administrator-role override does not
satisfy this purpose. Existing API authentication and CSRF checks remain in
force. The approver must be a different actor from the requester.

1. `GET /api/oauth/pending/{id}/activation-original` performs SELECT-only
   inspection under the actual cold owner. Its eight fields are `apiVersion`
   (`serverware.oauthActivationOriginal/v1`), `action`, `resourceId`,
   `payloadDigest`, `request`, `review`, `requesterId` and `expiresAt`. This is
   review data, not an activation permit. It neither expires nor rewrites rows.
2. `POST /api/control-plane/mutations/webauthn/options` accepts the explicit
   `apiVersion: serverware.oauthActivationApprovalOptions/v1`,
   `action: credential.oauth.activate`, exact `resourceId`, `payloadDigest` and
   `request`, plus optional `approvalId`. With no approval ID, only the pending
   requester can obtain request options. With an ID, the actual stored requester
   selects activation options; a distinct actor selects decision options.
3. The requester submits the resulting genuine assertion to
   `POST /api/oauth/pending/{id}/activate`. MFA is exactly
   `oauthActivationProfile: serverware.oauthActivationApprovalOptions/v1` and
   `assertion`. A definite approval request returns the existing 428
   `control_plane_approval_required` response with its approval ID. This is an
   explicit continuation, not activation success or automatic resend authority.
4. The distinct approver obtains their own options for the same exact request
   and approval ID, then uses
   `POST /api/control-plane/approvals/{approvalId}/approve` with `note: null` and
   MFA containing the profile and their fresh assertion. Approver MFA must not
   contain `approvalId`.
5. The requester obtains fresh activation options for that approved ID and
   explicitly submits activation again. This MFA has the profile, fresh
   assertion and `approvalId`. Non-null `setupSessionId` or `setupRevision` is
   refused by this profile.

Options return only `publicKey` and `serverware`. The latter is the closed
seven-field `schema`, `operation`, `operationId`, `challengeId`,
`credentialRecordId`, `payloadDigest`, `expiresAt` projection. The authority
challenge is opaque; it is not the old generic options hash. Assertions are
verified by the actual purpose-authorized verifier against current admitted
hardware trust, user presence and user verification. Assertion metadata is not
substituted for that verification. Canonical MFA is limited to 16 KiB.

## One atomic mutation boundary

The source-fixed operations are `oauth-activation-approval.request`,
`oauth-activation-approval.decide` and `oauth.pending.activate`. There is no
standalone consume operation. Activation consumes the exact approval, inserts
the credential and generation head, removes the pending row and writes its audit
event in one controlled transition. The pending ciphertext is preserved; the
HTTP adapter neither decrypts nor re-encrypts it and performs no credential DML.

The adapter uses the actual cold custody client's verified response path with
its original deadline. It then compares the definite result to SELECT-only
public readback, including the consumed approval and secret-free credential
projection. Unknown, late, conflicting or uncertain outcomes are blocked with
no automatic retry and no fallback to generic runtime writes. This profile does
not add approval, ciphertext or token data to logs.

The existing portal has not been connected to this new ceremony by this slice.
Deployment still requires independently provisioned enrollment authority,
matching signed authority configuration and current physical authenticator
trust. Shared fenced subject coordination across deployments, external
application coordination and measured pre-subject issuance remain separate
unfinished work. This source has not been built, executed or provisioned as a
running pilot.
