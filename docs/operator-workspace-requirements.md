# Credential-first operator workspace

## Requirement and scope

The operator's October 8 feedback is the design input: connect an account such
as Google for unattended application use, or specify credential replacement
without having to author a response-field projection. The product remains a
credential-control proxy, not a mechanism for distributing provider tokens.

The existing combined demo form stores a credential, creates a 24-hour client
identity, and grants one projected-JSON route together. Those are distinct
resources. Simplifying labels without separating their lifecycles would not
meet the requirement.

This workspace changes the development profile only. It does not satisfy or
remove native commissioning, independent custody, production approval, provider
ownership, public routing, or production acceptance requirements. No deployment
is established by this document or by source tests.

## Resource model

- **Credentials and accounts:** a named encrypted credential or verified OAuth
  account. Saving a static credential requires its name, authentication type,
  value, and applicable header name, not an endpoint or response schema. The
  existing encrypted credential database remains the only secret store.
- **Applications:** the identity used by one client or job to authenticate to
  Serverware. Creation and rotation return a client token once; only its verifier
  is persisted. Lifetime is explicit and finite. Provider-token refresh and
  client-token rotation are independent operations.
- **Access rules:** references to an application and credential, the approved
  destination and operations, and any optional additional restrictions. No rule
  means no access. Merely saving a credential or application grants nothing.
- **Proxy setup:** endpoint, client-scoped CA trust, and actual supported client
  instructions. The console and forward-proxy addresses remain distinct.
- **Audit:** explain configuration changes and request decisions without exposing
  provider secrets, client tokens, or OAuth token responses.

One credential may serve several rules and applications. Removing an
application's access cannot delete that shared credential. Removing a credential
with active assignments requires an explicit affected-application workflow; it
must not silently cascade from an ordinary application action. Local removal
is not provider-side revocation or forensic erasure of historical database pages.

## User journeys and acceptance

The default journey is **connect an account, choose an application, allow its
use, copy the client setup**. Separate resources must not become disconnected
administrative chores. The overview should show the next unfinished step and
each resource should link to its assignments. Advanced controls belong behind
an explicit restriction choice, with a plain-language summary of what will be
allowed before publication.

The two basic onboarding paths are:

1. **API key or password:** name the credential and store its value. When granting
   access, choose the destination and credential placement. A replacement rule
   identifies one specific header and an exact nonsecret placeholder; it is not
   a global search-and-replace over arbitrary request bytes. The workload's
   Serverware identity is separate from that placeholder and must never be
   forwarded to the provider.
2. **Connect Google:** administrator setup supplies the OAuth application once;
   the account owner consents to the chosen permissions. Applications use the
   connected account without receiving its provider tokens. The normal flow
   refreshes access automatically; provider-required reauthorization is a
   distinct, exceptional action, not a daily setup step.

For a basic replacement rule, **do not filter response content** is a legitimate
explicit choice, not an empty or wildcard field projection. The interface must
state supported formats and remaining transport/disclosure limits. If a selected
preset requires response-side evidence, such as Gmail message age, that check
cannot silently disappear when content filtering is disabled.

| Journey | Evidence required |
| --- | --- |
| Save a static credential | Browser-to-API persistence succeeds without route or response fields; no signed access policy changes and no provider request is made. |
| Share a credential | Two independently authenticated applications can use their own permitted rules referencing the same encrypted credential. |
| Remove one application's access | After the new policy is actually loaded, the revoked client cannot dispatch, including with a previously warmed credential cache; the other application still works. |
| Rotate a client token | The new token is disclosed once, the old verifier is replaced in the signed policy, and old-token rejection is verified after activation. No provider refresh or reconnection occurs. |
| Restart or migrate | Existing credential ciphertext, IDs, token verifiers/expiry, nonce history, policy bytes/hash/sequence and high-water state are preserved; a restart neither renews tokens nor grants new access. |
| Connect Google | Real consent identifies the account and granted permissions; a proxy request obtains only an injected access token, with no provider token handed to the application. |
| Run Google unattended | A request after access-token expiry completes through actual refresh, generation reconciliation and durable storage; concurrent callers do not race token rotation. Provider-required reauthorization is distinct from transient failure. |
| Replace a configured value | A normal client with the configured placeholder succeeds; unrelated, ambiguous or mismatching input does not select or reveal a credential. Existing insertion-only rules retain their behavior. |
| Apply no response content filter | Supported responses retain their logical content without a user-written field allowlist; protocol, size, timeout, target, safe-header and disclosure controls still apply. Unsupported formats are explicit, not silently transformed or advertised as supported. |

Google OAuth application configuration belongs to administrator setup. An
account owner still performs initial consent. The interface should show the
verified account, permissions, refresh/reconnection state and affected
applications, not access or refresh tokens. An OAuth source implementation is
not evidence of a working deployed provider integration.
The [Google integration plan](operator-google-integration-plan.md) records the
remaining catalog, consent and unattended-refresh work, including why a generic
generation-conflict response is not permission to retry credential issuance.

## Compatibility and migration

Import existing combined connection metadata transactionally into separate
catalog records. Preserve the existing encrypted credential rows and each
connection's application identity, token verifier, expiration and rule identity.
Migration does not sign, advance or replace the committed policy. Mark the
catalog schema version only after the complete import validates.

Catalog mutation uses revision compare-and-swap, and access-changing mutation
also binds the expected committed policy hash. Data, policy publication and
redacted audit changes commit together. A database commit followed by a failed
policy-file write is pending publication, not an invented rollback or active
policy. Actual loaded-policy observation determines enforcement.

Once the catalog is active, legacy combined creation/revocation must refuse
instead of reinterpreting a shared resource as a disposable one-to-one
connection. Preserve historical receipts. Do not reset history, reuse retained
identifiers, silently renew a client token, or automatically retry an uncertain
mutation. Status remains available for reconciliation.

## Incremental delivery is not completion

The workspace now offers an explicit bounded whole-JSON response choice as
well as selected-field projection. New UI rules prefer the whole-JSON choice
when advertised; the API's omitted mode still requires the historical
projection. Existing saved policies are not broadened. Text, binary, compression
and streaming compatibility remain separate requirements, not capabilities of
the JSON-only choice.

The advertised modes describe this source version, not dynamic negotiation
with an arbitrary running proxy. Deployment must pin a compatible control plane
and gate supporting `bufferedPassthrough`, and establish private actual-proxy
acceptance before rollout. An old gate must reject an unsupported policy; never
silently substitute another response mode. Saved state is not active until the
backend reports active publication and the loaded hash matches the saved hash.

Per-rule header replacement is implemented in the catalog, UI and Rust source;
actual proxy acceptance remains separate. Google profile integration and the
real-provider consent/refresh journey are still open requirements. Do not
present inactive OAuth controls, a health check, fixture-only browser success
or a JSON-only response mode as completion of those journeys.

Client placeholder matching belongs to an access rule, not the reusable secret.
Two applications sharing a credential may use different dummy values, or one
may need insertion without any dummy header. The provider header target still
comes from the credential's injection contract. The placeholder is public client
configuration, never a provider secret or an application authentication token.
The [replacement guide](exact-header-replacement.md) describes that client
journey and its exact supported header contract.

## What the original examples imply

| Example | What the operator should configure | What must remain enforced |
| --- | --- | --- |
| Gmail recent mail | Connect Google; choose read-only mail and an optional age limit. | Verified account and scopes; message routes and response-side age evidence, not only a rewritten query. |
| X daily posting | Connect the X account; allow posting with a daily quota. | Shared provider-account quota across applications; changing a client identity cannot reset it. |
| npm publishing | Store the publishing credential; choose package and allowed hours. | Typed publish operations, exact package and schedule; a time window permits requests rather than scheduling a job. |
| ECR image publication | Select account, region and repository; require approval for the exact image. | Request-bound, one-use human approval before credential use. Publication is not enclave deployment or attestation. |
| Ordinary API client | Store the key; select destination and credential placement. | Application identity, explicit destination/operation permission and exact replacement semantics; no compulsory content projection. |

These are user-facing presets over the existing policy mechanisms, not reasons
to expose their entire schema during credential creation. The current generic
rule editor cannot express all of them; the README explicitly keeps ECR-specific
integration open. Selecting a restriction still requires its actual request and
response enforcement, and choosing an unfiltered mode must not silently discard
it.

Account connectivity/refresh health, application-token validity and actual rule
activation must be three separately visible states. A healthy Google grant does
not renew an expired Serverware application token. A temporary refresh failure
must not be labeled lost consent without provider evidence. Existing Google
disconnect/reconnect and native ownership boundaries remain explicit; do not
work around them with a pasted refresh token or a hidden legacy fallback.

## Remaining ordinary-client usability gaps

The current source is not yet a general "just replace authentication" proxy.
Removing mandatory response projection solves only one part of that journey:

- An empty request-field list currently forbids a body. Ordinary JSON POSTs
  still need field declarations; a future unchanged-request-content mode needs
  an explicit backend contract, not merely a collapsed form section.
- Query names default to none, and forwarded client headers default to
  `accept` and `user-agent`. An example-request importer could suggest those
  names locally for explicit approval; it must not silently broaden access.
- Saved-rule summaries should include body, query and header restrictions as
  well as destination, exact path and methods. Collapsing advanced editors must
  not hide what the application will actually be allowed to send.
- Generated cURL is currently a connection template, without body or query
  values. Lead with settings for an existing client, or explicitly build a
  complete example from supplied sample input without executing it.
- Whole-JSON responses retain status-code, body-presence, size and safe-header
  restrictions; `204 No Content` is not supported by the current envelope.
  Text, binary and streaming remain open compatibility work. The current
  CONNECT parser also requires canonical query ordering. Ordinary-client
  compatibility needs explicit implementation and proof, not a claim that
  "no response filter" removes these protocol restrictions.

Destination and operation permissions remain necessary even in the simple
journey. Optional content restrictions and provider-specific presets should be
separate choices, with a short effective-permission summary before publication.
