# Measured NEW-credential OAuth in a durable Setup session

This additive source profile connects real controlled draft creation, measured
OAuth consent/issuance, protected pending staging and distinct-person credential
activation to the existing durable Setup row. It is not reconnect, a completed
Setup deployment, or runtime verification.

## Independent authority and cold selection

The actual admitted `catchplate.oauthApplicationStartup/v3` config selects
encrypted application material and **Setup-only new issuance**. Its closed six
fields, independent enrollment root, inherited protected descriptors and real
custody/configuration association remain mandatory. Versions1/2 retain their
old semantics. A browser profile label cannot select v3. The old unbound native
intent/consent/effect endpoints refuse a v3 enrollment; neither callback bytes
nor recovery observations switch purpose.

The independently signed authority configuration/v6 must explicitly include
`oauthMeasuredSetupPolicy` (`catchplate.oauthMeasuredSetupAuthorityPolicy/v1`)
and enable the new source-fixed operations:

- `oauth.setup.create`, `oauth.setup.activation-request`,
  `oauth.setup.activation-decide`, `oauth.setup.activate`,
  `oauth.setup.audit-settle`.
- `oauth.measured-setup.prepare`, `.claim`, `.capture`, `.stage`, `.recover`,
  `.cancel`.

The first four human operations consume genuine current hardware assertions
from actual authenticated OIDC credential owners. Activation additionally
consumes an exact approval by a different credential owner plus a new requester
assertion. This does not fabricate optional MFA evidence or change unrelated
authentication modes. The separate fixed native signing purpose is
`nativeOAuthSetupExchange.sign/v1`, with statement
`catchplate.nativeOAuthSetupExchangeStatement/v1` and its own schema+NUL Ed25519
domain and `catchplate/native-oauth-setup-exchange-attestation/v1` NSM nonce
domain. A legacy exchange statement, refresh assignment, HTTP status or copied
row is not this permission.

The native follow-on selects a distinct Setup configuration/listener/helper
owner, not two listeners on one port. CP v3 expects the explicitly provisioned
Setup callback origin. Native cold configuration and lifecycle are separate
source owners; source composition and runtime verification remain required.
The Setup draft returns through `#nativeOAuthSetupDraft=` and must contain
`catchplate.nativeOAuthSetupDraft/v1`; the old fragment cannot carry it. The
portal subsequently matches the actual cold-selected provider profile before
requesting options. The native-only authorization page consumes the distinct
`catchplate.nativeOAuthSetupAuthorizationRedirect/v1` response; the CP portal
does not interpret that response or choose a provider redirect from it.

## Actual row and original-byte connection

Controlled creation creates the existing draft `created` phase with revision0.
Template/principal/route IDs are draft selections; `routePolicyDigest` is
explicitly null. No policy review, canary or release success is manufactured.
Creation binds actual owner/assignee, provider, enrollment original and original
expiry, consumes a fresh requester assertion, checks a complete authenticated
Setup population, and commits session/event/audit association together.

| Protected transition | Session state | Retained source evidence |
| --- | --- | --- |
| `oauth.setup.create` | `created`, revision0, event1 | Exact created row, actual requester assertion, source-bound event/audit link |
| measured prepare | `oauth_started`, revision1, event2 | Initial binding + state/PKCE/consent originals, actual started row |
| measured stage | `oauth_verified`, revision2, event3 | Verified provider identity, normalized encrypted pending original, actual verified row |
| Setup activate | `credential_activated`, revision3, event4 | Exact pending + distinct-person approval + new requester assertion; credential/version1/currentness root/pending removal/session CAS committed atomically |

Cancellation before contact instead commits `cancelled`, revision2. No cleanup
or failed-provider outcome is inferred from expiry. All required revision/event
increments are source-bounded; generic binding revision is capped at i64max−4,
and this supported chain accepts only the exact revisions above.

The native intent/state v2 add exactly `setupBinding` (six fields: session ID,
revision, canonical row SHA256, owner, nullable assignee, original expiry). Every
native phase retains the **initial** binding; `setupBindingSha256` is part of
every signed statement. The separate protected `oauth_measured_setup_custody`
retains literal `setup_initial_json`, `setup_started_json` and nullable
`setup_final_json`. Current rows cannot replace the initial binding. Native
results contain exactly three row originals: `exchangeOriginal`,
`custodyOriginal`, `setupOriginal`, all canonical ASCII strings, not base64.

Actual native state, contact, retention, pending and recovery windows are
clipped to the immutable initial Setup expiry and independently admitted
enrollment/operation windows. A new read or callback does not reset them. Caller
metadata cannot contain `setup_session_id`, `setupSessionId`, or reconnect
aliases; stage adds no marker. The protected row/custody/pending connection,
not a metadata hint, supplies the association.

## Public producers and observation

The real HTTP producers are:

- `/api/setup/oauth/create/draft`, `/create/options`, `/create`: explicit draft
  review, fresh hardware options and one controlled creation submission.
- `/api/setup/oauth/native/intent`, `/native/options`, `/native/consent`: exact
  created-row binding, native-origin private preparation and requester consent.
- `/api/setup/oauth/pending/{id}/activation-original`,
  `/api/setup/oauth/activation/options`, `/api/setup/oauth/pending/{id}/activate`:
  exact staged-account inspection and separate Setup approval/activation.
- The actual `/api/control-plane/approvals/{id}/approve` route dispatches the
  **stored** `credential.oauth.setup-activate` purpose to its genuine owner.
  Generic mutation options cannot substitute for this profile.
- `/api/setup/oauth/sessions/{id}/original` and `/api/setup/oauth/audit-settle`:
  owner-authorized observation and protected factual audit settlement.
- `/api/data-plane/oauth-setup-issuance` and its `/original` route: fixed
  existing authenticated native transport, encrypted originals only. The effect
  endpoint independently verifies the fresh exact native proof; possession of
  the transport credential alone cannot authorize it.

The browser's dedicated controls retain public review originals in memory,
enforce explicit clicks and page-local one-attempt locks, and never persist an
assertion or approval authority. Only existing public form drafts and the
nonsecret Setup ID recovery hint use session storage. The server repeats actual
cookie/CSRF/current owner/credential checks. Browser data is never an authority
carrier. After uncertainty, keep session/pending/approval/event IDs and inspect;
neither a missing row nor loss of acknowledgement authorizes execution retry.

The native recovery acquisition request is
`catchplate.nativeOAuthSetupRecoveryOriginalRequest/v1` + exchangeId. Its
response is `catchplate.nativeOAuthSetupRecoveryOriginalResponse/v1`,
`okForAction:false`, and the exact three row originals. This SELECT-only response
is data, not permission to decrypt, contact or re-stage. A separately verified
fresh recover operation must consume actual retained capture/custody/current
Setup state, using the initial binding. Expired or changed Setup state refuses;
no provider contact can be repeated to resolve an unknown outcome.

## Real audit inclusion, not a transition digest

Each new controlled Setup event starts `audit_status=controlled_pending` and is
linked by the protected `oauth_setup_audit_links` relation to its exact metadata
audit outbox ID, request digest and event digest. The mutation's returned
`auditEventDigest` is **not** an audit-chain inclusion hash.

`oauth.setup.audit-settle` independently reads the exact event/link and actual
completed `metadata_audit_outbox` row. Only matching original event bytes,
completed status, authentic stored audit hash and completion time allow the
event to become `audited`. It does not advance a session or grant another
effect. Its own observation audit is distinct. Under actual v3 selection the
legacy Setup audit DML drainer is suppressed and reports
`protected-explicit-settle-required`; zero counts are not completion evidence.

## Bounded source acquisition

Capacity remains64 Setup rows, including retained/expired rows. No deletion,
archival, migration or capacity reset is authorized. Stage and activation retain
all three complete ordinary populations and both independently reconstructed
family-retirement roots. The existing fixed family pair admits combined32 rows
with declared allowance34; both SQL reads remain separately metered.

Declared query rows including the single framework audit-capacity query are:
create75, measured prepare210, measured stage240, Setup activate247,
activation request/decision12, audit settle5. The global256 bound is unchanged.
Complete root reconstruction and the actual acquisition-group checks precede
kernel/effect evaluation; no count-only absence claim replaces them.

Strict original bounds remain: Setup row64KiB, event64KiB, human arguments192KiB,
native arguments2MiB, custody row4MiB, machine HTTP request3MiB, signed runtime
response6MiB and combined HTTP response8MiB. Exact field types and cross-original
joins are checked before effect submission. Paired data contracts are in
`schemas/oauth-measured-setup-authority.v1.schema.json`.

This slice does not finish reconnect, post-expiry/token-family retirement for
the new Setup custody family, final Setup policy/canary/enrollment transitions,
capacity migration, runtime tests or a deployed pilot. No host-side token/client
plaintext, provider fallback, synthetic session completion or live provider
operation is introduced by source authoring.
