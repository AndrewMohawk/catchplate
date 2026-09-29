# Measured initial OAuth issuance

Status: source implementation only. No build, browser, provider, Nitro, KMS,
database or deployment acceptance has been performed. This profile covers new
Google/X credentials without setup or reconnect. Those complete successors,
issued-material cleanup, cross-deployment application coordination and broader
product requirements remain open; they are not replaced by this smaller flow.

## Two origins and actual confidential ingress

The existing parent-terminated `/api/oauth/callback/{provider}` cannot provide
no-parent custody: the authorization code has already crossed the parent's TLS
boundary before application encryption. This profile does not reuse that route,
encrypt in parent JavaScript, or weaken the workload mTLS listener.

Explicit native startup v9 requires `measuredIssuance` in addition to every v8
field, including actual encrypted service-token and guest-inspector owners. Its
gate selector is `--native-measured-issuance-startup-v9`; the image selector is
`--measured-issuance-v9`. No environment/config auto-selection is introduced.
The [v9 schema](../schemas/native-startup-configuration.v9.schema.json) and
[closed data bundle](../schemas/native-oauth-measured-exchange.v1.schema.json)
describe the supplied originals, not independent admission or operational proof.

The actual retained native CA generates a dedicated TLS 1.3 browser leaf. Its
private material remains in enclave memory. The same `Arc<BrowserTls>` is held
by the browser listener, sealed helper preparations and native signing method;
the leaf certificate/SPKI and independently assigned CA scope are bound to the
new role-4 statement. `browserVsockPort` is a separate fixed parent-CID listener.
Binding a colliding listener fails startup. This browser listener deliberately
does not request a workload client certificate: it has its own consent/cookie
authority, while the existing workload mTLS listener remains unchanged.

The existing [opaque parent ingress](native-parent-ingress.md) can forward a
separately configured public TCP endpoint to this exact enclave CID/browser
port. It neither terminates TLS nor supplies a trusted peer header. The
independently enrolled redirect is exactly
`callbackOrigin + /oauth/callback/google` or `/oauth/callback/x`, and differs
from the CP portal origin. Browsers must independently trust the admitted native
CA/origin; no certificate-warning bypass or self-signed acceptance is added.
Origin/DNS/certificate trust, provider redirect registration, fixed inbound and
outbound relay assignments and actual public reachability are external
provisioning prerequisites, not actions performed by this source work.

## Actual consent and one contact

The actual provider read projection labels only genuinely cold-selected
encrypted application profiles. The portal then uses these fixed human routes:

- `POST /api/oauth/native/intent`: current OIDC credential-owner cookie, CSRF
  and public name/scopes/metadata; returns public intent and the enrolled origin.
- Native `/oauth/begin`: explicit browser click generates state, HttpOnly
  `__Host-` cookie nonce and S256 PKCE verifier inside the helper. Only encrypted
  state, public commitments and measured draft evidence return to the portal.
- `POST /api/oauth/native/options` and `/consent`: fresh genuine hardware,
  UP/UV assertion over the exact draft, current credential/trust originals and
  requester role. The controlled prepare transaction consumes that assertion,
  reserves complete local capacity and records the original absolute bounds.
- Native `/oauth/authorize`: the same-browser native cookie and exact signed
  prepare receipt are rechecked before the source-fixed provider authorization
  URL is returned. No token POST has happened yet.
- Native callback: actual TLS request path/provider, cookie, state and exact
  code/contact commitments select an irreversible controlled claim. Only its
  definite authenticated receipt allows the single provider token POST.

The portal retains no private state/code/verifier/cookie. Its encrypted return
and signed-receipt handoffs use bounded top-level navigation fragments, cleared
immediately on receipt, never local/session storage, logs or rendered raw
responses. Existing public form-draft storage is unchanged. Epoch nanoseconds
are preserved as numeric lexemes, not JavaScript `Number`. A fresh passkey is
always an explicit click; there is no resend loop after uncertain submission.
The fixed browser profile bounds returned preparations at 512 KiB and receipt
navigation at 768 KiB. An oversized receipt is refused, not split or retried;
browser-specific URL capacity remains an acceptance prerequisite. General
machine request/response limits remain 3/8 MiB respectively.
The initial native owner also retains at most 16 draft identities for its
original lifetime, including terminal drafts; it never evicts a consumed slot
to manufacture retry capacity. Larger-capacity lifecycle handling remains
separate work, not a production-completeness claim.

The helper alone opens the independently admitted encrypted client material,
constructs the fixed provider request and terminates verified provider TLS.
Google token TLS targets `oauth2.googleapis.com`; X token TLS targets
`api.twitter.com`. A separate fixed identity GET uses
`openidconnect.googleapis.com` or `api.x.com`. Only TLS records traverse the
parent relay. No arbitrary URL, redirect, ambient trust, plaintext RPC or
caller-provided provider-success boolean is accepted.

## Purpose, capture and atomic pending storage

The independently signed measured configuration has an explicit
`oauthMeasuredExchangePolicy` purpose block and separately enabled operations:
`oauth.measured-exchange.prepare`, `.claim`, `.capture`, `.stage`, `.recover`
and `.cancel`. Both actual verifier and planner authenticate the enrollment,
independent current purpose, original role-4 signature/NSM evidence, current
configuration/deployment/instance, original provider/CA/binary scope and exact
request. Refresh, old consent, cleanup and audit assignments grant no permission
to this new family. Old exchange operations refuse these assigned enrollments.

The new statement/sign operation is `nativeOAuthExchange.sign/v1`, not a
response or refresh alias. It is constructed only from the sealed native
helper/browser owner; original COSE, certificate chain, PCRs, boot/key and fresh
purpose nonce are verified. Hardware requester evidence is independently
required for prepare, not inferred from this machine signature.

`oauth_exchange_reservations` preserves stable exchange identity and original
consent; `oauth_measured_exchange_custody` retains exact prepare/claim/capture/
stage/cancel/recovery argument originals. The real controlled metadata owner
serializes protected roots, complete bounded populations, work, pending and
audit changes. No runtime DML grant or separate success callback is added.

After the one token POST, raw response bytes and minimal issued material are
encrypted immediately under exact deterministic artifact IDs/version-1 AAD.
The actual controlled capture stores both originals before the helper accepts
its signed commit acknowledgement. Normalization and identity GET occur only
after that receipt. A malformed reply can be retained without a stageable token;
it cannot mint pending authority or trigger inline revocation.

The token response is bounded to 96 KiB, identity body to 64 KiB, raw/token
originals to the existing bounded encryption profile, and each envelope to
256 KiB. The final normalized token envelope is distinct from the minimal issued
capture; no false ciphertext-equality assertion is used. Actual provider subject,
application association, granted scopes and original response time determine
review and expiry. Atomic staging preserves Google complete-population collision
guards, family-retirement fences, authoritative setup absence, pending/backlog
bounds, exact work consumption and audit. It creates a pending credential, not
an active one. Existing separate activation approval remains required.

The native owner serializes private OAuth helper protocols with refresh. It
retains the original process, generated key, listener, active shutdown handle
and scoped runtime lifetime. Incoming browser operations narrow their actual
kernel socket deadline to at most 30 seconds; they cannot reset it per read.
Cancellation closes the active browser socket and joins scoped tasks. This is
not a hard watchdog or proof of remote provider termination.

## Interruption and known-capture recovery

No lost response, timeout, expiry or absent row proves that contact did not
happen. A committed claim with no durable provider response remains uncertain;
the provider POST is never repeated. A cancelled callback records exact encrypted
callback/error originals only while still prepared and cannot clear a claim.
The retained work source is `measured-oauth-exchange/v1`; SELECT-only operator
observations include all its states with no expiry mutation, deletion or
permission to reuse the legacy cleanup worker.
Even an otherwise development deployment with a cold encrypted application
refuses the legacy reconciliation branch before its expiry/decryption writes;
an absent cleanup owner is not permission to expose or retry measured material.

Explicit cold `recoveryTargets` are sorted exact exchange IDs. Startup obtains
only encrypted data from `/api/data-plane/oauth-issuance/original`, then the
actual helper forms a fresh `.recover` request. Independent current processing
authority must match the exact durable custody row and capture input. Historical
enrollment authenticity is retained without requiring its old contact window
to be live or renewing that window. The original pending expiry still bounds
staging. A fresh recovery nonce and <=30-second processing interval are consumed
once; uncertainty cannot reopen them.

After a definite recovery receipt, the helper can decrypt the exact known
capture and make one fixed identity GET to finish the measured review. It cannot
POST a code, reissue tokens, substitute ciphertext, repair unknown history or
renew token expiry. Already-staged observation requires the actual pending row
to equal its retained original; absence or a later activation is not inferred
as completion. Unknown capture/claim outcomes remain closed. No independent
provider signature, cross-deployment completeness or provisioned runtime
acceptance is claimed by encrypted bytes, a local inventory or this guide.
