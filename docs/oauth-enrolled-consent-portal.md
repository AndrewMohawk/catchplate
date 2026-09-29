# Enrolled OAuth consent in the operator portal

The portal connects the existing [controlled consent/start/callback API](oauth-controlled-exchange-client.md)
to two explicit actions: prepare consent options, then use a fresh hardware
passkey and open the provider. This is source integration, not browser, provider,
provisioning or pilot evidence. Activation is a separate exact-account,
distinct-person ceremony; opening provider consent does not activate a credential.

Each portal response renders one fixed `enrolledOAuthProfile` from the actual
cold application-owner selector: `enrolled-new-credential-v1`, `development`, or
`unavailable`. A failed selection is unavailable, never development. Both portal
entry routes use the same renderer. This public discriminator only routes the UI;
the server independently rechecks the owner and every request. No HTTP error,
row label, echoed ciphertext or assertion metadata chooses a compatibility path.

The enrolled form requires an active, currently checked OIDC cookie with the
literal `credential_owner` role, a secure top-level page, and no entered bearer
credential. The UI can reveal the existing credential field but never clears it
on the operator's behalf. Existing sign-in, session activation and authentication
controls remain available. Requests use same-origin cookies and freshly fetched
CSRF tokens, not the generic mutation/resend helper.

The first click submits the selected provider, scopes, name and metadata to
`/api/oauth/consent/options`. The closed response is validated against that form,
provider and current context. Its 18-field request is retained only in page memory.
A bounded duplicate-rejecting parser preserves numeric token spellings and the
exact request substring: nanosecond integers never pass through JavaScript
`Number` or a parse/stringify round trip before submission. The request digest is
checked using sorted ASCII JSON while preserving those numeric tokens. The raw
request is not rendered, logged, downloaded or put in local/session storage.
Existing form-draft storage holds only its preexisting user-entered fields.

The second click obtains a real WebAuthn assertion for the opaque issued
challenge, checks its public shape/challenge/origin, and sends the original
request with the exact purpose-specific MFA to `/api/oauth/start` once. Browser
shape checks do not verify the signature or replace the server's independently
admitted physical authenticator trust. The selected hardware credential and
current policy remain server-authorized.

The original issued/contact deadlines, challenge expiry and a bounded monotonic
page-operation window constrain both actions. Starting a new browser operation
does not extend the retained options deadline. Actor, roles, credential trust,
policy, provider, form or setup-target changes discard the pending context and
abort an in-flight ceremony. Expiry does not restart it. Context and fresh cookie
checks bracket the assertion, start response and final navigation.

Navigation requires the closed successful start response, matching provider,
redirect, scopes, exact state commitment and expiry, and the configured HTTPS
authorization endpoint with the expected code/PKCE query. A late, mismatched,
ambiguous or failed response cannot navigate. A sent operation with an unknown
outcome blocks further submission from that page; there is no automatic resend,
412/428 loop, authorization restart or attempted-request fallback. Page locks
are not durable anti-replay authority: the protected server claim remains the
one-use boundary across pages/processes.

Enrolled setup and reconnect remain explicitly unavailable. Reconnect cannot
enter the old mutation helper or silently become new-credential consent. The
unconfigured development form retains its existing path. Controlled refresh,
recovery/revocation, cross-deployment subject fencing and independently measured
provider issuance remain separate work. This panel does not provision roots,
hardware trust or a running authority service, and has not been browser-tested.
