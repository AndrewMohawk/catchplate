# Native OAuth issuance bound to durable Setup

This source path joins [protected Setup transitions](measured-oauth-setup.md)
to an actual native browser listener, private helper, purpose-specific signer
and writer receipt verifier. It is not runtime evidence or whole Setup/reconnect
completion. Ordinary application/service authentication remains in scope.

## Explicit cold selection

Native startup v15 contains the same actual owners as v14, including the gate
cgroup, encrypted service tokens, guest roles, measured refresh and retirement.
It **replaces** required `measuredIssuance` with required `measuredSetup`.
Select `--native-measured-setup-startup-v15`, or the image entrypoint selector
`--measured-setup-v15`. Earlier versions and the default v6 remain unchanged.

There is exactly one browser/helper issuance purpose in a profile. It is selected
before serving, not inferred from a callback, request label or successful legacy
receipt. The same generated native CA/TLS owner is retained by the listener,
Accepted request, broker configuration and signing preparation; the helper also
rejects simultaneous Setup and unbound issuance configuration.

The [cold contract](../schemas/native-oauth-measured-setup.v1.schema.json) adds
required `setupLimits`: capacity 64 and maximum session lifetime 300–604800
seconds, exactly equal to the separately signed authority policy. These limits
do not extend an existing session. Callback and portal are distinct exact HTTPS
origins. Applications contain encrypted materials and independent enrollment,
not parent-readable client secrets.

## One continuous Setup journey

The control plane creates the genuine initial Setup row. The native helper
retains its six-field binding: session, revision, row hash, owner, current
assignee and original expiry. Its v2 intent/private state is distinct from
unbound v1 issuance. Owner/requester equality and unchanged assignee/expiry are
checked again at actual signed writer receipts, not trusted from browser input.

The native origin serves the fixed begin/draft/authorize/callback routes.
It returns `#nativeOAuthSetupDraft=` to the portal with the distinct
`serverware.nativeOAuthSetupDraft/v1` document. The portal obtains genuine
hardware consent and returns exact writer originals to the native origin.
Only verified consent permits helper-only client opening and provider redirect.
The native page accepts only its Setup authorization-redirect schema.

The signer accepts a sealed Setup preparation from the real helper, never
arbitrary JSON or a host UDS fallback. Its separate statement, signature and
attestation domains bind the original Setup hash, actual TLS leaf, role, boot,
binary, policy and unchanged operation interval. Shared TLS/scalar helpers do
not convert an old signed grant into Setup authority.

The fixed machine endpoint is `/api/data-plane/oauth-setup-issuance`.
Each effect follows its own actual writer receipt. An irreversible claim
precedes the token POST; durable encrypted raw capture precedes normalization,
identity lookup and atomic pending/Setup staging. All helper protocols share
the actual native OAuth serialization guard.

The helper retains all three exact Setup originals: initial, started and final.
Prepare/claim/capture use started, stage uses verified, and cancellation uses
cancelled. Only the defined field deltas are accepted; a new current row cannot
replace the original consent binding. Credential activation remains the
separately approved control-plane transaction.

## Recovery and acceptance boundary

Cold-selected recovery acquires three encrypted/data-only row originals from
`/api/data-plane/oauth-setup-issuance/original`. It does not treat acquisition
or an HTTP status as authority. Fresh Setup-specific recovery permission and an
actual signed receipt precede private state opening. Captured recovery may
perform the already authorized fixed identity GET, but never repeat the token
POST. Already-staged recovery is observation only. Unknown outcomes, changed
owners, missing originals and expired windows do not grant retry or renewal.

This integration does not complete reconnect, later policy/canary/enrollment
Setup steps, pre-subject cleanup, migration or global lifecycle. Independent
enrollment/purpose/role assignments, KMS custody, real Nitro and provider
execution, trusted hardware ceremonies and frozen end-to-end verification
remain required. No build, test, browser, provider or cloud execution is claimed.
