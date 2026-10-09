> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Replace a saved provider key

This operator-development workflow changes the secret behind a saved static
credential without creating another credential, application or permission.
It does not reconnect OAuth accounts, revoke a key at its provider, or establish
native or production acceptance.

## Operator flow

Open **Credentials**, choose **Replace key**, review the affected applications,
and enter the new provider value. Authentication placement, destinations,
application identities and access rules remain unchanged. There is no response
configuration step. The form never retrieves the old key and clears the new
value when submitted, cancelled, navigated away from, or invalidated by changed
saved state.

The action appears only for active bearer/custom-header credentials when the
server advertises the exact `serverware.operatorStaticKeyReplacement/v1`
capability. Google accounts use a different lifecycle and cannot use this action.

## Transaction and API

`POST /api/operator-demo/credentials/replace-key` accepts the credential `id`,
`expected_revision`, `expected_policy_hash`, `expected_credential_generation`
and `secret`. Existing administrator authentication, exact same-origin checks,
strict JSON parsing and the 16 KiB transport limit apply.

The core credential generation is distinct from the catalog resource version.
Both are read from committed state; the secret, generation history, catalog
version/revision and redacted audit event commit in one SQLite transaction under
the existing publication lock. Stale reviews refuse rather than overwrite.
The encrypted envelope implementation is reused, without decrypting the old
value or creating an equality oracle. Submitting an identical value explicitly
advances the generation as well.

The credential ID, name, authentication kind/header, provider identity,
application verifiers, access rules and signed policy remain unchanged.
Only nonsecret generation numbers and replacement time appear in the public
receipt/catalog. A failed audit append must roll back the entire transaction.

A failed/lost response does not establish rollback. The UI never retries the
POST automatically. A missing, malformed or mismatched confirmation requires a
fresh saved-state review before further changes, including when the POST was
acknowledged but the subsequent catalog read could not be confirmed.

## Lease transition is not immediate revocation

After commit, new secret issuance must match the new generation. A request
pinned to a stale generation fails closed; this workflow adds no static-key
retry or Google-style reconciliation.

Previously issued Rust generation/secret leases may remain valid until their
expiry or until the gate observes the new generation. Operator issuance caps
each lease at five seconds, but that is not an availability deadline or an
acknowledgement that every proxy has switched. Already-dispatched requests are
not recalled. Clearing this Python process's cache does not clear remote gate
caches, and reloading an identical policy is not a cutover mechanism.

The UI therefore reports **Replacement saved**, not **all proxies updated** or
**provider key verified**. Revoke the old key with its provider separately;
replacement here does not perform or prove that action.

## Verification status

Focused synthetic checks passed in separate bounded, network-none containers:

- SQLite/encryption: 13 tests in 108.653 seconds.
- Actual loopback HTTP, including replacement and restart: 5 tests in 91.992 seconds.
- Offline assets: 10 tests in 0.053 seconds.

The isolated browser passed 13 rendered groups across 19 contexts plus one pure
projection group. These used intercepted fixtures, not joined backend or proxy
traffic. Desktop/mobile review screenshots were inspected. Logs are retained in
`/srv/catchplate-fast/projects/serverware-operator-workspace-evidence/key-replacement.tZFBOn1X`
(`store.log`, `api.log`, `assets.log`, `browser.log`); screenshots are in
`/srv/catchplate-fast/projects/serverware-operator-artifacts/key-replacement-browser-synthetic-qD7DCk`.

The existing Connect browser regression passed all 24 rendered groups, and
Google setup passed five rendered groups plus its pure generator/label checks
on the same unchanged production sources. Their logs are `connect-regression.log`
and `google-regression.log` in the same evidence directory. Neither suite
contacted a live service or executed generated client commands.

The private actual Rust proxy replacement checker has **not** been executed;
the retained live `e19` deployment is unchanged. These results do not establish
remote lease/cache transition, provider-key validity or revocation, public-route,
native, or production acceptance.
