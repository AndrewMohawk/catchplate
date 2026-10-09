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

### Actual proxy verification, 2026-10-09

The one-shot private checker passed on committed source
`a88e0678c7448ffc00276c4c8d1f349451dcae84` and the unchanged actual Rust executable
`sha256:f430734734cb43fb60eb1e28a863b337c314bb3e5377b23b6671564c62a91d9b`.
The fixture had three resource-limited, non-root containers, an internal-only
network, no published ports and no live data mounts. Running executable,
source hashes and shared publication-lock identity were verified before use.

Two assigned applications each dispatched using generation 1, then used
generation 2 on their **same original CONNECT/TLS connection** after a measured
5.250085786-second post-commit wait. The upstream fixture checked the actual
injected authorization value in all four requests. There were no reconnects,
functional retries, app-token changes or permission changes. The unchanged
10-second connection-head deadline remained in force. A third, unassigned
application was denied before upstream dispatch.

Exactly one key-replacement audit event and four paired release-start/terminal
records identified the actual credential generations; the audit queue drained
and the complete durable audit chain verified. The two policy reload events
belonged to initial rule creation, not key replacement. Issued dispatch-secret
leases were checked against the five-second per-issuance cap. This proves the
observed lease-expiry transition, not immediate remote invalidation or recall.

The checker finished successfully in 17 seconds. Evidence in the same directory
includes `checker.stdout.log`, `checker-receipt.json`, `isolation-result.json`,
the pinned preparation manifest and private runtime logs. Its source hash is
`ca43e7a8f051c601b136c8aa6f5f7343b38e257d5d405db264ecdfb41da99192`.
Production source hashes were unchanged after execution.

All task test containers and the private Compose network were removed after
successful termination. The private synthetic state was moved out of scratch
to `private-fixture-retained/` within the evidence directory, preserving its
ownership and private permissions. Its claimed checker must not be replayed.
The completed browser scopes left no processes; their empty scratch was removed.

The retained live `e19f8b5a` deployment is unchanged. These results do not
establish provider-key validity or revocation, real Google consent/refresh,
public-route, native, or production acceptance.
