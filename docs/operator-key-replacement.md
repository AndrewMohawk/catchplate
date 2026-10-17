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
server advertises the exact `catchplate.operatorStaticKeyReplacement/v1`
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

## Historical ca08 demo rollout, 2026-10-09

This rollout selected immutable app source
`ca08fd353da6188bc4c0849974403f7b9189f8f7` with the same f430 Rust executable.
Only the app container was recreated. A fresh stopped-consistent backup and
independent observer preserved all seven credentials, generation rows, catalog
accounts, applications and rules, 92 nonces, all 176 prior audits, 29 non-SQLite
files and the original empty publication-lock inode. No CA, token, key or policy
was regenerated. The before/after app-proxy observations retained revision 10,
policy sequence 8, identical active/loaded policy and zero audit pending/errors.

The console maintenance window was 10:45:07–10:46:45 UTC. Public console/catalog
kept their authentication redirects; lab health returned 200, and monitoring
confirmed successful checks at 10:47:20 and 10:48:20 UTC. All four services are
healthy with zero restarts and no host-published ports. See the
[historical deployment checkpoint](../docker/catchplate-operator-demo/README.md#historical-live-ca08fd35f4307347-checkpoint).

The bounded internal read-only browser check used actual deployed HTML/catalog
and kept administrator authentication out of the browser. Attempt 1 stopped at
an incorrect test expectation for the dynamically updated page title. After
correcting that assertion, attempt 2 verified all seven replacement actions,
the desktop review's actual assignments, blank password field and Cancel, then
stopped on **mobile horizontal overflow** with long retained names. Neither
attempt submitted a key, sent a provider/proxy request or changed catalog state.
The full browser acceptance is therefore not passed. Both attempts and their
terminal isolated scopes are retained, without an unchanged third full rerun.

The specific layout issue is long credential/app names in the replacement
heading and affected-app list. A source-only correction adds scoped
`overflow-wrap:anywhere` to that panel, preserving all text and controls rather
than clipping overflow. The focused `--layout-only` browser regression passed
one rendered group at 320, 390 and 1280 pixels, with full text and usable
controls. Temporarily removing wrapping in the synthetic page reproduced
overflow at both mobile widths; restoring the actual CSS removed it. Cancel
cleared a synthetic draft, and no POST or live request ran. The unchanged
13 groups were not repeated. Source hashes remained unchanged and the isolated
scope exited zero with no remaining cgroup processes.

CSS SHA-256 is
`614743f565589e21396a46a6347c56c93bc48ed79b365b8d375f27c558b4f163`;
test SHA-256 is
`f54ebd23ae1d32a3e8fe55ec8bf5d57e943866cfdba325b230be78675708f336`.
The result is `layout.log` in the rollout evidence directory below. Desktop and
320-pixel screenshots were inspected in
`/srv/catchplate-fast/projects/serverware-operator-artifacts/key-replacement-browser-synthetic-avW5sC`.
This regression used intercepted fixtures. At that checkpoint the fix was not
deployed; the separate follow-up rollout and actual layout result are below.

Rollout evidence is
`/srv/catchplate-fast/projects/serverware-operator-workspace-evidence/key-replacement-live.63FFg1d3`.
The live read-only browser receipts are `runtime-browser/receipt.json` and
`runtime-browser-attempt2/receipt.json`; the retained-state result is
`retained-observer-regexp.json`. The private key-change proof above remains
separate from this rollout: no saved live key was replaced during verification.
Provider-key validity/revocation, real Google consent/refresh, external-Internet,
native and production acceptance remain unproven.

## Current c838 layout rollout and actual browser result

The demo now runs immutable app source
`c8387a66bc773f984bbd1ab661309b4f8368f7f2` with the same f430 Rust executable.
The only production-source delta from ca08 is the scoped wrapping rule.
A fresh stopped-consistent backup and independent observer again preserved
all seven resource/generation sets, 92 nonces, 176 audits, 29 non-SQLite files,
the CA, tokens, policy and publication-lock identity. Revision 10 and policy
sequence 8 remain active with zero audit pending/errors. The app alone was
recreated; the same gate and edge restarted, without initialization or a build.
The maintenance window was 11:08:08–11:09:36 UTC. Normal TLS routes recovered,
and monitoring recorded successful checks after the two maintenance failures.

The focused actual-browser check passed once at 390, 320 and 1280 pixels.
It selected the longest eligible saved credential name from the real catalog,
checked the exact affected-application IDs, complete title/list/caveat text,
blank password field, usable control geometry and Open/Cancel at each width.
Document width exactly matched all three viewports. Five actual API/HTML GETs
returned 200; a manual refresh and final read preserved the full catalog except
its observation clock. There were zero console/page errors, refused/external
requests or mutations. No key was entered, Submit clicked or DOM property
modified. All three panel screenshots were inspected. The browser/context
closed normally and the isolated scope ended with no remaining processes.

Evidence is
`/srv/catchplate-fast/projects/serverware-operator-workspace-evidence/key-layout-live.0Bx1bANa`:
`runtime-layout-browser/receipt.json` has SHA-256
`eac5d2a1a67eb8246a541a12c8e3151e6b4bfa8268f654eb57afe408c549ca44`.
The checker hash is
`7f4b8b8d3ad1aff794dbbc4556c6a2cc0c74fa300fa87025f249bdd5c1d86b63`;
its 14-file deployed-source manifest is
`6527f73b94293b385dafa20d7ca1c9ffecb40c882be7331721dcd0de7c5aea32`.
The app/proxy pair receipt after the browser is byte-identical to its baseline.
Completed helper containers and empty task browser scratch were removed;
backups, source snapshots and evidence remain retained.

This resolves the deployed long-name review-layout failure, not every feature's
browser acceptance. The browser used an internal GET-only bridge with the
administrator token confined to the app process; it did not establish an
authenticated public SSO session, external-Internet reachability, a live key
change, real Google use, native or production acceptance. The earlier private
key-change/lease-expiry proof remains attributed to its original source.
