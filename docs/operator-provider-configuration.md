# Operator-owned provider configuration

## Status and user outcome

Internal custody, app startup and public gate publication are implemented and
tested, including an isolated paired managed app/gate fixture. The writable
settings API/UI remain unfinished. This is not authorization to change a running
deployment or proof of real Google access.

The proxy operator should
be able to configure a provider application in the product, review its effects,
and activate it without supplying a host secret-file path or asking another
person to edit environment files. Account consent remains a separate action.

The existing [Google setup transition](operator-google-setup.md) prepares public
configuration and validates a controlled cold restart. It does **not** accept or
store the Google application secret. Its deployment procedure still requires
an externally provisioned private file. That is an administration mechanism,
not completion of self-service configuration.

Do not add a working-looking Save button, writable API scaffold or success
message until durable custody and the actual startup consumer are implemented
and verified together. This document adds none of them.

### Historical v1 preparation and cold-read checkpoint

The import-independent primitives in
[`operator_provider_custody.py`](../serverware/operator_provider_custody.py)
now provide encrypted provider-application storage, exact owner/version/public
profile binding, publication-guarded transactional writes, and an existing-key-only
reader. They neither create a missing master key nor select a configuration
version. Public projections contain no secret or encrypted envelope.

The internal `prepare_managed` operation in
[`operator_google_setup.py`](../serverware/operator_google_setup.py) now stores
encrypted custody, its exact version reference, the pending setup record,
catalog revision and audit record in one real publication-locked transaction.
It uses the existing setup lifecycle with a separate closed managed grammar;
the legacy API still rejects secrets. Preparation is inactive, and cancellation
does not select or enable a provider configuration.

[`operator_publication.py`](../serverware/operator_publication.py) also supplies
an import-independent, bounded shared-lock reader over an existing SQLite
snapshot, including committed WAL data. It creates no schema, lock or master
key. SQLite may coordinate existing WAL state through sidecars; this is not a
zero-filesystem-write promise. The retained-state decoder and public custody
inspection do not import runtime configuration or decrypt a secret.
`secret_present` reports structural presence, not authenticated ciphertext or
provider readiness. A private consumer must validate and decrypt the exact
operation's owner/version/profile binding separately.

This slice requires a retained store with an existing master key. A genuinely
empty store and a retained store with a missing key both refuse without creating
a key, setup record, custody schema or preparation audit. A separately admitted
first-key initialization boundary is still required; adding a dummy credential
is not a product workaround.

These operations are deliberately not connected to the writable API, settings
UI, managed activation or startup consumer yet. Gate/application isolation and
the paired cold-configuration consumer below also remain required. This is an
internal preparation foundation, not self-service configuration or a deployment.

Focused verification on 2026-10-10 covered 58 pure custody/bootstrap/decoder
tests and 46 connected preparation/cold-read/legacy regression groups against
the same production source. The final connected run passed all 46 in 463.768
seconds, with no skips, in the cached backend image with networking disabled,
read-only source/root and a dedicated private synthetic scratch directory.
Earlier fixture failures are retained: the test worker needed a private umask,
the scratch directory needed mode 0700, and successful managed tests needed an
explicit existing-key baseline. Those corrections did not relax production
guards; separate empty/missing-key negatives still pass.

The connected tests exercise the actual publication lock, SQLite transaction,
encrypted preparation and audit rollback; fresh processes validate exact
cold reads without importing runtime configuration/database/key-initialization
modules. The existing public setup, publication and Google profile regressions
also pass. Evidence is retained under
`serverware-operator-workspace-evidence/google-managed-preparation.PFpa4l7D`;
temporary test containers were removed, not evidence or live services.
No managed activation, writable settings API, real Google request, live upgrade
or native-pilot acceptance was exercised by these tests.

### Managed v2 app-startup checkpoint

The internal `review_configuration` / `prepare_configuration` path now uses a
separate app-only provider key and an exact retained operation selector. It does
not adopt the earlier v1 foundation. Only explicit first Prepare can initialize
that key; cold readers never regenerate it. A provisional profile is usable only
inside the real startup transaction, and normal serving requires the exact
activation to be committed and re-read. Cancellation retains history while
clearing only its matching selector. No environment file or variable is rewritten.

Eight connected groups passed on 2026-10-10 in 202.427 seconds in a network-none
container, including fresh preparation, activation, second restart, commit
gating, cancellation/reprepare, stale configuration and missing custody refusal,
rollback, and actor-owned recovery after a lost response. The independent key
module's 21 focused checks also passed. Evidence is retained under
`serverware-operator-workspace-evidence/google-managed-cold.sZ8pumYD` and
`serverware-operator-workspace-evidence/curated-boundary.IFPloRyU`.
This checkpoint is the app-side internal consumer only: paired public gate
configuration, later upstream transitions, observed runtime readiness and the
writable API/UI still need their own connected acceptance. No live Google
configuration, real provider contact or native action was performed.

### Public projection, destination changes and readiness checkpoint

The subsequent backend integration publishes only the committed operation,
public profile and current destination settings into the curated gate directory.
It contains neither the client secret nor provider-key paths or ciphertext.
Fresh, pending and cancelled configurations have an explicit null profile;
missing or inconsistent retained authority does not become an empty default.
Publication failure remains a failure after commit, with repair on the next
genuine startup rather than a claim that the transaction rolled back.

Later reviewed destination changes preserve the active Google configuration and
the retained credentials, applications and policy across two cold restarts.
Readiness joins the exact operation, profile/settings digests, signed policy and
expected gate executable. Two local read snapshots surround the health request;
an inherited publication lock prevents that request entirely. Matching an
unconfigured pair proves static-policy readiness, not eligibility for consent.

On 2026-10-10, the frozen backend batch passed 10 focused observer tests and 18
connected groups: three destination-change, nine public-projection, three
readiness and three affected legacy-publication checks. The readiness group uses
real SQLite, publication locks and catalog changes with synthetic health
transport; it is not an actual managed Rust-gate observation. Evidence is in
`serverware-operator-workspace-evidence/google-managed-public.Ve6JtMhG`.
At this checkpoint, the Rust consumer still needed its own compile/runtime
acceptance.
Writable settings, real Google consent, live migration and native acceptance
are not established by this checkpoint.

### Actual managed app/gate fixture checkpoint

On 2026-10-10, all 13 focused managed-Google Rust tests passed, and the normal
`cargo build --release --frozen --offline --bin serverware-decision-gate`
completed with exit 0 at build source
`ff6d86b1a0267dcb5915e07684bdc5b216dbde7d`. The resulting binary is
`333ff7a3db00ab2bf03644fc965aed9b691bdd6ddc4ec651273e6d0c36f053e0`.
`compiled-source-join.json` matches all 494 actual compiler-input files to
fixture source `6f09f3e77c414d165155e99f64b9795935058050`; this is not a claim
that the two complete source trees are identical or a production release.

The private fixture observed the actual app and gate matching first with no
Google configuration, then matching the activated operation, public
profile/settings bindings and expected binary. Activation preserved the original
shared leaves and initial policy. Before/after mount observations kept the
provider key, database and app private signing/master keys outside the gate;
the separately required interception CA remains a gate input. Stock Requests
and curl Basic/Bearer checks passed with four upstream forwards, eight
authentication denials, two policy reloads and zero functional retries.

Evidence is retained in
`serverware-operator-workspace-evidence/managed-gate.CuSszToX`:
`result.json`, `unconfigured.stdout`, `activated.stdout`, `clients.stdout`,
`mount-before.json`, `mount-after.json`, `compiled-source-join.json` and
`teardown.json`. The same evidence directory retains `rust-build/`, including
the build/test receipts and logs, original source archive and compiler-input
record. The byte-verified executable is retained under
`serverware-operator-artifacts/sha256-333ff7a3db00ab2bf03644fc965aed9b691bdd6ddc4ec651273e6d0c36f053e0/serverware-decision-gate`.
Private Compose teardown exited 0; fixture data and evidence were retained.
This is synthetic
internal configuration/proxy proof only: no real Google consent or provider
request, new writable API/UI acceptance, native-pilot acceptance, live deployment
change or production-readiness claim follows.

### New-consent readiness boundary

Managed initial consent and reauthorization now capture the exact configured
app/gate readiness observation before taking publication or SQLite ownership.
Within their existing reviewed-revision transaction, they recheck the same
activated operation, committed process profile, current destination settings
and policy before any consent write. A matching unconfigured pair is not
eligible. The transaction recheck is local-only; it never makes a gate request.

An unavailable gate, configuration mismatch or changed review refuses the new
start through the existing fixed 409 response. This does not add a readiness
requirement to callbacks, actor-owned status recovery, disconnect, token refresh
or credential leases. In particular, a gate outage after issuing a consent URL
must not strand that already-started operation. Flag-off external profiles keep
their existing start behavior without a new health-request dependency.

These are point-in-time admission observations, not leases, Google health checks
or a promise that the proxy will remain available for the whole browser flow.
The existing callback, state, identity and credential-authority checks still own
those later transitions.

At source `d06fc6d7629787244e954ea3dd159e23880be939`, all **31** focused checks
passed: 21 inert helper/observer checks, six connected managed-consent groups
and four existing external-profile consent/reauthorization regression groups.
The managed groups completed in 198.186 seconds. They exercise actual ASGI
admission, cookies/PKCE, SQLite and publication ownership, including unchanged
state on refusal, current-CAS rejection of old observations, and both callbacks
plus actor-owned recovery while gate health is unavailable. Health and provider
transports are synthetic; managed refresh, disconnect and leases were not
executed by this batch. Evidence is retained in
`serverware-operator-workspace-evidence/google-managed-consent.vm77HTMZ`, with
the exact source archive/manifest, command, log and successful network-none
container termination. This is not browser, live gate/provider, deployment or
native-pilot acceptance.

## Keep the objects distinct

| Object | Operator action | What it does not imply |
| --- | --- | --- |
| Proxy deployment | Configure console/proxy addresses, trust and permitted destinations. | Arbitrary runtime routing, DNS or container changes. |
| Provider application | Configure the Google OAuth client used by this proxy. | A user's account consent, granted scopes or refresh health. |
| Saved connection | Save a static key or connect a verified Google account. | Permission for every application to use it. |
| Application permission | Assign a saved connection to a bounded operation preset. | Whole-provider access or removal of mandatory safety checks. |

The operator can register their provider application through the provider's
administration interface and enter the resulting client ID and secret here.
Show the exact callback URI and required permission preset before that step.
Automatic creation of a Google project/OAuth application is not provided by
the existing code and must not be promised by this configuration flow.

## Effective configuration already available

The existing authenticated catalog readout exposes `proxy_url`,
`allowed_upstreams`, catalog revision and policy observation, saved resources,
and versioned capabilities. Reuse that readout rather than returning raw
environment variables or adding a second settings authority. Relevant owners
are `serverware/operator_catalog_mutations.py:catalog_status`,
`serverware/operator_catalog_capabilities.py` and
`serverware/operator_catalog_gmail.py:capabilities`.

Google discovery joins the cold profile and retained database binding in a
read transaction. Unconfigured is distinct from malformed or drifted. A saved
account is not evidence that the provider is healthy. Source capabilities alone
are not proof that the deployed gate supports them.

Provider presets should describe bounded jobs and derive compatible defaults;
they must not silently broaden existing saved rules. The current Gmail bundle
is message listing, pagination and message reads, not every Google service.
The separate GitHub work proposes repository-scoped issue-reading and
issue/comment-creation bundles using a static token. It remains source work
until paired verification; it is neither GitHub App registration nor a writable
deployment-settings feature. `api.github.com` must still be an explicitly
permitted deployment destination. Do not hard-code speculative capability DTOs
in the UI: consume the closed versioned descriptors supplied by the backend.

## Required writable Google contract

The minimum first implementation is **first managed Google configuration** on
an eligible operator-development store, not replacement of an existing client.

1. **Review:** an administrator reads the effective configuration and exact
   catalog revision, policy hash and settings digest. The server derives the
   HTTPS callback from the admitted console origin and fixes the provider
   endpoints, Gmail preset and scopes. The only destination change is the
   existing reviewed append of the Gmail origin, preserving order and fixture
   CIDRs.
2. **Configure and prepare:** one explicit bounded POST accepts a caller-held
   operation UUID, client ID, write-only secret and the exact review pins. Store
   encrypted custody and the public pending setup operation in one publication
   lock/SQLite transaction with audit. Retain the UUID before submitting. A lost
   response is recovered by actor-owned GET, never automatic POST replay.
3. **Activate:** pending configuration remains inactive until a controlled
   cold start consumes exactly that operation. The activation transaction
   rechecks all pins and commits the profile/settings change and durable
   receipt together. A stale review refuses; it is not automatically rebased.
4. **Observe:** distinguish prepared, cancelled, activation committed and
   matching runtime observed. Only a matching app/gate configuration and policy
   observation permits a ready-to-connect claim. Account consent and an actual
   provider job remain later, separate acceptance steps.

Use a separately versioned write contract; do not silently change the existing
public-only setup grammar. The new JSON body must be bounded (at most 8192
bytes), with a single nonempty secret of at most 4096 UTF-8 bytes, a canonical
client ID and no unknown keys. Retain current admin, exact Origin, strict JSON,
no-store and operation-ownership guards. Reject paths, commands, arbitrary
endpoints/scopes, environment assignments and deployment control inputs.

The managed API must distinguish pre-lifecycle input rejection (422), reviewed
state conflict (409), absent actor-owned receipt (404), and uncertain storage,
commit, publication or response outcomes (503). Do not reuse the legacy setup
wrapper's blanket `SetupUnavailable` to 409 mapping: managed preparation can
raise that exception after commit. A missing receipt never proves rollback or
authorizes replay. Settings discovery must still work after activation rather
than calling the unconfigured-only review operation unconditionally.

The UI must retain only an exact operation reference before sending, clear the
write-only client secret from both the form and transient payload, and recover
uncertain results through GET only. The generic catalog mutation controller does
not supply this contract. Saving provider configuration must not automatically
start account consent or restart either service.

Public results contain the public binding, operation/version, timestamps,
status and `secret_present` only. Never return the secret, encrypted envelope,
secret fingerprint, filesystem location or a secret-bearing error. Cancellation
does not enable the provider; retained operation IDs cannot be reused. Any
future secret erasure/rotation policy needs its own audited custody transition.

## Custody and cold-start boundary

Use dedicated provider-application custody, not a catalog account credential or
OAuth revocation-work row. Encrypt the secret with associated data binding the
owner UUID, configuration version and exact public profile. Its storage and
schema markers must be validated; missing retained custody is corruption, not
permission to recreate or fall back. Bound retained versions and admit at most
one pending first-configuration operation.

This cannot be implemented solely inside the existing setup handler:

- `config.py` loads Google secrets during import, and
  `operator_catalog_oauth_profile.py` pins the secret file, environment and
  process. `operator_demo.activate()` then pins the runtime configuration.
- `crypto.load_master_key()` imports configuration and can create a missing
  key. It is not a read-only early bootstrap reader. Managed cold loading needs
  an explicit import-independent, existing-key-only path. First-ever key
  creation for genuinely empty state must be a separately defined durable
  initialization boundary; retained encrypted authority with a missing key
  must refuse. Never regenerate a key to make startup pass.
- A cold reader may supply provisional in-memory configuration only after
  strict private-directory, marker, ownership and retained-state validation.
  The pre-database preflight and activation transaction must revalidate it.
  Neither reader may initialize schemas, contact Google or repair missing
  state as a side effect of reading configuration.
- Legacy Rust profiles remain environment-selected. Managed mode instead loads
  the fixed public configuration artifact under the shared startup lock and
  reports the exact committed activation identity. The gate never receives the
  client secret. Verified ownership/currentness and repair from committed state
  remain mandatory; a successful file write alone is not activation.

The current operator Compose recipe mounts the complete app-data directory
read-only into the gate, including SQLite and its master key. Managed custody
must not rely on a public-only parser while leaving both ciphertext and its key
readable there. The integration needs a curated shared publication directory
and only the gate's required CA material, excluding the application database and
master key. Preserve one shared publication-lock inode across both processes.
Do not substitute an individual bind mount of `policy-bundle.json`: publication
uses atomic replacement, so that mount could retain an obsolete file inode.
This is a coordinated ownership/publication change, not a Compose-only edit or
authorization to migrate retained live state now.

No runtime environment mutation, `webapp.env` rewrite, arbitrary secret-file
writer, Docker socket, self-restart privilege or hot-reload claim belongs in
this slice. Restart requirements must be visible. Publication ownership does
not prove that old processes stopped.

### Curated gate publication checkpoint

The opt-in `operator_gate_publication` publisher now derives a `gate-runtime`
directory from the committed signed policy under the original publication lock.
It repairs this copy independently of the canonical policy after a failed
publication or restart. The dormant `docker-compose.curated-gate.yml` layer
mounts that directory into the gate, with separate read-only binds of the
original lock, marker and required interception CA files. It excludes the app
database and master/signing keys. The gate still needs the interception CA
private key; this is not an all-public or production-isolated data plane.

Seven connected checks passed on 2026-10-10 in 96.799 seconds in a network-none
container: real policy changes, disabled-mode compatibility, stale/missing copy
repair, postcommit failure followed by fresh startup, unsafe paths and actual
shared-lock exclusion. Evidence is retained in
`serverware-operator-workspace-evidence/curated-boundary.IFPloRyU`.
The separate internal-network fixture at source `6773f2d7` also passed its
one-shot stock Requests/curl Basic/Bearer client check: four upstream forwards,
eight authentication denials and two policy reloads. Before/after mount and
filesystem observations joined the same app/gate processes, original lock and
marker, retained binary `2bfe5e38`, and policy sequence 1 through 3. The app's
new credential master key and database remained unreadable in the gate. The
fixture had no host ports or external egress and was stopped after verification.
The earlier fixture's client check passed, but its baseline observer incorrectly
required a master key before any credential existed; that run is not presented
as a complete before/after proof. Both records are retained in the evidence
directory above. This is synthetic proxy/isolation proof, not managed Google,
real-provider or native-pilot acceptance. Live migration remains unverified;
no live mount changed.

## Compatibility, ownership and acceptance

Keep externally managed env/file profiles unchanged and mutually exclusive
with the new owner. Refuse first-configuration writes where a retained Google
profile already exists. Client/callback changes, secret rotation and migration
of existing provider ownership are separate reviewed transitions; never
rewrite existing profiles or disconnect accounts to force adoption.

The internal configuration/custody modules, config-independent reader, startup
integration and public gate consumer now have the isolated acceptance above.
The next implementation boundary is the authenticated writable API/UI. Preserve
production, enrolled/native ownership, existing-account recovery and all
provider-selection guards. Do not duplicate their authority in the UI.

Acceptance must prove real encrypted storage and write-only responses;
authenticated strict input; exact UUID/CAS and lost-response recovery;
missing-key/schema/custody refusal; rollback and cold-start interruption;
unchanged credentials, accounts, apps, rules, original intents, token verifiers,
expiry, policy bytes/sequence/high-water and CA material; and matching app/gate
activation. The setup phase must make zero provider requests. Real consent,
refresh and an ordinary supported client job are subsequent tests, not evidence
that can be inferred from saving configuration or seeing a healthy process.
