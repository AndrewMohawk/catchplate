# Operator-owned provider configuration

## Status and user outcome

This is the next implementation contract, not an implemented writable settings
API or authorization to change a running deployment. The proxy operator should
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

### Internal storage checkpoint

The import-independent primitives in
[`operator_provider_custody.py`](../serverware/operator_provider_custody.py)
now provide encrypted provider-application storage, exact owner/version/public
profile binding, publication-guarded transactional writes, and an existing-key-only
reader. They neither create a missing master key nor select a configuration
version. Public projections contain no secret or encrypted envelope.

The 22 synthetic checks in
[`test_operator_provider_custody.py`](../scripts/test_operator_provider_custody.py)
pass, covering tampering, rollback, malformed retained state, filesystem guards
and reads that cannot import configuration or key-initialization modules. Writer
tests substitute only the publication-ownership assertion; they do not prove the
real setup transaction, audit or activation flow.

These primitives are deliberately not connected to the API, settings UI or
startup yet. The caller still owns full development-profile admission, WAL-aware
database opening, lifecycle/audit validation and activation. This is a storage
foundation, not a completed operator-configuration feature or live deployment.

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
- The Rust gate currently selects its public Google profile from environment.
  A paired public cold-configuration consumer must join the same committed
  activation. The gate must not receive the client secret. A public artifact,
  if used, needs verified ownership/currentness and crash recovery from the
  authoritative committed record; a successful file write is not activation.

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

## Compatibility, ownership and acceptance

Keep externally managed env/file profiles unchanged and mutually exclusive
with the new owner. Refuse first-configuration writes where a retained Google
profile already exists. Client/callback changes, secret rotation and migration
of existing provider ownership are separate reviewed transitions; never
rewrite existing profiles or disconnect accounts to force adoption.

The next implementation needs a dedicated configuration/custody module and
config-independent reader, narrowly joined to the operator runner, profile
admission, setup/preflight and API. A separate gate change owns the public cold
consumer. Preserve production, enrolled/native ownership and all existing
provider-selection guards. Do not duplicate their authority in the UI.

Acceptance must prove real encrypted storage and write-only responses;
authenticated strict input; exact UUID/CAS and lost-response recovery;
missing-key/schema/custody refusal; rollback and cold-start interruption;
unchanged credentials, accounts, apps, rules, original intents, token verifiers,
expiry, policy bytes/sequence/high-water and CA material; and matching app/gate
activation. The setup phase must make zero provider requests. Real consent,
refresh and an ordinary supported client job are subsequent tests, not evidence
that can be inferred from saving configuration or seeing a healthy process.
