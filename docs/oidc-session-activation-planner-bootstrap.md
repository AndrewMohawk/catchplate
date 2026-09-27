# Root-authenticated activation-planner bootstrap

This is source-only cold configuration and snapshot admission for
`oidc.session.activate`, not permission to activate a browser session. The
[bootstrap module](../serverware/oidc_session_activation_planner_bootstrap.py)
authenticates an independent root's original signed configuration, dedicated
planner identity, policy, resources, complete-root-vector bytes and enrolled
current-state observation scope. It reads no
key or TLS file, opens no database or journal, and creates no work allowance.
Nothing here has been built, executed, provisioned or accepted for production.

The [delivery entrypoint](oidc-session-activation-planner-delivery.md),
[cold planning composition](oidc-session-activation-cold-planning.md) and
[private service](oidc-session-activation-planner-service.md) consume this
profile. They must authenticate the original bootstrap themselves; the private
`_PlannerMaterial` result is ordinary same-call data, not an externally accepted
verification token.

## Original wire and admission

The exact three-field envelope is `schema`, `payload`, `signatureBase64Url`.
Its schema and root-signature domain are
`serverware.signedOidcSessionActivationPlannerBootstrap/v3`; the closed payload
uses `serverware.oidcSessionActivationPlannerBootstrap/v3`. The original is at
most 4 MiB. Admission verifies the actual Ed25519 root signature and canonical
original bytes before selecting private resources. V3 is mandatory: v1 lacks
the required state pins, and v2 lacks the bundle-key and execution-store scope.
Neither older profile is accepted as a fallback or enables the new custody.

The closed payload binds:

- Current source revision, fixed role and operation; actual configuration
  payload/digest, generation, complete runtime-role identities and a separately
  root-asserted runtime-closure digest.
- Dedicated planner public key/SPKI and exact three-field identity
  (`sessionIdentityDigest`, `measurementDigest`, `attestationReceiptDigest`).
  The signing key must differ from the root and configured generic,
  evidence, transition and enrollment-issuer signing purposes, and the genuinely
  enrolled state, computation and completion keys. Purpose/key
  separation does not require different measured release bytes.
- Actual configured RP/origin, required user verification, a non-widening
  authenticator-class/attestation policy, and bounded original trust-root
  descriptors with their current bundle digest/sequence.
- Plan age/skew and delivery TTL (5–60 seconds), exact database endpoint and
  verifier read-role TLS identity, source/configuration query-manifest pin and
  three fixed TLS-file byte counts/digests.
- Plain SHA-256 `deliveryKeyDigest`, `journalKeyDigest` and `bundleKeyDigest`
  pins for three pairwise-distinct exact-32-byte delivery/journal/bundle keys,
  never their values; complete-root-vector original; launch interval/resources.
- A `databaseId`, the original `stateEnrollment`, and fixed `stateEndpoint`.

`completeRootVector` is exactly
`{base64Url, byteCount, bytesDigest, identityDigest}`. Its original is at most
64 KiB. Admission checks the raw-byte digest and invokes the real complete-vector
decoder/digest, including canonical form, full source inventory, manifests and
count relationships. This is not a caller-supplied selected-root subset.

`stateEnrollment` uses the same exact four descriptor fields, with a 128 KiB
original cap. Admission checks its raw SHA-256 digest, genuinely verifies the
root-signed current-root enrollment under the independent bootstrap root, and
joins its actual framed identity digest. Its generation digest must equal the
genuinely admitted configuration generation; its database ID must equal the
explicit signed `databaseId`. The latter binds the enrolled database to the
signed database endpoint by a trusted provisioner assertion. The signature
alone does not establish database provenance or equate unrelated digest domains.

`stateEndpoint` is exactly `socketPath`, `requestTimeoutSeconds`, `listenerUid`
and `listenerGid`: `/run/serverware/current-root/state.sock`, integer 1–30
seconds, and root-created kernel listener peer `0:0`. It enables only the
separate [head observation](authority-current-root-head.md) exchange. The state
service's v4 profile admits planner UID 65507 for this purpose; independent
socket access is still required. The socket pathname's `65516:65516`, mode
`0660` ownership is not the kernel peer identity or an access grant to 65507.

The read configuration is the actual reader's four-tuple: generated DSN,
connection timeout, seven-field database/TLS/planner identity, and clock skew.
`readRole.databaseRole` must equal the genuinely configured verifier database
role. The endpoint is the closed `host`, `hostaddr`, `port`, `databaseName`
profile; the DSN is generated with fixed TLS paths, `sslmode=verify-full`,
`passfile=/dev/null` and `gssencmode=disable`. There is no supplied DSN, password
or fallback selector. Actual database identity and read checks remain the real
reader's responsibility. This profile deliberately has no
`structureManifestDigest`: that reader has no independently pinned structure
manifest parameter, so this bootstrap does not claim an extra catalog-pin gate.

## Fixed cold resources

`serverware.oidcSessionActivationPlannerLaunch/v3` fixes process mode
`oidc-session-activation-planner`, service UID/GID 65507 and request-peer UID/GID
65532. The inherited descriptor inventory is exactly nine; the original seven
numbers and purposes remain unchanged:

| Descriptor | Purpose |
| --- | --- |
| 198 | Root public key original |
| 199 | Signed bootstrap original |
| 200 | Listener |
| 201 | Dedicated Ed25519 planner private key |
| 202 | Raw delivery key |
| 203 | Separate raw journal key |
| 204 | Journal directory |
| 205 | Separate raw execution-bundle key |
| 206 | Execution-bundle store directory |

The listener is `/run/serverware/oidc-session-activation/planner.sock`; the
journal is `/var/lib/serverware/oidc-session-activation-planner`. Signed launch
fields include exact listener socket/path device/inode, journal device/inode,
`journalMaximumRecords` (1–1024), `journalQuotaBytes` (1 byte–8 GiB), and request
timeout (integer 1–30 seconds). Actual ownership, modes, descriptor sealing,
key pairs and unchanged filesystem identities belong to the delivery/service
checks; this document does not provision them.

V3 additionally requires `bundleKeyFd` = 205, `executionStoreDirectoryFd` = 206
and `executionStoreDirectoryPath` =
`/var/lib/serverware/oidc-session-activation-execution-bundles`. The signed
`executionStoreDirectoryDevice` is an unsigned 64-bit integer and
`executionStoreDirectoryInode` is a positive unsigned 64-bit integer, matching
the existing journal/store binding grammar. Their pair must differ from the
journal's device/inode pair; a different pathname alone is insufficient.
`executionStoreMaximumRecords` is 1–1024 and `executionStoreQuotaBytes` is
1 byte–8 GiB. These independently signed limits need not equal the journal's.
The directory remains subject to the same service UID/GID 65507; actual
descriptor ownership, protected-path identity and mode checks belong to cold
delivery and the real [execution store](oidc-session-activation-execution-store.md).
No directory is created and no bundle key is provisioned by this bootstrap.

`tlsFiles` is exactly `ca`, `clientCertificate`, `clientKey`, each with
`{byteCount, bytesDigest}`. Their fixed directory is
`/run/serverware/oidc-session-activation-planner-tls`, with filenames `ca.pem`,
`client.crt`, `client.key`. Public originals are 2–65536 bytes; the private key
is 2–16384 bytes. Private originals never enter the bootstrap or public plan.

## Work, clocks and remaining authority

`_verify_on_work(*, bootstrap_bytes, root_public_key, work,
live_window=None, transport_deadline_ns=None)` returns the private material.
`_produce_on_work(*, payload, root_private_key, root_public_key, work,
live_window=None, transport_deadline_ns=None)` validates these same original
scope gates and produces the real root-signed original; it does not invent the
independent inputs. `_fresh(interval, work, opening=None)` retains the original
clock bracket.

The signed interval lasts at most 300 seconds. An inherited processing window
and absolute transport deadline remain in force, with rollback checks and no
new work budget, fresh opening allowance or launch renewal. Material retains
the actual bootstrap/vector/state-enrollment originals, actual enrollment
identity, fixed state endpoint, original opening/interval, owned
configuration/policy, key pins and fixed resource scope. It cannot be posted
back as authority. The material appends required `bundle_key_digest` without
changing any existing field name or verifier/producer signature. The original
root-signature, configuration/generation/runtime, planner-purpose, policy,
state-enrollment and complete-vector checks still precede resource admission.

`trustMode` is `trusted-host-local`; `hardwareBacked`, `nativeStageZero`,
`hsmBackedKeys`, `teeVerified` and `externalWitnessVerified` must all be false.
The root-signed vector supplies independently authenticated *snapshot
expectations*. The cold path additionally requires a fresh challenge-bound,
signed no-pending head matching that vector before planning; the original
observation also limits the signed plan's expiry. A sampled head is not an
atomic reservation or an action-time execution guarantee. Action-time one-use
custody, protected execution, token delivery/recovery and public activation
remain separate work. Existing state-service reserve/complete/lookup peers are
unchanged; the new v4 head-only peer does not acquire those permissions.
