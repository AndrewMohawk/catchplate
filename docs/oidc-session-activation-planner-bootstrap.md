# Root-authenticated activation-planner bootstrap

This is source-only cold configuration and snapshot admission for
`oidc.session.activate`, not permission to activate a browser session. The
[bootstrap module](../serverware/oidc_session_activation_planner_bootstrap.py)
authenticates an independent root's original signed configuration, dedicated
planner identity, policy, resources and complete-root-vector bytes. It reads no
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
`serverware.signedOidcSessionActivationPlannerBootstrap/v1`; the closed payload
uses `serverware.oidcSessionActivationPlannerBootstrap/v1`. The original is at
most 4 MiB. Admission verifies the actual Ed25519 root signature and canonical
original bytes before selecting private resources.

The closed payload binds:

- Current source revision, fixed role and operation; actual configuration
  payload/digest, generation, complete runtime-role identities and a separately
  root-asserted runtime-closure digest.
- Dedicated planner public key/SPKI and exact three-field identity
  (`sessionIdentityDigest`, `measurementDigest`, `attestationReceiptDigest`).
  The signing key must differ from the root and configured generic,
  evidence, transition and enrollment-issuer signing purposes. Purpose/key
  separation does not require different measured release bytes.
- Actual configured RP/origin, required user verification, a non-widening
  authenticator-class/attestation policy, and bounded original trust-root
  descriptors with their current bundle digest/sequence.
- Plan age/skew and delivery TTL (5–60 seconds), exact database endpoint and
  verifier read-role TLS identity, source/configuration query-manifest pin and
  three fixed TLS-file byte counts/digests.
- Plain SHA-256 pins for two distinct exact-32-byte delivery/journal keys,
  never their values; complete-root-vector original; launch interval/resources.

`completeRootVector` is exactly
`{base64Url, byteCount, bytesDigest, identityDigest}`. Its original is at most
64 KiB. Admission checks the raw-byte digest and invokes the real complete-vector
decoder/digest, including canonical form, full source inventory, manifests and
count relationships. This is not a caller-supplied selected-root subset.

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

`serverware.oidcSessionActivationPlannerLaunch/v1` fixes process mode
`oidc-session-activation-planner`, service UID/GID 65507 and request-peer UID/GID
65532. The inherited descriptor inventory is exactly:

| Descriptor | Purpose |
| --- | --- |
| 198 | Root public key original |
| 199 | Signed bootstrap original |
| 200 | Listener |
| 201 | Dedicated Ed25519 planner private key |
| 202 | Raw delivery key |
| 203 | Separate raw journal key |
| 204 | Journal directory |

The listener is `/run/serverware/oidc-session-activation/planner.sock`; the
journal is `/var/lib/serverware/oidc-session-activation-planner`. Signed launch
fields include exact listener socket/path device/inode, journal device/inode,
`journalMaximumRecords` (1–1024), `journalQuotaBytes` (1 byte–8 GiB), and request
timeout (integer 1–30 seconds). Actual ownership, modes, descriptor sealing,
key pairs and unchanged filesystem identities belong to the delivery/service
checks; this document does not provision them.

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
the actual bootstrap/vector originals, original opening/interval, owned
configuration/policy, key pins and fixed resource scope. It cannot be posted
back as authority.

`trustMode` is `trusted-host-local`; `hardwareBacked`, `nativeStageZero`,
`hsmBackedKeys`, `teeVerified` and `externalWitnessVerified` must all be false.
The root-signed vector supplies independently authenticated *snapshot
expectations*, not independently fresh latest-head admission. Consequently
F08.4d.5 remains in progress: the cold configuration/snapshot/service portion
does not finish its fresh-current-root/head requirement. Action-time one-use
custody, protected execution, token delivery/recovery and public activation
remain separate work. No state-service reserve/complete/query peer or existing
bootstrap profile is widened here.
