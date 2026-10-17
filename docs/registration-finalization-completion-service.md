# Cold finalization completion service

The dedicated `registration-finalization-completion` source profile owns
read-only recovery and signed completion delivery for
`webauthn.registration.finalize`. It does not invoke or retry protected SQL,
clear an execution attempt, renew a grant or activate an OIDC browser session.
The [finalization SQL observation](registration-finalization-sql-service.md)
is unsigned and cannot supply this service's expected packet or prove a
completion. This implementation is source-only, unbuilt, unexecuted and
unprovisioned; no production acceptance gate is established.

## Fixed cold resources

| Resource | Fixed value |
| --- | --- |
| Role/process mode | `registration-finalization-completion` |
| Service UID/GID | `65508:65508`, no supplementary groups |
| Request peer | `65532:65532` |
| Listener | `/run/catchplate/registration-finalization/completion.sock` |
| Root/bootstrap/listener/key/journal FDs | `198`, `199`, `200`, `201`, `202` |
| Trust directory | `/run/catchplate/registration-finalization-completion-trust` |
| Completion key | `/run/catchplate/registration-finalization-completion-key/completion.pem` |
| Completion journal | `/var/lib/catchplate/registration-finalization-completions` |
| TLS directory | `/run/catchplate/registration-finalization-completion-tls` |

The root original is `root-public-key.pem` and the signed bootstrap is
`bootstrap.json` in the fixed trust directory. Root/bootstrap/key originals
are retained in sealed descriptors. The listener pathname is `65508:65532`,
mode `0660`; its root-activated kernel peer is `0:0`, not the service UID.
The journal is `65508:65508`, mode `0700`, with independently signed device/inode
and checkpoint. The completion key is the actual enrolled Ed25519 key, not a
caller, planner, grant, computation or state key; root delivery admits the
bootstrap before accessing private resources.

## Closed root-signed bootstrap

[`registration_finalization_completion_bootstrap.py`](../catchplate/registration_finalization_completion_bootstrap.py)
uses distinct schemas:

- `catchplate.signedRegistrationFinalizationCompletionBootstrap/v1`
- `catchplate.registrationFinalizationCompletionBootstrap/v1`
- `catchplate.registrationFinalizationCompletionLaunch/v1`

The original is at most 4 MiB. Its positive `issuedAtEpochNs`/`expiresAtEpochNs`
interval is at most 300 seconds; `requestTimeoutSeconds` is an integer in
`1..30`. `trustMode` is `trusted-host-local`. `hardwareBacked`, `nativeStageZero`,
`hsmBackedKeys`, `teeVerified` and `externalWitnessVerified` must all be false.
The launch closes the five descriptor numbers and ordered inventory, process
and peer identities, fixed listener path, socket/path device and inode,
journal device/inode and `journalMaximumRecords`. No alternate resource path,
private-purpose descriptor or implicit restart is selected by a request.

Actual finalization transition custody configuration admits the complete
`configurationPayload`, `configurationDigest`, `generation` and
`runtimeRoleIdentities`, then supplies the real planner and finalization
operation public keys. Evidence-admission policy is not a fallback.
`currentRootEnrollment`, `grantEnrollment` and `authorizationEnrollment` each
contain exactly `base64Url`, `byteCount`, `bytesDigest`, `identityDigest` for an
original enrollment. Genuine root/current-root/grant/finalization-caller
admission joins their exact identities, database, generation and key scopes.
`completionSpkiDigest` and `completionMeasurementDigest` must match the actual
current-root enrollment. The completion key and dedicated caller remain
separate from enrolled/configured purposes, including enabled evidence,
enrollment and transition keys. `runtimeClosureDigest` remains an independent
root assertion, not a measurement performed by this module.

The root independently supplies these per-operation values:

- `packetDigest` and `authorizationDigest`: canonical pins, never inferred from
  unsigned SQL locators, a returned packet or journal contents.
- `replayExpectations`: actual fixed-finalization historical expectations.
  The real replay grammar and transition admission join the configuration,
  planner identity/SPKI, finalization signer identity/SPKI, RP/origin and all
  configured plan/proof age/skew limits. Historical request, roots, database
  cutoff, verification-time and deadline facts remain independent signed inputs;
  neither a returned packet nor the current processing clock fills them.
- `currentPending`: exact positive `sequence`, `headDigest`, positive `fence`.
  Sequence must be below enrolled `maxRecords`, leaving completion capacity.
- `completionCheckpoint`: exact nonnegative `sequence`, `headDigest`.
  `journalMaximumRecords` must equal the current-root enrollment's maximum;
  the checkpoint cannot exceed it. At sequence zero its head must equal the
  actual current-root enrollment identity, not a scanned local prefix.

These signatures are not a live witness that a pending head remains current.
A later cold launch needs its own independent checkpoint and unchanged
operation/history scope; no response automatically advances either checkpoint.

## Two read-only database identities

`databaseEndpoint` contains only `host`, `hostaddr`, `port`, `databaseName`, using
the existing closed canonical server-name, literal-unicast address, port and
database-identifier grammar. `sqlRoles` contains exactly `custody` and `commit`;
each has `connectTimeoutSeconds` in `2..300`, plus bounded `clientDn`,
`clientSerial`, `issuerDn`. The source constructs fixed
`SUCCESSOR_RECOVERY_ROLE` and `COMPLETION_READER_ROLE` connection strings with
the same endpoint/database, `sslmode=verify-full`, `passfile=/dev/null` and
`gssencmode=disable`. There is no supplied DSN, password or endpoint fallback.

Both reader configurations are mandatory exact eight-tuples, ending in the
independently signed `structureManifestDigest`; the shared `queryManifestDigest`
also joins actual configuration. Both real readers retain their restricted
TLS/role/ACL and same-connection catalog admission. There is no seven-field or
optional-catalog-pin fallback. Signed hashes and matching endpoint fields do
not establish that both credentials reach the same genuine database.

`tlsFiles` has exactly five logical fields, each with only `byteCount` and
`bytesDigest`:

| Field | Fixed basename | Bounds |
| --- | --- | --- |
| `ca` | `ca.pem` | `2..65536` bytes |
| `custodyCertificate` | `custody.crt` | `2..65536` bytes |
| `custodyKey` | `custody.key` | `2..16384` bytes |
| `commitCertificate` | `commit.crt` | `2..65536` bytes |
| `commitKey` | `commit.key` | `2..16384` bytes |

The bootstrap does not open them. Protected delivery validates root-owned,
fixed-path originals; public files use mode `0444`, private files mode `0440`
and group `65508`. The child retains the literal environment without `PG*` or
other ambient credential/configuration selectors. Independent certificate-only
database authentication, restricted privileges and egress remain prerequisites.

## State service and bounded exchange

`stateEndpoint` is exactly `socketPath`, `requestTimeoutSeconds`, `serviceUid`,
`serviceGid`, `listenerUid`, `listenerGid`: fixed
`/run/catchplate/current-root/state.sock`, integer timeout `1..30`, service
`65516:65516` and root listener `0:0`. Separate filesystem ACLs must permit the
new peer; neither a bind mount nor this bootstrap grants that access.

The state owner requires the explicit root-signed v3 bootstrap/payload/launch
profile adding `finalizationCompletePeerUid/Gid = 65508`. It admits this peer
only for authenticated finalization completion and nonce-bound state queries;
the v3 legacy completion peer `65515` is restricted to evidence completion. Reserver peers
cannot complete or query. v1/v2 peer behavior is unchanged. A query response is
not a new action grant or independently current lease.

The [transport](../catchplate/authority_registration_finalization_completion_transport.py)
uses `SWRFCM01` / `SWRFCR01`. Raw2 is the exact purpose
`recover-registration-finalization-completion` and the canonical ASCII packet
digest already independently pinned by the bootstrap. Raw4 is either
`acknowledged`, completion-request digest, original signed completion request,
original signed state receipt; or `uncertain` with the other three bodies
empty. Response framing supplies neither the expected packet nor signature
verification. No exception text or incoming successful authority carrier is
accepted.

The [entrypoint](../catchplate/registration_finalization_completion_entrypoint.py),
[startup owner](../catchplate/registration_finalization_completion_startup.py),
[launcher](../catchplate/registration_finalization_completion_launcher.py) and
[runner](../catchplate/registration_finalization_completion_runner.py) retain the
exact resources and original opening. At most one connection is accepted per
launch, including a rejected peer/frame. One actual work allowance and live
window open before peer/frame/body intake; the inherited absolute deadline,
clipped to the cold launch, covers recovery and response without reopening.

Genuine recovery uses the actual custody reader, historical original replay,
committed-state reader, completion delivery journal and current-root client.
It does not repeat SQL. An already retained matching completion reuses its
unchanged signed originals rather than creating a replacement; an acknowledged
original can return its retained acknowledgment. Uncertainty never clears a
claim or grants an automatic request/process retry.

The original-only [receiving verifier](registration-finalization-completion-response.md)
authenticates returned completion/state signatures against actual finalization
plan/grant/pending replay; raw4 framing is not that verification. The control-plane
completion caller, retained completion association and public recovery workflow
remain to be integrated. The launcher and uninstalled socket/service templates
are packaged as source inputs, not deployed services.

## Library and release boundary

`_verify_on_work(*, bootstrap_bytes, root_public_key, work)` authenticates
originals before resource use. `_produce_on_work(*, payload, root_private_key,
root_public_key, work)` signs independently established claims. `_fresh(interval,
work, opening=...)` retains the original epoch/monotonic bracket. The private
`_CompletionMaterial` carries ordinary owned configuration/enrollment data,
`planner_public_key`, `operation_public_key`, actual completion key/pins,
independent pending/checkpoint/packet/authorization/history, exact eight-tuple
reader settings, TLS pins and launch interval/opening. No API accepts this
material as a substitute for authenticating originals.

Provisioned keys, accounts, trust history, database provenance/privileges,
socket ACLs, deployment and frozen verification remain separate. Bounds and
service timeouts are not hard driver/kernel watchdogs. Signed completion is
not a browser-session activation, latest-head lease or reusable permission;
separate present-caller/public handoff authorization and OIDC activation are
not supplied by this bootstrap.
