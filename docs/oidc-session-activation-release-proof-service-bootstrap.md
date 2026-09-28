# Cold private release-proof worker

This source-fixed worker produces one committed-release proof. It is separate
from the completed consume-completion exchange and does not reopen that spent
owner. Source implementation is not deployment, execution, hardware isolation,
token release, or completion of the public protected handoff.

## Independently provisioned originals

`oidc_session_activation_release_proof_bootstrap.py` admits the runtime-root
signature in `serverware.signedOidcSessionActivationReleaseProofBootstrap/v1`,
whose payload is `serverware.oidcSessionActivationReleaseProofBootstrap/v1` and
whose purpose is `launch-oidc-session-activation-release-proof`.

Its closed payload contains `schema`, `sourceRevision`, `purpose`, `role`,
`trustMode`, seven original wrappers, `proofScope`, `expectedRelease`, `callerId`,
`issuedAtEpochNs`, `expiresAtEpochNs`, and `launch`. The wrappers are
`completionBootstrap`, `proofEnrollment`, `releaseCustody`, `intent`,
`intentEnrollment`, `completionRequest`, and `stateReceipt`, each exactly
`{base64Url, byteCount, bytesDigest}`. The role is
`oidc-session-activation-release-proof`; trust mode is `trusted-host-local`.

The genuine existing completion-bootstrap verifier authenticates its original
configuration, pending tuple, packet identity, caller controls, historical
custody originals, and two read-only database/TLS configurations. This is pure
original admission: its completion signing key, completion journal, and state
socket are neither required nor opened by the proof worker. The new outer
bootstrap independently supplies exact completed request and state receipt
originals; their signed commit semantics are verified by the actual proof
producer, not inferred from canonical data or a successful result object.

`proofScope` is the existing closed seven-field proof enrollment scope;
`expectedRelease` is the existing closed six-field release target including
its five-field consume binding. The producer identity joins the actual
completion-custody receiver identity. The release receiver remains the distinct
token-release custodian. Root/client-provided digest hints cannot substitute
for the producer's genuine committed-original replay.

The separate proof signer is genuinely root enrolled and excluded from actual
root, planner, current-root computation/completion/state, consume caller/grant,
intent caller, historical planner and configured signing purposes. Its key
measurement is the independently pinned producer measurement; this is a
trusted-host-local claim, not a hardware measurement.

The original release custody contains the actual signed intent digest. That
custody and this proof bootstrap therefore require independent root authorization
after intent exists. Source `.198` adds the [setup policy and receiving contracts](oidc-session-activation-release-proof-input-policy.md)
and an opt-in dynamic worker; issuer-side packet acquisition and its finite
signing/staging service remain open. Neither the public caller nor the worker
manufactures root authority. The original intent signature, root enrollment, target, cohort and
lifetime are checked before private resource delivery; the request's old token
is admitted later by the genuine producer, once, with the complete originals.

## Exact cold resources

The isolated launcher accepts only `--root-delivery`. It begins as root with
one systemd-activated listener named `serverware-oidc-session-activation-release-proof`.
The socket path is `/run/serverware/oidc-session-activation-token-release/proof.sock`,
owned by `65497:65532`, mode `0660`. The one fixed peer is UID/GID `65532`.

| FD | Source-fixed resource |
| --- | --- |
| 198 | Sealed public runtime-root PEM |
| 199 | Sealed public proof bootstrap |
| 200 | Activated proof listener |
| 201 | Sealed separately enrolled proof signing key |
| 202 | Sealed raw32 execution-bundle key |
| 203 | Sealed raw32 historical-bundle key |
| 204 | Sealed raw32 delivery-history key |

The signed launch schema is `serverware.oidcSessionActivationReleaseProofLaunch/v1`.
It pins role, process mode, service and peer IDs; `rootPublicKeyFd`, `bootstrapFd`,
`listenerFd`, `signingKeyFd`, `executionBundleKeyFd`, `historicalBundleKeyFd`,
`deliveryKeyFd`; exact `inheritedFileDescriptors`; `listenerPath` and
`requestTimeoutSeconds`; plus listener socket/path device and inode pairs.
There is no journal FD, completion signer, state client, SQL writer, or root
private key. The delivery-history key is required by the genuine historical
custody; this worker does not call the token-opening API.

Public files are fixed under
`/run/serverware/oidc-session-activation-release-proof-trust/` as
`root-public-key.pem` and `bootstrap.json`. Private files are fixed under
`/run/secrets/` with prefix `serverware-oidc-session-activation-release-proof-`
and suffixes `signing-key`, `execution-bundle-key`, `historical-bundle-key`, and
`delivery-key`. Private originals require root ownership and mode `0400`.
Protected ancestors, no-follow opens, file identity and exact admitted sizes
are checked before reads. Root PEM and signing PEM caps are 16 KiB; AES
originals are exactly 32 bytes; the bootstrap cap is 48 MiB. The total retained
original inventory is bounded to 64 MiB, so individual maxima are not additive
permissions to allocate every maximum simultaneously.

The two read-only readers retain the existing five source-fixed TLS paths under
`/run/serverware/oidc-session-activation-delivery-completion-tls/`: `ca.pem`,
`custody.crt`, `custody.key`, `commit.crt`, `commit.key`. Public files require
root-owned mode `0444`; the two private TLS originals require root:65497 mode
`0440`. Each file's actual size, bytes digest, inode and unchanged pathname are
joined to the genuine nested root bootstrap. Reusing the authenticated TLS
read-only configuration does not import completion signing or state authority.

## Original-bound continuation

`_verify_on_work(*, bootstrap_bytes, root_public_key, live_window,
transport_deadline_ns, work)` requires the actual supplied allowance. Its
private `_ProofMaterial` contains same-call observations only; startup admits
the actual sealed originals again rather than accepting that material as proof.
Both verifier and publisher accept an optional restrictive `_current` that is
propagated through the selected nested cold-admission path; defaults retain the
fixed path. The paired root-only `_produce_on_work` accepts `payload`, `root_private_key`,
`root_public_key` and the same mandatory current-bound arguments.

Root delivery opens the construction work/window before any root, key or TLS
read. Public root/bootstrap admission precedes every private read and seal.
Actual sizes are charged before native reads; charging helpers are not wrapped
inside callbacks requiring unchanged work metrics. Nested authority/intent and
delivery expiry may only tighten the original first three clock samples and
deadline. Sticky guards retain and compare all observed epoch values and their
original monotonic checks.

After permanent UID/GID `65497` drop and supplementary-group removal, the same
PID continues; there is no post-drop exec or standalone `--run`. The process
mode deliberately remains `oidc-session-activation-delivery-completion`, which
the actual completion custody requires. The proof role, launcher, socket and
signer are nevertheless separate. UID reuse is not claimed as isolation from
another process with the same trusted-host-local purpose.

The literal eight-entry environment contains the existing fixed runtime
PATH/LANG/TZ/LD_LIBRARY_PATH/PYTHONDONTWRITEBYTECODE values, that process mode,
and only the root/bootstrap FD names for this proof worker. All seven resource
descriptors retain close-on-exec. Runner
`_run_on_work(*, work, live_window, transport_deadline_ns, delivery_current)`
passes the actual original work, narrowed pair and retained root guard into
startup, invokes one finite exchange, and closes without retry. The actual root
guard returns an epoch integer while retaining its original monotonic state;
it is not serialized into a clock DTO or replaced with a later sample.

Cleanup tracks descriptor identities, never blindly closes a replaced numeric
slot, and never retries an uncertain close. Startup cleanup and root cleanup
compose without re-closing already released descriptors. No worker, directory,
socket, account, enrollment, key or certificate is provisioned by these files.

The [proof producer](oidc-session-activation-release-proof-production.md) remains
the sole source of signed proof facts. The cold worker is not authority to mint
post-proof release/storage/client grants, open plaintext, or issue a cookie.
