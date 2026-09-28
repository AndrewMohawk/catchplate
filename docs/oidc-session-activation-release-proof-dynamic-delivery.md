# Dynamic release-proof worker delivery

This source-only path receives one independently issued proof bootstrap,
stages its exact protected resources, and continues the existing private
one-shot proof worker. It does not provision resources or establish that a
worker, proof exchange or credential handoff has run successfully.

## Independent public inputs

The isolated `oidc_session_activation_release_proof_dynamic_launcher.py`
accepts only `--root-delivery`. It starts as root with two activated listeners,
identified by names in either descriptor order:

- `serverware-oidc-session-activation-release-proof`, the existing `proof.sock`.
- `serverware-oidc-session-activation-release-proof-bootstrap`, fixed at
  `/run/serverware/oidc-session-activation-token-release/proof-bootstrap.sock`.

The staging pathname is root:65494, mode `0660`; the sole accepted issuer peer
is UID/GID 65494. The worker's existing public proof peer remains UID/GID
65532. The root-created listener and its protected pathname are distinct pins.

Before waiting, the receiver independently admits the root-signed policy and
its exact completion bootstrap, proof enrollment and intent enrollment. These
protected public files, plus the runtime root, live under
`/run/serverware/oidc-session-activation-release-proof-dynamic-trust`:

- `root-public-key.pem`
- `issuer-policy.json`
- `completion-bootstrap.json`
- `proof-enrollment.json`
- `intent-enrollment.json`

The staging request carries only its fixed purpose and the issued proof
bootstrap original. No caller-supplied policy, resource path, successful
material, plaintext token or replacement processing scope crosses that wire.
Receiving admission verifies the root signature and exact independent policy,
completion, enrollment, target and launch joins before private resource reads.

## Protected staging, then the actual worker

The unchanged worker inventory is seven descriptors, FD 198 through 204:
runtime root, issued proof bootstrap, proof listener, proof signing key,
execution bundle key, historical bundle key and delivery key. Actual key-pair
and AES-purpose bindings must match the independently admitted originals.
The five existing completion TLS files retain their source-fixed paths and
signed byte/hash pins. There is no completion signer, journal, writable state
client or directory provisioning in this receiver.

The receiver seals the public originals and holds the exact admitted keys,
TLS files and listener before returning `staged` plus the framed bootstrap
identity. This ACK is not proof-worker readiness, a committed-release proof,
token delivery or permission to retry. It precedes closing the staging channel
and permanently dropping to UID/GID 65497 in the same PID.

The dynamic runner then calls the genuine proof startup and one `serve_once()`
under the original work, opening samples and narrowed deadline. There is no
post-drop `exec`, renewed processing allowance or second accepted proof request.
The proof request still supplies its exact intent identity and ephemeral old
token independently. The real private producer replays authenticated originals
and reads committed state; staging itself does neither.

## Capacity and failure boundary

Incoming originals are capped before allocation with room reserved for held
public originals, decoded graphs, private resources and the eventual response.
The source-bound delivery continuation retains actual sealed identities,
clock/work continuity and measured retained capacity; startup separately owns
its accepted socket and read-only private readers. Capacity metadata is not an
authority DTO. The fixed seven descriptors are not treated as a blanket
exemption for arbitrary later file descriptors.

Failures and uncertain closes are terminal. Cleanup attempts only still-owned
matching descriptors; it neither retries the exchange nor removes retained
records or provisions replacement resources. The existing static proof launcher
continues to use its unchanged entrypoint. Deployment, independently matching
resources and public HTTP/session completion remain separate acceptance work.
Source `.199` connects the [request-scoped issuer](oidc-session-activation-release-proof-input-issuer-service.md)
to the real bounded packet reader and owned staging channel. The separate grant
issuer still needs a fresh proof-bootstrap connection instead of its cold pin.

## Opt-in packaging

The uninstalled `release-proof-bootstrap.socket`, alternate
`release-proof-dynamic.socket` and `release-proof-dynamic.service.in` templates
use the `serverware-oidc-session-activation-` prefix. They conflict with the
fixed proof socket/service and preserve the existing key/TLS substitutions;
only `@RELEASE_PROOF_DYNAMIC_TRUST_DIR@` supplies the five-file public trust
directory. The production Dockerfile copies the templates and isolated launcher
without rendering, installing or starting them. No issuer root signing key is
mounted into this worker.
