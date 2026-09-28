# Consume-input issuer cold delivery

This source-only cold path delivers six independently provisioned resources to
the finite consume-input issuer. It authenticates public originals before
opening the runtime root signer, then permanently drops privilege and continues
in the same process and original work/window. It does not create resources,
install a service or deploy a worker. Explicit launch v2 permits one exact-pair
staging exchange after issuance; the original launch v1 has no such channel.

## Closed signed launch

The role/process mode is `oidc-session-activation-consume-input-issuer`, with
UID/GID 65495 and caller UID/GID 65532. The root-created listener is
`/run/serverware/oidc-session-activation-consume-inputs/grants.sock`, with exact
activation name `serverware-oidc-session-activation-consume-input-issuer` and
pathname ownership 65495:65532, mode 0660. The signed launch independently pins
both kernel-socket and pathname device/inode values. Its fixed peer remains the
actual control-plane caller; a pathname owner is not the kernel listener peer.

The signed/payload schemas are
`serverware.signedOidcSessionActivationConsumeInputIssuerBootstrap/v1` and
`serverware.oidcSessionActivationConsumeInputIssuerBootstrap/v1`; the launch
schema is `serverware.oidcSessionActivationConsumeInputIssuerLaunch/v1`. Purpose
is `launch-oidc-session-activation-consume-input-issuer`, bound to the actual
source revision and `trusted-host-local` trust mode. Explicit launch v2 is
`serverware.oidcSessionActivationConsumeInputIssuerLaunch/v2`; it adds exactly
`deliveryEndpoint` to the otherwise unchanged launch fields. Both envelope and
payload schemas remain v1. No request-selected profile or v2-to-v1 fallback exists.

The v2 endpoint has exactly `path`, `timeoutSeconds`, `peerUid`, `peerGid`:
`/run/serverware/oidc-session-activation/consume-bootstrap.sock`, an integer
timeout 1..30 no greater than the signed request timeout, and root peer 0:0.
It narrows the same opening allowance and adds no inherited descriptor. The
actual owner creates, tracks and closes one staging socket under its fixed
channel; a supplied socket or arbitrary FD cannot replace it.

The closed payload contains `schema`, `sourceRevision`, `purpose`, `role`,
`trustMode`, `issuerPolicyDigest`, `activationPlannerBootstrapDigest`,
`rootSigningKey`, `issuedAtEpochNs`, `expiresAtEpochNs`, `launch`.
Policy and activation planner are separate exact originals, not embedded
templates. Their framed identities use the actual consume-input issuer policy
domains. `rootSigningKey` contains only `byteCount` and raw `bytesDigest`.
The launch fixes six descriptors, listener path, process identities, bounded
timeout and actual socket/path pins. Its interval must fit within the genuinely
admitted independent policy; the old activation launch remains historical data.

`_verify_on_work` takes exact `bootstrap_bytes`, `issuer_policy_bytes`,
`activation_planner_bootstrap_bytes`, `root_public_key`, and mandatory original
`live_window`, `transport_deadline_ns`, `work`. Optional private `_continuity`
only propagates restrictive clock floors. `_produce_on_work` instead takes the
owned payload and actual root private/public pair; it genuinely admits policy
and activation originals before signing and checking its signed readback.
Neither accepts a verified-material input or loads a key.

The private `_IssuerMaterial` has thirteen fields: `bootstrap_bytes`,
`issuer_policy_bytes`, `activation_planner_bootstrap_bytes`, `policy_material`,
`launch`, `root_signing_key_byte_count`, `root_signing_key_digest`,
`attestation_interval`, `opening_sample`, `live_window`, `deadline_ns`, `live`,
`delivery_endpoint` (None for v1).
These are same-call outputs, not transferable verification proof.

## Exact files and descriptor delivery

Public trust files live only under
`/run/serverware/oidc-session-activation-consume-input-issuer-trust`:

| FD | Original/resource | Bound |
| --- | --- | --- |
| 198 | `root-public-key.pem` | 16 KiB |
| 199 | `bootstrap.json` | 16 KiB |
| 200 | Fixed activated listener | One socket |
| 201 | `issuer-policy.json` | 64 KiB |
| 202 | `activation-planner-bootstrap.json` | 4 MiB |
| 203 | Runtime root signer | 16 KiB |

The private file is exactly
`/run/secrets/serverware-oidc-session-activation-consume-input-issuer-root-signing-key`.
Public files must be root-owned mode 0444, private mode 0400, all regular with
link count one. Protected root-owned ancestors and leaves are opened without
following symlinks. Actual byte counts are charged before reads/sealing;
pre/post metadata and named-file identities are checked. The original inventory
is bounded by 64 MiB. The independent policy retains its own genuine historical
activation admission and key/resource separation checks.

Root delivery begins with exactly FD3 and the one matching systemd activation
name. It reserves destinations without overwriting an occupied FD, reads and
seals public originals, loads the public runtime root and genuinely verifies the
signed launch/policy/activation originals. Only then does it open the private
signer file. The exact byte count and digest must match the authenticated pin;
the actual Ed25519 private key must pair with the runtime root. Metered key
helpers are invoked directly, never inside a stable callback that forbids work
changes. Six inherited descriptors remain CLOEXEC, with sealed public/private
originals and exact listener pins. No bootstrap file is written or replaced.

There is no delivery AES key, history bundle key, completion signer, SQL/state
writer, journal, TLS private key or token store in this issuer inventory.
Root-signing capability is private to this independently provisioned worker.
A signed directory or endpoint pin is policy, not an observation or provisioning
proof for any destination worker.

## One process and original lifetime

The sole construction work ledger and clock bracket begin before public-file
I/O. Actual policy/activation admission and signing-key checks preserve sticky
epoch/monotonic floors; interval, policy and timeout narrowing keep the original
first three samples and can never add lifetime or work allowance. Root delivery
retains this lifetime-only closure after dropping privilege; it does not retain
a six-only FD-inventory callback that would reject the startup-owned accepted
connection.

Supplementary groups are cleared; all real/effective/saved UID/GID values become
65495, with unprivileged-process checks before continuation. Only the literal
eight-entry environment remains. The isolated launcher is
`/runtime/authority-bootstrap/oidc_session_activation_consume_input_issuer_launcher.py`,
invoked by `/runtime/python/bin/python3 -I ... --root-delivery`.
It calls the runner's `_run_on_work` with the same `work`, narrowed `live_window`,
`transport_deadline_ns` and retained `delivery_current`. There is no post-drop
exec, detached process, standalone `--run`, retry or replacement allowance.
Cleanup checks exact descriptor identities and fails truthfully without blindly
closing replaced slots or retrying uncertain closes.

The [finite service](oidc-session-activation-consume-input-issuer-service.md)
authenticates actual request originals and returns signed consume-planner/history
originals. Under launch v2 it first sends those exact two originals to the
[dynamic receiver](oidc-session-activation-consume-dynamic-delivery.md), checks
both framed identities in the staged ACK and closes its owned staging channel.
The ACK is not worker readiness, private replay, commit or token delivery. V1
continues to return originals without staging. Neither closes the public
dispatch/HTTP/cookie path. Installation, provisioning, runtime verification and
production acceptance remain separate.
