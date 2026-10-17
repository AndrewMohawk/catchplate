# Cold release grant issuer delivery

This source-only worker is a separately provisioned one-shot release grant issuer.
It is not a root generator, a storage provisioner or evidence of deployed operation.
Its only private signing capability is the actual independently provisioned runtime
root key, confined to this fixed issuer role. The control-plane caller receives no
root key, AES/history key, completion signer, state writer or SQL writer.

The separate [dynamic input path](oidc-session-activation-release-grant-input-delivery.md)
in source `.200` admits a fresh proof bootstrap under independent cold
authorization and derives the exact signed policy/launch originals described
here. The static entrypoint and its fixed trust files remain strict; replacing
`proof-bootstrap.json` alone cannot authorize another request.

The role and process mode are `oidc-session-activation-release-grant-issuer`, UID/GID
65496. The root-created listener is
`/run/catchplate/oidc-session-activation-token-release/grants.sock`, pathname owner
65496:65532 and mode 0660, with fixed request peer 65532:65532. Independent root
provisioning supplies the listener and all signed originals before launch; this
code creates no path, changes no file protection and installs no service.

## Signed launch and exact originals

The signed/payload schemas are
`catchplate.signedOidcSessionActivationReleaseGrantIssuerBootstrap/v1` and
`catchplate.oidcSessionActivationReleaseGrantIssuerBootstrap/v1`. Purpose is
`launch-oidc-session-activation-release-grant-issuer`; trust mode is
`trusted-host-local`. The payload contains only schema/source/purpose/role/trust,
the exact `issuerPolicyDigest` and `proofBootstrapDigest`,
`rootSigningKey: {byteCount, bytesDigest}`, issue/expiry and `launch`.

Both public-original identities use the actual
[issuer policy](oidc-session-activation-release-grant-issuer-policy.md) framed
domains. The root-key byte pin is a SHA-256 identity of the exact bounded PEM
original, not an alternative public signing identity: its actual Ed25519 private
key must still pair with the independently supplied runtime root public key.

The policy and proof bootstrap remain separate originals, never base64-embedded
in this launch. `_verify_on_work` requires `bootstrap_bytes`,
`issuer_policy_bytes`, `proof_bootstrap_bytes`, `root_public_key`, and mandatory
`work`, `live_window`, `transport_deadline_ns`. It authenticates the launch root
signature, exact original identities and genuine .192 policy/proof admission.
The launch interval must fit inside the admitted policy interval. Root-authorized
release directory/checkpoint pins remain policy, not observations of empty or
durable storage.

The actual `_IssuerMaterial` has twelve fields: `bootstrap_bytes`,
`issuer_policy_bytes`, `proof_bootstrap_bytes`, same-call `policy_material`,
owned `launch`, `root_signing_key_byte_count`, `root_signing_key_digest`,
`attestation_interval`, `opening_sample`, `live_window`, `deadline_ns`, `live`.
No successful material is accepted as an authority input. `_produce_on_work`
requires the payload, the same separate originals, actual root pair and mandatory
allowance; genuine original admission precedes signing and canonical signature
readback. It does not produce or infer OS resource pins.

## Fixed delivery inventory

| FD | Original or resource |
| --- | --- |
| 198 | Sealed runtime root public key |
| 199 | Sealed signed issuer launch bootstrap |
| 200 | Exact root-created activated listener |
| 201 | Sealed .192 issuer-policy original |
| 202 | Sealed .190 proof-bootstrap original |
| 203 | Sealed runtime root-signing-key PEM |

The trust directory is
`/run/catchplate/oidc-session-activation-release-grant-issuer-trust`, with fixed
files `root-public-key.pem`, `bootstrap.json`, `issuer-policy.json` and
`proof-bootstrap.json`, each root-owned mode 0444 and link count one. The sole
secret path is
`/run/secrets/catchplate-oidc-session-activation-release-grant-issuer-root-signing-key`,
root-owned mode 0400 and link count one. Protected root-owned ancestor directories
are opened component by component with no symlink following. No environment,
request or signed payload can substitute these paths.

The root public key, launch, policy and key each have a 16 KiB cap; the detached
proof bootstrap retains its 48 MiB cap. The fixed source inventory is below the
64 MiB aggregate ceiling; actual sizes are checked and charged before read/seal.
Nested policy/proof admission retains its own bounded originals on the same work.
Signed key length is enforced before private reading, then exact bytes and the
real key pair are checked. Every delivered descriptor retains CLOEXEC.

## Same-process current authority and cleanup

The isolated launcher accepts only `--root-delivery` under
`/runtime/python/bin/python3`, with the fixed launcher path
`/runtime/authority-bootstrap/oidc_session_activation_release_grant_issuer_launcher.py`.
One construction work ledger and clock bracket start before public-original I/O.
Actual root launch/policy/proof admission completes before any private-key access.
The guard runs directly before and after charged original reading and sealing;
charging helpers are never wrapped inside a stable-work native callback.

After exact resource checks the same PID permanently drops every UID/GID to
65496, clears supplementary groups and verifies the unprivileged process. It
sets only the literal eight-variable environment. The original construction
guard survives through `_run_on_work(work=..., live_window=...,
transport_deadline_ns=..., delivery_current=...)` into the identically named
startup keywords. Windows preserve the original first three samples and only
tighten; the actual root guard retains its prior epoch and monotonic observations.
There is no post-drop exec, standalone `--run`, replacement ledger or renewed
request allowance.

The runner initializes once, calls `require_started().serve_once()` once, and
always attempts startup cleanup. Success requires the actual service's true
finite completion and established cleanup; failure never authorizes retry.
Root delivery owns exact descriptor identities through handoff and cleanup.
Already closed descriptors are not retried; replaced/indeterminate descriptors
are not blindly closed and cannot yield a successful cleanup result. Error text
contains no original, private key or request token.

The separately authored service must still admit the exact ephemeral request,
derive genuine grants, send its bounded response and close under these same
guards. This cold delivery path neither opens a token nor authorizes a public
cookie. Independent provisioning, process isolation and end-to-end request-scoped
acquisition require their own evidence; source delivery is not runtime proof.
