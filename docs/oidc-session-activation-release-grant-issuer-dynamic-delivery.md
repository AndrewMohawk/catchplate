# Dynamic release-grant issuer delivery

This source path receives one fresh, root-signed proof bootstrap, derives the
existing exact grant-issuer originals under an independent cold authorization,
and continues the actual finite grant issuer. It does not provision resources
or establish runtime readiness, successful token delivery or a current session.

## Independent cold originals

The isolated dynamic launcher accepts only `--root-delivery`. Its protected
public trust directory is
`/run/catchplate/oidc-session-activation-release-grant-issuer-dynamic-trust`,
with six root-owned, single-link, mode `0444` files:

- `root-public-key.pem`
- `authorization.json`
- `proof-input-policy.json`
- `completion-bootstrap.json`
- `proof-enrollment.json`
- `intent-enrollment.json`

The independently signed dynamic authorization fixes the client, release and
issuer resource policy, signer identity and both listener pins. Its actual
public-original verifier runs before waiting. No posted resource template,
replacement policy, private packet, successful-material carrier or token is
accepted on the staging channel.

Two activated sockets are selected by distinct names, in either FD order:

- Existing `catchplate-oidc-session-activation-release-grant-issuer`, at
  `/run/catchplate/oidc-session-activation-token-release/grants.sock`.
- New `catchplate-oidc-session-activation-release-grant-issuer-bootstrap`, at
  `/run/catchplate/oidc-session-activation-token-release/grant-issuer-bootstrap.sock`.

The new staging pathname is root:65494, mode `0660`; its only accepted issuer
peer is UID/GID 65494. The existing public grant listener remains
65496:65532, mode `0660`, and accepts the fixed public caller later.

## Exact proof, then signer and derived originals

The staging raw2 contains only its source-fixed purpose and the exact fresh
proof-bootstrap original. Genuine admission checks that original against all
independent cold originals before any root-signer read. Only then does the
receiver open the existing fixed root-signing-key path, check its signed
size/hash pin and actual Ed25519 pair, and call the real dynamic producer.

The producer returns the existing issuer-policy and issuer-bootstrap originals.
They are genuinely re-admitted with the same exact proof bootstrap; the old
key-admission class check is unchanged. The receiver seals the existing six
FDs: 198 runtime root, 199 issuer bootstrap, 200 public grant listener,
201 issuer policy, 202 proof bootstrap and 203 root signer. There are no
AES/history keys, TLS reader resources, SQL/state writes or new directory
provisioning in this receiver.

The ACK is `staged` plus the exact proof-bootstrap identity in the distinct
grant-input delivery domain. It is sent only after the derived originals,
signer and listener are held. It is not worker readiness, a release outcome,
token delivery or permission to retry.

## Same-process finite continuation

After normal staging connection/listener closure, the receiver permanently
drops to UID/GID **65496**, with no supplementary groups, in the same PID.
The explicit dynamic runner then invokes the actual grant issuer once. The
existing static entrypoint and runner path retain their prior behavior.

One original work ledger, opening samples and narrowing-only clock allowance
cover intake, signature production, sealed handoff and the later public
grant exchange. Source-bound continuation metadata retains the actual seals,
listener and measured capacity; it cannot be supplied as incoming authority.
The genuine issuer separately accounts for its accepted and outgoing staging
sockets. Its configured launch/v2 still stages the exact release-server
bootstrap before returning the public grant pair.

Incoming proof bytes are capped before allocation inside the same 64 MiB
inventory as cold originals, bounded decoded graphs, derived originals and
reserved exchange space. Startup accounts for its rereads and second genuine
admission rather than opening another allowance. Failures or uncertain closes
are terminal: no retry, re-exec, token logging or automatic resource recreation.
Cleanup closes only still-owned matching descriptors. The opt-in packaging
remains uninstalled source; provisioning and runtime acceptance are separate.
