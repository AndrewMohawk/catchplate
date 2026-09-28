# Same-permission release-grant acquisition

This source connects a proof-verified private continuation to the one-shot
[issuer service](oidc-session-activation-release-grant-issuer-service.md), then
to the existing original-verifying token handoff. It is not a public HTTP route,
a deployed service or proof that the separate release worker was provisioned.

```mermaid
sequenceDiagram
    participant P as Active permission
    participant I as Private grant issuer
    participant J as Custody journal
    participant R as Token-release worker
    P->>P: Spend shared handoff latch
    P->>I: Purpose + actual LIVE raw7
    I->>I: Admit independent policy/proof originals; derive grants
    I-->>P: Opaque client/server raw2
    P->>J: Retain exact bounded grant originals
    P->>P: Admit grants against actual retained history
    P->>J: Irreversible grant-keyed release claim
    P->>R: Same proof, intent, possession and ciphertext
    R-->>P: Request identity + token
    P->>P: Genuine original-bound receiving verification
```

## Caller boundary

Explicit [parent/v12 configuration](control-plane-oidc-session-activation-release-grant-acquisition-bootstrap.md)
adds only a root-pinned `grants.sock` endpoint. The caller accepts no posted
policy, target, grant, token, endpoint, resource pin or time window. Its inputs
are the exact retained signed proof, enrolled proof key, signed intent and
intent enrollment, actual pending-cookie possession and proof-bound encrypted
delivery hints. Old-token bytes are ephemeral; hashing them is not a substitute
for the full request identity. No request frame or returned token is journaled.

The active permission exposes `acquire_and_release_token()` and the owning
startup facade exposes `_acquire_oidc_session_activation_release_token()`.
These are private, no-argument continuations, not public request handlers.
The older direct `release_token(client_authorization_bytes=...,
server_bootstrap_bytes=...)` API remains available and uses the same one-use
handoff latch.

The exact owner, thread/process, target, cookie, cold endpoint, proof/intent
originals and predecessor guards remain live throughout. The caller preserves
the original work ledger and only inherited/narrowed time bounds. Its complete
remaining original-byte inventory is reserved before issuer contact. The final
token verifier retains the acquisition guard through a restrictive internal
handoff hook; that hook cannot supply authority or a replacement allowance.

## Durable behavior and uncertainty

The existing durable proof-attempt claim already prevents reacquiring a live
permission from recovered records. Acquisition additionally spends the same
in-memory handoff latch before issuer I/O. There is no restart/retry route from
stored proof or grants, so this slice adds no second journal attempt kind.

On a bounded complete reply, the existing `release-grants` suffix retains raw2
before semantic admission, including empty or malformed original bytes. Failed
framing, expired permission or failed durable writes fail closed; they do not
promise that a reply was retained. No journal result is treated as signature
verification or permission. The existing irreversible grant-specific claim
still precedes the sole token-release exchange.

A missing reply is an unknown outcome, not permission to repeat acquisition or
release. No success object, token cache, cookie mutation or automatic recovery
is introduced. A future HTTP handler must independently recheck the returned
token's actual current session, credential and identity before replacing the
pending cookie.

## Deployment boundary

`docker-compose.oidc-session-activation-release-grants.yml` mounts one already
provisioned socket read-only and refuses host-path creation. It supplies no
root signing key to the public application. The uninstalled issuer systemd
templates and exact-source launcher packaging are separate from public Compose.

Independent resource observation, issuance-policy/proof-worker delivery and
delivery of the exact newly signed server bootstrap to the actual release
worker remain required. Grants delivered only to this caller do not configure
that worker. Consume planner/history acquisition, per-request proof provisioning,
the public HTTP/cookie flow, separately authorized recovery and portal remain
open. All implementation here is source-only, unbuilt and unexecuted.
