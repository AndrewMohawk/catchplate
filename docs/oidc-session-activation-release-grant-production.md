# Original-only LIVE release grant production

For the subsequent actual worker connection and R0/R1/R2 split, see
[current grants over historical evidence](oidc-session-activation-release-grant-history-bridge.md).
The original library-only boundary below is historical, not a claim that the
connected source worker has been executed or provisioned.

`authority_oidc_session_activation_release_grant_production._produce_on_work`
is a private root-issuance library. It returns exactly
`(client_authorization_bytes, server_bootstrap_bytes)`, not an admitted carrier
or a plaintext token. This source does not yet implement an issuer owner or
acquisition service.

## Independent inputs

The function takes the actual LIVE release raw7, an original signed
[issuer policy](oidc-session-activation-release-grant-issuer-policy.md), its
exact bound [proof bootstrap](oidc-session-activation-release-proof-service-bootstrap.md),
the independently held root key pair, and the original work/window/deadline.
It accepts no posted expected scope, outcome digest, request identity, launch
resources, successful proof object, recovery selector or permission callback.

Raw7 is `(purpose, proof, proofEnrollment, intent, intentEnrollment, oldToken64,
encryptedEnvelope100)`. The old token is ephemeral possession material. This
module performs no journal, log, socket or filesystem write, and never opens
the encrypted delivery envelope. Its root private key is not a public caller
credential or a key supplied by the raw request.

## Original admission and issuance

The signed policy independently selects the client ID/identity, fixed endpoint
and release launch/resource pins. Genuine policy admission authenticates the
exact proof bootstrap and its nested originals. The producer then joins the
request's intent and enrollment originals byte-for-byte to those root pins.

It re-admits root release custody, signed COMPLETE and state ACK, current live
intent with old-token possession, and the distinct signed release proof.
Completion ancestry, target and receipt identity come from the independently
root-bound completion originals, never copied from the incoming proof.
Limited original enrollment readbacks obtain the real purpose-separated public
keys and age/skew policies; they do not replay private history. No historical
AES, commit reader, SQL writer or completion signer is accepted by this API.

The actual authenticated evidence derives the canonical expected outcome and
the complete framed raw7 request identity. The producer then calls the genuine
existing root producers in order: outcome-storage authorization, LIVE server
bootstrap, and client authorization. Each output receives original verification
readback on the same work. The server embeds the exact proof-associated custody
original; scope17 binds its full signed bytes, the derived outcome/request, and
the independently configured client. Only the final two originals escape.

The source-fixed storage checkpoint is `recordCount=0, outcomeDigest=null`.
That is permission for the exact independently pinned slot, not an observation
that the slot exists or is empty. A derived outcome identity is likewise not
proof of persistence, egress, receipt acknowledgment or current session state.

## One inherited allowance

The held input inventory, decoded originals and reserved bounded output sizes
are subject to the 64 MiB aggregate ceiling. All parsing, hashing, signatures,
comparisons and encoding use the supplied cumulative work. There is no new
clock opening or per-stage timeout. Policy, proof, intent, custody, completion,
delivery and endpoint bounds only narrow the original window and deadline.

The private optional `_continuity` hook exchanges only nondecreasing integer
epoch/monotonic floors with a future real owner. It cannot replace admission,
return permission or widen a bound. Floors are checked against the current
narrowed deadlines; mandatory original live guards remain active through the
final raw2 return. Intent/proof use the base-only hook to avoid guard recursion.

## Still open

Root-key delivery/custody, actual resource observation and provisioning,
issuer startup/service, response delivery and same-active-permission acquisition
composition remain separate work. The finite
[grant transport](oidc-session-activation-release-grant-transport.md) is only
framing until connected to such an owner. This library does not launch workers,
retry, retain tokens, install a cookie or authorize public activation/recovery.
Source-only: unbuilt, unexecuted and unprovisioned; no production acceptance is
established by this module.
