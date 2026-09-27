# Consume completion cold bootstrap

`oidc_session_activation_delivery_completion_bootstrap` genuinely admits a
root-signed, current-source `oidc.session.activation-delivery.consume` completion
launch. The fixed process is `oidc-session-activation-delivery-completion`,
UID/GID **65497**. Its private caller is also **65497:65497**, not the general
control-plane caller. This is a trusted-host-local purpose: all five hardware,
TEE and witness claims remain exactly false. A shared UID is not isolation
between the worker and its separately admitted private caller.

The signed envelope, payload and launch use dedicated
`signedOidcSessionActivationDeliveryCompletionBootstrap/v1`,
`oidcSessionActivationDeliveryCompletionBootstrap/v1` and
`oidcSessionActivationDeliveryCompletionLaunch/v1` serverware schemas.
There is no legacy launch fallback or generic replay widening.

## Actual originals and independent scope

The bounded 32 MiB envelope embeds four original controls as exact
`{base64Url, byteCount, bytesDigest}` records: `receivingCustody`,
`plannerBootstrap`, `plannerHistoryCustody` and `receivingHistoryCustody`.
Their original caps remain 16 KiB, 4 MiB, 8 MiB and 8 MiB. The dedicated
[completion custodian](oidc-session-activation-delivery-completion-custody.md)
authenticates all four on the same work allowance. The old consume planner and
planning-history original intervals are historical metadata. Fresh completion
custody and v6 activation-history authority, not expired launches, constrain
current processing. The outer launch must fit the fresh custody interval.

The root independently pins the consume request/scope/journal expectations,
packet and caller-authorization identities, current pending sequence/head/fence,
local completion-journal checkpoint, configuration/generation/runtime cohort,
receiver identity and enrolled completion signing key. The original current-root,
consume grant and caller enrollments, and historical caller authorization, are
also embedded with both raw SHA-256 and domain-separated identity pins.
Their genuine signatures, exact subjects and purposes are checked. Historical
caller admission here is not full encrypted plan/effects replay; the actual
worker repeats that replay from originals before completion.

The completion signer is separate from root, consume/activation planners,
caller, grant, computation, state and configured generic/evidence/transition
key purposes. Root-asserted receiver measurement must equal its enrolled
completion measurement; neither assertion is a hardware measurement proof.
The three AES key digests come from genuine custody originals, remain pairwise
distinct, and are joined to actual sealed key bytes during delivery. No key
value is serialized into the bootstrap or SQL packet.

Root-held PostgreSQL configuration supplies separate custody/commit read-role
tuple8 values: deterministic DSN, timeout, fixed role, client DN, client serial,
issuer DN, query manifest and structure manifest. Exact five TLS file sizes and
hashes, literal database endpoint, fixed state endpoint and listener/journal
identities are bound. Actual reader constructors remain responsible for their
real immutable query/catalog admission. ACKs and SQL responses cannot select
these independent pending, packet or reader pins.

## Interfaces and lifetime

`_verify_on_work(*, bootstrap_bytes, root_public_key, work, live_window=None,
transport_deadline_ns=None)` returns internal `_CompletionMaterial` facts.
`_produce_on_work` takes independent `payload`, root private/public keys and
the same allowance arguments; it authenticates embedded originals before
signing and checks canonical output readback. Neither accepts a successful
material object as authority. Parsing, capture, hashing and cryptography share
the bounded work ledger; the original aggregate is capped at 64 MiB.

Actual cold delivery calls `_construction_on_work(work)` **before** root/key/TLS
I/O and always supplies that original window/deadline to verification and
startup. The optional verifier fallback is not the cold handoff. `_fresh`
checks fresh role/custody intervals using the retained opening; it never
revives an old planner. Narrowing retains the original first three clock
samples and never extends the inherited deadline.

Material retains actual raw4 controls, three enrollment originals and caller
authorization, genuine custody, independently admitted receiver/configuration
facts, planner/operation/completion public keys, current pending tuple3,
checkpoint tuple2, state endpoint tuple4, reader configuration tuple8 pair,
TLS pins, launch and original attestation interval/opening. It is ordinary
same-call data, not a reusable admission capability.

See [eight-FD delivery](oidc-session-activation-delivery-completion-delivery.md)
and [service composition](oidc-session-activation-delivery-completion-service.md).
This source is unbuilt, unexecuted and unprovisioned. Public dispatch, cold
application-caller packaging and plaintext release are separate work.
