# Independent private release response verification

[`authority_oidc_session_activation_release_response.py`](../catchplate/authority_oidc_session_activation_release_response.py)
consumes original public evidence and the exact private exchange to verify the
returned token commitment. It accepts no admitted-result object, cached success,
delivery AES key, history owner, signer or store. Its sole output is the exact
64-byte token after all checks. This is authored source, not build, execution,
provisioning or production evidence.

## Original-only interface

```text
_verify_on_work(
    *, response_originals, request_originals,
    client_authorization_bytes, server_bootstrap_bytes, root_public_key,
    expected_client_scope, live_window, transport_deadline_ns, work,
    _continuity=None, _retain_current=None, _additional_original_bytes=0
) -> token64
```

The exact raw7 live or raw8 recovery request and success-only raw2 response use
the existing [private transport](oidc-session-activation-release-transport.md).
The caller independently supplies the closed 17-field scope of the fresh
[client authorization](oidc-session-activation-release-client-authorization.md),
including server-bootstrap identity, profile, request identity, client identity,
server receiver, caller/producer, release/receipt bindings and expected outcome.
Client identity never substitutes for the server's `receiverIdentity`.

All original byte references, the actual public root key and original lifetime
are held before the complete mutable scope is captured or any native/hash
callback runs. Every frame has its actual contract bound. The combined external
original and re-admission inventory must fit 64 MiB before scope capture or
nested admission; reads, copies, cryptography and reconstruction consume the same
existing cumulative work. No replacement ledger, clock opening or deadline is
created. Wire capacity does not promise enough remaining verification work.

`_additional_original_bytes` is an exact integer from zero up to, but not
including, 64 MiB. It adds the actual caller's already-held active-context
representations to the receiving reservation; it cannot increase the allowance
or supply authority. The default is zero. The length-only
`_reservation_bytes(request_lengths, *, client_bytes, bootstrap_bytes,
additional_original_bytes=0)` helper lets a source-owned exchange caller apply
the same check before socket contact. It returns a conservative size, not an
admission result or permission; the caller must refuse sizes above the shared
ceiling.

The reservation includes eight server-bootstrap byte footprints, four
footprints for request/client/fixed-response originals, four for the bounded
nested custody/planner/vector/state-enrollment/storage/recovery originals,
eight source-maximum client-scope footprints, four source-maximum reconstructed
outcome footprints and four framing footprints. Bounds use actual enclosing
original lengths and source caps before nested bytes are decoded. No incoming
graph or claimed capacity selects a larger bound. These conservative
representation counts are **not a Python process-heap guarantee**. Existing
LIVE/RECOVERY schemas, profiles, signature checks and historical semantics are
unchanged; oversize combinations fail earlier.

## Genuine admission and comparisons

The verifier genuinely authenticates the fresh client original and its pinned
server bootstrap. That bootstrap authenticates the original custody/planner and
state controls, storage authorization and, for recovery, the separate fresh
recovery authorization. No successful material is accepted from the caller.
Both client and original server guards remain live throughout verification.

It then performs these fixed joins:

1. Recompute the domain-framed identity of the exact ordered request and compare
   it to both the independently authorized `requestIdentity` and response echo.
   Echo alone supplies no authentication.
2. Read back the genuine root-signed state enrollment to obtain actual planner,
   computation, completion and state public-key exclusions. Join its original
   identity and database/generation pins to the actual admitted controls.
3. Check the original ciphertext's format and SHA-256 against the independently
   authenticated release target, without decrypting it.
4. Admit the actual intent/enrollment and old-token possession once. Join the
   intent identity to the original root custody. A limited genuine intent
   enrollment readback obtains the actual caller public key for proof-signer
   exclusion; it does not repeat intent or historical execution replay.
5. Admit the actual proof/enrollment once against independently pinned producer,
   receiver, release, custody/intent/state-receipt identities and the genuine
   intent's original interval. It cannot use a caller-selected exclusion set.
6. Reconstruct the canonical outcome from those same-call admitted originals,
   including proof and enrollment digests, and compare its domain identity to
   the independently root-pinned expected outcome in **both** profiles.
7. Validate the response token's exact 64-byte URL-safe grammar and SHA-256
   against the authenticated `deliveryScope.newTokenDigest`, then run every
   retained current guard before returning those same bytes.

The state and intent enrollment readbacks are deliberate bounded public-key
admission, charged to the original work. They avoid inventing an unauthenticated
key-extraction convention; the original client/server, intent and proof
verification paths are each invoked once. No SQL or encrypted historical
execution replay is performed by this receiver.

## Live versus recovery authority

`live-release` invokes the existing live intent and proof verifiers. Their
original expiry and policy narrow the processing allowance; all genuine guards
remain attached through the final token check.

`recovery` is selected only by the independently expected client scope and
authenticated server bootstrap. The latter must genuinely admit its distinct
fresh root recovery purpose and checkpoint `1/outcomeDigest`. Only then are the
separate historical intent/proof verifiers used. Old intervals remain signed,
bounded evidence, not renewed execution permission. Current possession is
still checked, the original delivery must remain unexpired, and fresh client,
server, storage and recovery lifetimes remain current.

Recovery additionally requires the supplied raw8 outcome record to be byte-for-
byte equal to the canonical reconstruction. Its identity must equal the client
pin, fresh recovery pin and independently authorized checkpoint. The receiver
never opens or reads that directory: these are original-authority/identity
comparisons, not an observation that a record exists or was durably written.

Cross-guard epoch and monotonic observations remain sticky. Every narrower
window keeps the original opening bracket, and deadlines can only decrease.
Historical evidence does not clip the new processing window to an expired old
intent or silently create a new one. Any failed admission, comparison, budget
or current guard withholds the token; no error body or retry authority results.

The optional private `_continuity` seam adds the actual configured caller's
owner/FD guard without changing standalone admission. Before phase checks and
after mandatory samples, the receiver supplies its retained epoch/monotonic
floors; the real owner absorbs them, checks its original resources and clocks,
and returns an exact immutable integer pair that can only increase those
floors. The receiver retains that pair before its next sample. Neither side
can hide rollback below the other's newer observation. This is restrictive
clock continuity, not a success or authority input; all original checks still
run, and callback work may increase but never reset its original ledger. The
returned floors must also remain strictly below the receiver's current narrowed
epoch deadline and monotonic bound, including after its final inner guard. The
configured caller tail-returns this verifier's bytes without a weaker native
suffix after the final genuine original and owner checks.

When supplied, that original continuation now also reaches the genuine nested
client/server, intent and proof admissions. Children receive a separate
base-only floor function: it calls the original caller and retained original/
narrowed processing guards, never the aggregate response guard or an attached
child. Their final genuine guards remain attached to the aggregate guard, so
actual newer observations remain sticky without recursive ancestry. With no
external continuation the old standalone nested `None` path remains unchanged.

The private `_retain_current(current, window, bound)` hook receives the full
genuine final response guard and exact narrowed scalars after token admission.
Its return value supplies no authority; the same ledger is checked and the
full guard runs again before token return. A source-owned caller may retain this
guard for an active finishing boundary, but must never feed it back into its
own ancestor. Nor does retaining it make a closed actor/acquisition usable:
post-cleanup delivery needs its separately defined original-preserving terminal
continuation. Neither token nor request is passed to this retention callback.

## Remaining boundary

This verifies that returned secret bytes match the exact authenticated release
commitment under current independent client authority. It does **not** attest
server execution, store fsync/readback, network delivery, recipient
acknowledgment, single egress, latest session state or hostile-host rollback
resistance. Computing an outcome identity is not observing durable retention.

This verifier itself does not perform network I/O or authorize a new exchange.
The [configured private caller](control-plane-oidc-session-activation-release-client.md)
separately composes one guarded exchange and this genuine verifier; it supplies
the restrictive continuity seam, never a caller-posted callback. Public/portal
authority and independent production gates remain separate. No key
provisioning, service installation or runtime claim follows.
