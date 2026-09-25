# Independent registration-evidence exchange

Source `.128`; implementation only, unbuilt and unexecuted. This adds the fixed
transport, concrete signer/replay owner and genuine caller-side reconstruction.
It does not establish an independently admitted signer launch, public enrollment,
evidence custody, registration finalization or production readiness.

## Original bytes across the service boundary

```text
authenticated operator/OIDC admission (public continuation still pending)
    -> cold enrollment issuer -> original signed grant
    -> held verifier/planner source raw4 + original browser bytes/time
    -> fixed raw8 request -> peer-checked signer owner
        -> genuine grant/source admission -> durable attempt -> evidence signing
    <- original evidence envelope + original input-codec bytes only
    -> caller replays original grant/source/attestation, verifies evidence
    -> regenerates evidence-admission request + compares input bytes exactly
    -> later custody and business execution gates (not bypassed)
```

`_EnrollmentOwner.prepare_registration_signer_request` composes the real cold
issuer and fixed request codec on unchanged work and original time. It does not
authenticate a raw carrier's caller or acquire source observations. Its caller
must already have completed the actual application admission.

The request has exactly eight original byte strings, in this order:

1. Signed source-request control.
2. Original source-request context.
3. Signed source-response control.
4. Original source observations.
5. Signed enrollment grant.
6. Original browser client-data JSON.
7. Original browser attestation object.
8. Canonical metadata: schema, source revision, credential ID, transports and
   original `verifiedAtEpochNs`.

Metadata cannot override user, label, enrollment authorization, policy, roots,
keys or sibling selection. Time is positive signed-64-bit nanoseconds and must
be exactly representable in microseconds; decoding never rounds or replaces it
with a current timestamp. The grant and authenticated source interval must agree
with these original browser/time bindings.

The response contains only the original evidence envelope and input-codec bytes.
Unsigned finalization arguments and caller-selected typed commitments are not
returned. All per-part limits and the 64 MiB aggregate ceiling are checked before
body allocation. These are transport ceilings, not a guarantee that maximal
inputs fit the cumulative verification allowance.

## One connection, one attempt

The private Unix stream protocol uses `SWESQ001`/`SWESR001`, fixed 64-bit lengths,
request half-close and exact response EOF. The serving owner checks the admitted
peer before reading the magic; the caller checks its admitted server peer before
sending bodies. One absolute deadline bounds each exchange. An earlier caller
deadline is never extended. There is no automatic retry, alternate endpoint,
JSON error fallback or unsigned success receipt.

`RegistrationEvidenceSigner.from_admitted_configuration` owns copied
configuration/generation/runtime inputs, the genuine dedicated evidence key,
separately admitted signer identity, original receipt interval and peer pins.
It validates their actual policy/key consistency and opens one real
`EnrollmentReplayStore` over an existing pinned private directory. It neither
creates storage nor supplies root/attestation provenance for those inputs.

The owner is nonroot, PID/UID/GID-bound and distinct from the caller and generic
authority role identities. A request must pass full framing/EOF before its one
validation allowance is created. Serving calls the actual exchange signer,
which durably consumes the grant before evidence signing. Expiry, lost delivery
or a later failure does not clear the marker. Closing releases the owned replay
lease and key references, never the borrowed provisioned directory descriptor.

This service deliberately requests evidence only. It supplies an empty sibling
list internally and discards the producer's finalization arguments. That empty
list does not assert OIDC completeness: complete live sibling and credential
history queries still belong to the later atomic finalization authority.

## Response verification and remaining work

The client performs one transport exchange and invokes the fixed configured
response verifier on the same work. That verifier genuinely authenticates the
original grant and source controls, replays source proofs, derives ceremony and
trust inputs from those observations, and repeats actual browser attestation
verification to obtain independent expected claims. It checks the configured
evidence signature, identity and exact originally derived evidence interval.

Returned input bytes are never decoded to choose trust roots, scope or policy.
The actual evidence-admission invocation and input codec are regenerated, and
the full original input bytes must match. Grant, source and evidence lifetimes
remain distinct and live through verification. The returned typed request is
for `webauthn.registration.evidence.admit`, not `webauthn.registration.finalize`.

Independent cold signer admission, protected signer key/listener/replay delivery,
actual signer identity/attestation and prior-publication provenance remain
external prerequisites. The new service factory is a composition boundary, not
proof that those prerequisites happened. A caller-supplied dictionary or key
cannot independently establish them.

The public operator/OIDC handlers still use legacy finalization. Root-admitted
endpoint selection, source acquisition at that authenticated boundary, full
custody/current-root successor execution, replay rollback/capacity management,
production provisioning and exact frozen verification remain unfinished.
