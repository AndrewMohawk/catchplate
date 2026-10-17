# Historical registration signer subject

The separate private
[`authority_webauthn_registration_signer_history._verify_subject_on_configuration`](../catchplate/authority_webauthn_registration_signer_history.py)
reconstructs a registration subject from the original signer request-eight and
response-two, including when their original controls have expired. Existing
live signer and subject verifiers retain their expiry checks unchanged. This
is source implementation only: no build, execution or production admission has
been performed.

## Inputs and original verification

The keyword-only API takes `payload`, `configuration_digest`, `generation`,
`runtime_role_identities`, `request_originals`, `response_originals`,
`live_window`, `work`, and optional `transport_deadline_ns`. The caller must
supply independently root-admitted configuration/cohort inputs and an already
opened **current processing** window. Configuration mapping is not independent
provenance. No incoming successful subject, actor selector, evidence claims,
caller-chosen key or historical `now` argument is accepted.

Exact immutable originals retain their existing per-body and grouped limits;
the combined raw-ten inventory is at most 64 MiB. Mutable configuration graphs
are detached before native verification callbacks. All work uses the same
cumulative allowance, which may reject inputs below the aggregate byte ceiling.

The verifier performs the actual chain, rather than parsing a retained subject:

1. Authenticate the original enrollment issuer signature, independent audience,
   configuration/generation and separate key purpose; bind the original browser
   bytes, credential metadata and evaluation instant to that signed enrollment.
2. Verify the source request and planner response signatures, actual role-key
   separation, exact configuration scope and complete original byte commitments
   **before** decoding detached context/source observations.
3. Replay source primary/query proofs and original cutoff/root joins. Rebuild
   the ceremony, historical published-trust context and actual WebAuthn
   attestation result from the browser originals and authenticated source rows.
4. Derive the complete expected evidence claims, then verify the real evidence
   signature under the independently configured registration signer identity
   and key. The evidence interval must equal the interval derived from the
   original ceremony and challenge/session deadlines.
5. Regenerate the evidence-admission typed request and full input codec. The
   regenerated input bytes must exactly match the original signer response.

Private historical helpers reuse existing canonical, shape, signature,
commitment and proof primitives. They do not invoke live verifiers using a
substituted issuance timestamp or invent a successful verification result.

## Two distinct time scopes

Original enrollment, source request/response and evidence intervals must remain
positive, within their independently configured maximum ages and mutually
consistent. Source response expiry stays equal to the original request expiry;
evaluation/cutoff timing and context deadlines remain bound. The original
signer intervals must have a nonempty intersection. Future-issued controls and
future evaluation/cutoff observations beyond their configured skew fail.

Past original expiry is accepted only for historical reconstruction. Actual
attestation/trust semantics are evaluated at the authenticated original
registration instant; that instant does not replace the processing clock.
Processing retains the caller's unchanged current wall/monotonic window and any
earlier transport deadline, with nondecreasing samples. No window, lifetime or
work allowance is renewed. These local checks are not a hard watchdog or
independent clock/currentness witness.

## Output is not recovery permission

The result is an ordinary owned dictionary with exactly `userId`, `challengeId`,
`sessionId`, `mode`, `requestDigest` and `operationId`. User/challenge/session
identifiers retain their 4096-byte text bounds. Only
`oidc-session-first-enrollment` has a non-null session ID; the other original
modes are `bootstrap-token`, `development-bootstrap` and `existing-webauthn`.
Request/operation digests come from the genuinely regenerated typed request,
not a local association or posted metadata.

The caller must independently authenticate the retained execution grant and
complete planning exchange and join their actual request/operation commitments
to these same-call subject facts. A local signer/grant association is only a
locator. Present-caller identity, live session/role, CSRF and a separate recovery
purpose remain mandatory; historical ownership alone authorizes no transport
or effect. No SQL, signing, durable write, completion, credential finalization,
OIDC activation, retry permission or latest pending-head claim is returned.

The [public completion-recovery flow](registration-completion-recovery.md)
currently requires the same independently configured historical cohort and a
still-current cold-owner attestation. It does not automatically admit a rotated
configuration/cohort or extend that owner's lifetime to recover older records.

Deferred frozen verification must cover genuine expired originals versus live
rejection, altered or unrelated authentic exchanges, body/claim/signature and
key-purpose mismatches, impossible original intervals, future observations,
context/input regeneration differences and unchanged processing work/deadline
exhaustion. No such tests were run in this source batch.
