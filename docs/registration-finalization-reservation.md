# Finalization reserve computation

This source-only producer turns genuinely admitted finalization originals into
the actual signed reserve-request and computation-snapshot byte pair. It does
not reserve state by itself, establish a current head, execute SQL, finalize a
credential or activate an OIDC session. No builds, tests or runtime verification
were run; provisioning and production acceptance remain separate.

## Original admission before signing

[`authority_registration_finalization_reservation._produce_on_configuration`](../serverware/authority_registration_finalization_reservation.py)
has the keyword-only contract:

```text
payload, configuration_digest, generation, runtime_role_identities,
originals, before_vector_bytes, authorization_bytes, grant_bytes,
authorization_enrollment_bytes, grant_enrollment_bytes,
current_root_enrollment_bytes, root_public_key, computation_private_key,
predecessor_sequence, predecessor_head_digest, fence,
live_window, transport_deadline_ns, work
    -> CurrentRootComputation(request_bytes, snapshot_bytes)
```

`originals` is exact custody raw7: intent, relay, plan envelope, proof, inputs,
context and separate historical expectations. The complete before-vector,
dedicated caller authorization, execution grant and three enrollment originals
retain their individual source bounds and combined 64 MiB cap. Configuration,
generation, runtime cohort, root/key custody and predecessor sequence/head/fence
must be independently admitted by the actual caller. Browser or grant claims
cannot supply that independent predecessor scope.

The genuine [finalization execution admission](registration-finalization-execution-admission.md)
checks root-delegated caller authority for `webauthn.registration.finalize`,
actual custody signatures, configured planner/operation keys and complete
grant/plan/before-vector replay. Every grant identity and original interval
must match those same originals. An evidence-admission grant or key-purpose
substitution fails; a local record ID is not authority. Authorization must
already precede the new plan, as described in
[pre-plan issuance](registration-finalization-authorization.md).

The private `_admit_on_configuration` retains original-derived facts and its
live checker for this same invocation. No public or private producer accepts
that object as proof input. The existing `_verify_on_configuration` still
returns only unchanged raw7. The reserve producer passes the original raw4,
grant, vector and genuinely derived history to the actual
[`authority_successor_execution_preparation`](../serverware/authority_successor_execution_preparation.py),
which performs its own full replay before the enrolled computation key signs.
The capability digest comes from the authenticated original grant, not a
caller-chosen digest. Snapshot commitments cover the original plan, result and
complete before/after vectors.

## Unchanged lifetime and remaining owners

The supplied work allowance and original window are never replaced. The final
epoch deadline intersects caller, intent, relay, plan and grant expiries;
the monotonic bound only narrows from the original opening bracket and inherited
transport deadline. The retained checker continues sticky wall/monotonic
rollback checks and original freshness before and after signing. Existing
generic internal brackets are capped by those same limits; no new issue time
retimes a plan or revives expired authority.

The result contains only the actual `CurrentRootComputation` originals. A
separately admitted delivery owner must durably retain the exact request before
one bounded send, preserve uncertainty, and genuinely verify any returned state
acknowledgment against independent predecessor/fence and original commitments.
That acknowledgment is not a latest-head witness. No automatic retry follows
an uncertain publication or exchange. Protected execution still needs actual
pending/currentness admission, irreversible attempt ownership and finalization
SQL/completion orchestration. OIDC session activation remains a distinct step.
This producer opens no socket or journal and provisions no keys or authority.

## Live receiving verification

[`authority_registration_finalization_reservation_response._verify_on_configuration`](../serverware/authority_registration_finalization_reservation_response.py)
accepts original raw10 `(authorization, *raw7, complete-before-vector, grant)`
and response raw3 `(reserve-request, computation-snapshot, state-acknowledgment)`.
Its other keyword inputs are the independently admitted configuration/generation/
runtime cohort, three enrollment originals and root public key,
`expected_predecessor_sequence`, `expected_predecessor_head_digest`,
`expected_fence`, `live_window`, `transport_deadline_ns` and existing `work`.
It needs no private key and returns only unchanged raw3, never an authority token.

Complete framing and combined original/enrollment bounds precede callbacks.
One genuine finalization admission supplies the full original grant/plan/vector
replay. The actual computation signature is verified live against the original
current-root enrollment, and its fixed operation, request/operation identities,
grant capability digest and predecessor/head/fence must match independent or
genuinely replayed inputs. Request issue must equal original grant/plan issue;
expiry cannot escape the original intervals or supplied processing bound.

The verifier reconstructs the complete before/after vectors and exact canonical
snapshot from that same replay and compares original bytes. The fixed
finalization record verifier additionally authenticates the state signature,
exact request/pending digest, predecessor-plus-one sequence, previous head,
fence, scope, vectors and original interval. This historical acknowledgment
check does not substitute for the live reserve gate. Original sticky clocks and
all admitted freshness constraints remain checked through return. Expired
reservation retrieval requires separate historical recovery admission; this
entrypoint cannot revive it or infer a latest head from a signed receipt.
