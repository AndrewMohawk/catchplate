# Activation-planning current-root head observation

The [head protocol](../serverware/authority_current_root_head.py) and actual
`CurrentRootDecisionOwner.observe_head` implement a separate read-only state
observation for `oidc.session.activate`. This is source-only, unbuilt and
unexecuted. It is not the completion lookup protocol, a receipt, an execution
grant or a successful-verification token.

Delivery consumption uses a [separate head purpose and explicit state v7 peer](oidc-session-activation-delivery-state.md).
It shares bounded protocol machinery, but has distinct schemas, operation,
signature/query domains and transport frames. The activation defaults and
historical APIs documented here do not accept consume observations.

## Exact originals

The canonical query is at most 4 KiB and has exactly seven fields:
`schema`, `sourceRevision`, `enrollmentDigest`, `operation`, `challenge`,
`contextDigest`, `expectedVectorDigest`. Its schema is
`serverware.policyAuthorityCurrentRootHeadQuery/v1`; its original-byte identity
domain is `serverware.policyAuthorityCurrentRootHeadQueryIdentity/v1`.
`operation` must be `oidc.session.activate`.

The actual caller must generate a fresh unpredictable 32-byte challenge for
each invocation and retain that exact query. The wire requires its canonical
64-character lowercase hex spelling; shape validation alone does not establish
entropy, uniqueness or freshness. Context and expected complete-vector digests
must come from the caller's genuinely admitted original planning scope, not an
observation or database response.

The signed response is at most 8 KiB. Its exact envelope is `schema`, `payload`,
`signatureBase64Url`, with schema/signature domain
`serverware.signedPolicyAuthorityCurrentRootHeadObservation/v1`. The payload
schema is `serverware.policyAuthorityCurrentRootHeadObservation/v1`. Its
eighteen fields bind:

- Schema, source revision, enrollment digest, database ID, generation digest,
  enrolled state-producer measurement, and fixed operation.
- Exact query digest, challenge and context digest.
- Original issue/expiry interval, sequence, head digest, complete-vector digest
  and fence.
- Pending request/decision digests, both null or both present.

There is no request-status field, historical receipt, mutation result or
pending-acceptance assertion. Unknown fields, old lookup schemas, malformed or
noncanonical originals, mismatched scope, signatures and intervals fail closed.

## Actual owner and verification

`observe_head(query_bytes, *, transport_deadline_ns=None)` requires the actual
PID-bound decision owner and uses one work allowance. Under its existing lock,
it captures the real enrolled scope, signer and state, opens the original
processing window, and clips it to the inherited absolute transport deadline.
It checks readiness, clock continuity and unchanged owner identities/state
around signing. A query whose expected vector differs from the locked vector
fails before signing.

The method neither consults request history nor publishes a journal record.
It returns only the original signed observation. Existing reserve, complete,
lookup and unsigned inspection semantics are unchanged; transport admission and
peer policy remain separate from this original-byte protocol.

The private protocol API is:

- `_encode_query_on_work(*, enrollment_digest, context_digest,
  expected_vector_digest, challenge, work)` and
  `_decode_query_on_work(raw, *, work)`.
- `_query_digest_on_work(raw, work)` for the canonical original's identity.
- `_verify_on_work(*, observation_bytes, query_bytes, enrollment_bytes,
  root_public_key, now_epoch_ns, work)`, returning an owned ordinary payload
  dictionary only.
- `_sign_on_work(*, payload, enrollment_bytes, root_public_key,
  state_private_key, now_epoch_ns, work)`, used with the real owner's derived
  state, not a posted successful carrier.

Verification genuinely authenticates the root-signed enrollment and enrolled
state key, original response signature/canonical bytes, database/generation and
measurement scope, enrolled capacity and control interval, then exact original
query enrollment, challenge, context and expected vector. Genesis additionally
joins the actual enrolled initial vector and empty pending/head/fence shape.
All work is charged to the supplied allowance; these protocol helpers do not
sample clocks, open windows, generate randomness or perform I/O.

## Boundary that remains

A valid observation proves what the admitted local owner signed in response to
that fresh query. The caller must reject nonempty pending state, preserve its
original work/window/deadline, and bind the genuine originals into planning.
The ordinary returned dictionary is not independently reusable authority.

This does not prove an off-host anti-rollback checkpoint, prevent the head from
changing after observation, or supply action-time one-use consumption. It does
not authorize execution, token delivery, session activation or retry after an
uncertain outcome. Independently admitted cold ownership, protected execution
and production verification retain their separate requirements; see the
[activation planner bootstrap](oidc-session-activation-planner-bootstrap.md).
