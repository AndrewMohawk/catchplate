# Successor execution grant production

Source `.143` adds genuine original-plan grant production and dedicated
root-enrolled authorizer enrollment production. These are source components,
unbuilt and unexecuted: they do not provision a signing service, admit a public
caller or establish production readiness.

## Root-enrolled dedicated authorizer

[`authority_successor_execution_grant_enrollment._produce_on_work`](../serverware/authority_successor_execution_grant_enrollment.py)
takes `current_root_enrollment_bytes`, the independently held root private/public
keys, actual `authorizer_public_key`, `authorizer_measurement_digest`,
`maximum_grant_age_ns`, `maximum_clock_skew_ns` and existing `work`. It returns
original root-signed enrollment bytes. It does not take independently selectable
database, generation or operation-list overrides.

Genuine current-root enrollment admission supplies the database, generation and
original enrollment identity. The producer fixes the exact six successor
operations, exports and reparses canonical authorizer PEM/SPKI, and checks the
actual key is distinct from root, computation, completion and state keys before
root signing. The root must independently approve that authorizer measurement
and age/skew policy; hashing or signing them does not establish provenance.
The helper generates no key, reads no clock and issues no execution grant.

## Original plans, independently authorized scope

[`authority_successor_execution_grant_production._produce_on_work`](../serverware/authority_successor_execution_grant_production.py)
accepts the fixed operation, original plan frames, independently admitted
expectations and planner/operation public keys, complete before-vector bytes,
original grant and current-root enrollments, independent root public key,
dedicated authorizer private key, `expected_authorization_digest`, original
caller deadline and the caller's existing work. An optional
`transport_deadline_ns` can only shorten the live bound. It returns **original
signed grant bytes**, not a proof token or executable result.

The producer owns the original inputs and mutable expectations before native
callbacks, genuinely admits both enrollments and pairs the actual authorizer
key to its dedicated public pin. That key is separate from current-root
computation/completion/state keys and the actual planner/operation keys. There
is no generic role-key fallback.

The actual six-operation replay runs once over original raw2 revocation,
raw3 evidence or raw4 transition frames. The producer derives the typed
request and operation identities, retained-plan commitments, genuine result,
complete before/after vectors and original control/frame commitments from
that same call. It does not accept successful replay objects, caller-selected
grant claims or a result digest as a substitute for replay. The resulting
grant is signed, then genuinely control-verified and compared with the exact
derived canonical claims; that last signature/scope check does not repeat
the heavy plan replay.

`expected_authorization_digest` must come from separately authenticated
caller/request authority. Neither a plan signature, its contents, the supplied
digest's shape nor this producer establishes that authority. Original
enrollment, key, history and complete-root provenance remain prerequisites.

## Original lifetimes and pre-decision order

The signed grant preserves the original plan's issue time. Expiry can only
shorten to the original plan expiry, enrolled grant age, caller deadline and
the producer's original policy window. Actual epoch/monotonic checks cover
replay, signing and verification; the window is not reopened afterward.
Expired originals cannot acquire a fresh execution lifetime.

The grant is **pre-decision**. Its framed original-byte identity supplies the
later reserve's `capabilityDigest`; it cannot contain the resulting pending
receipt or computation-snapshot digest without a cycle. The existing
[execution preparation and admission](authority-successor-execution.md)
independently join those later originals and perform their own same-call plan
replay. One replay in each separate operation is not a transferable successful
replay carrier.

## Authority that remains external

The signing helpers support only
`serverware.signedPolicyAuthoritySuccessorExecutionGrant/v1` and
`serverware.signedPolicyAuthoritySuccessorExecutionGrantEnrollment/v1`.
The original outputs remain bounded to 64 KiB and 16 KiB respectively; replay
originals retain the existing aggregate and cumulative-work limits.
A signature binds an enrolled assertion; it is not evidence that
the process authenticated a human, protected its private key or observed a
current database head.

There is no public caller-authentication route, cold authorizer owner,
production key/service provisioning or current-head lease in this slice.
No journal, reservation, custody packet, attempt marker or SQL action is
created by producing a grant. Existing pending-decision, protected custody,
identifier-only execution, independent checkpoint, one-attempt and
postcommit-completion requirements are unchanged. Public finalization and
production verification remain separate work.
