# OIDC activation: actual read and indexed-write evidence acquisition

This source-only owner reads real PostgreSQL rows and original primary/range
proofs for `oidc.session.activate`. Its explicit full method also derives the
actual transition and captures indexed write evidence. It does not sign a plan,
execute SQL writes, activate a session, deliver a cookie or enable a public
activation route.
Implementation is
[authority_oidc_session_activation_planning.py](../serverware/authority_oidc_session_activation_planning.py).
No build, database, test or runtime verification was performed for this batch.
The real successor registry now declares this operation's fixed acquisition
factory and an explicit configured planning factory, constructing the actual
[`OidcSessionActivationPlanOwner`](../serverware/authority_oidc_session_activation_plan_owner.py).
The existing module-level closure guard remains; no stub or bypass was added.
This closes the seven-operation successor source inventory, not an import,
runtime, cold-admission or provisioning verification claim.

## Fixed owner and originals

`OidcSessionActivationReadPlanner` is constructed with `read_dsn`,
`connect_timeout_seconds`, `database_identity` and `maximum_clock_skew_ns`.
The immutable seven-part database identity is the existing reader's role,
client DN, client serial, issuer DN and three independently admitted runtime
identity digests. The owner is process-bound and refuses concurrent use.
Those constructor inputs still require independent admission; observed
database values cannot configure or authenticate their own reader.

`acquire(*, request, business_before_roots, authorization_before_roots,
expected_counted_heads, live_window, transport_deadline_ns, work)` requires the
actual original typed activation request, independent primary roots and the
exact sorted seven counted-head expectations. Each expected counted head has
`indexId`, `indexRevision`, `rootDigest` and `leafCount`. The supplied immutable
seven-part live window and inherited monotonic deadline are mandatory. The
owner opens neither a replacement window nor a replacement work allowance.

The actual request commitment, operation ID and source operation/handler are
recomputed. All mutable request/root expectations are captured before clock
or driver callbacks. The original host clock policy must match the owner's
configured skew, and sticky epoch/monotonic checks cannot renew the deadline.
Connect timeout is clipped to remaining lifetime; less than libpq's two-second
minimum fails before connection. There is no automatic retry.

## One read-only snapshot

The existing protected read scope opens PostgreSQL using a fixed search path,
checks the actual TLS reader identity and lack of mutation privileges, and
enters `SERIALIZABLE READ ONLY DEFERRABLE`. Actual source dependency manifests
are admitted before the fixed body; missing provisioning fails closed.

The owner then:

1. Reads observed primary roots and compares both root classes to the held
   independent expectations. Database observations do not become current-root
   authority merely because they were read in a transaction.
2. Reads database time and compares it to a fresh sample within the original
   window and configured skew.
3. Uses the exact [activation read declaration](oidc-session-activation-reads.md):
   sixteen business queries plus the real audit-capacity query. The existing
   staged reader proves dependent source rows before using their fields.
4. Acquires counted heads, bounded range frontiers and primary proofs using
   the actual shared acquisition ledger. The complete collector genuinely
   reconstructs membership/nonmembership and range/row joins, then validates
   the mixed `QueryRead` associations. Observed counted heads must equal the
   independently held seven-head expectation.
5. Closes the read trace and exits the actual cursor, transaction and connection
   before returning. Cleanup, work, owner or final lifetime failure returns no
   result.

The private `_AcquiredActivationReads` holds ordinary owned `request`,
`database_now`, `selected_rows`, `query_reads`, `business_before_roots`,
`authorization_before_roots`, `before_proofs`, `read_heads`, `query_frontiers`
and `trace`. It contains no cursor, connection or executable authority.
The composing transition must consume the original proofs and perform its
actual empty-range, assertion, token, trust/RBAC, row-state and capacity replay;
constructing this result cannot substitute for that admission.

## Full transition in the same snapshot

`acquire_transition` preserves the read method's request/root/window/work
arguments but requires the **thirteen-head** independent expectation. Additional
original inputs are `assertion_bytes`, `old_token_bytes`, `new_token_bytes`,
`delivery_custody_key`; independent scope is `expected_user_id`,
`expected_session_id`, `expected_credential_id`, `expected_credential_record_id`,
`expected_challenge_id`, `rp_id`, `origin`, `authn_policy` and `trust_policy`.
It accepts no caller mutation, envelope, proof-result object or callback. The
caller must own the token originals and independently admitted custody key.

After genuine read proof acquisition, this method uses the actual database
time, proved session expiry and original request to derive the fixed delivery
scope. It genuinely seals and reopens the new token, then calls the full
original assertion/read/trust/RBAC transition and real audit-capacity finalizer.
That result contains exactly five business mutations plus one capacity CAS.

The actual indexed mutation reader projects those six mutations' complete
OLD/NEW images and acquires/reconstructs the real twelve write frontiers in
the same read-only snapshot, on the same physical acquisition ledger and work.
The thirteen-head union is two session, five delivery, three credential, two
challenge and one read-only pending-publication profile. The publication head
is not a write head. All thirteen were compared to the independent expectation;
none is fabricated by merging observations from another transaction. The older
operations retain their eleven-head ceiling; only this exact activation union
admits thirteen.

The returned `_AcquiredActivationTransition` extends the raw read fields with
`delivery_envelope_bytes`, the actual same-call `transition`, thirteen
`counted_before_heads` and twelve raw `write_inputs`. `read_heads` remains the
seven read-only heads. No token plaintext or custody key is returned. Offline
signed planning still genuinely replays the original transition and write
proofs; this ordinary result is not accepted instead of them. The original
transition's live checker and authenticated expiry are enforced after write
acquisition and again after scope cleanup, without retiming the envelope,
assertion, challenge or session.

## Deliberately separate boundaries

The shared acquisition/trace gates add only this fixed operation's seven read
roles and complete thirteen-head read/write inventory. Existing `acquire`
remains a seven-head read method; it cannot silently produce write evidence.

The actual configured planning owner now joins acquisition with
[indexed signed-plan replay](oidc-session-activation-plan.md), server-owned
token generation and [encrypted private original retention](oidc-session-activation-journal.md).
Its `prepare` returns token-free originals and local locators;
`verify_retained` replays a known exact plan with independently supplied roots
and thirteen-head expectations inside the original live interval. Neither is
SQL execution or expired-history recovery.

The [cold service](oidc-session-activation-planner-delivery.md) now supplies
root-original configuration/key admission and a complete-vector launch snapshot.
Fresh latest-root/currentness and index-population admission, immutable
source/database provisioning, reservation/protected execution and the final
public/portal activation sequence remain separate work. The owner does not infer
them from database success. Driver allocation, ordinary
primary-proof SQL and metadata admission keep their existing separate bounds;
this is not whole-process work accounting or a preemptive watchdog. A hostile
host/driver is not excluded by local handle/status checks or sampled clocks.
