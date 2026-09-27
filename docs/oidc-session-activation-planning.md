# OIDC activation: actual read acquisition

This source-only owner reads real PostgreSQL rows and original primary/range
proofs for `oidc.session.activate`. It does not sign a plan, execute SQL writes,
activate a session, deliver a cookie or enable a public planner factory.
Implementation is
[authority_oidc_session_activation_planning.py](../serverware/authority_oidc_session_activation_planning.py).
No build, database, test or runtime verification was performed for this batch.
The private call still imports the real planner, whose module-level registry
closure rejects the missing activation successor factory. The read source is
implemented but cannot run in the current tree until the genuine configured
owner is integrated. No registry check is bypassed and no stub is registered.

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

## Deliberately separate boundaries

The shared acquisition/trace gates add only this fixed operation and its seven
read roles. Older families retain their rules; activation write-head acquisition
is explicitly rejected. Future indexed write-frontier capture must use the
actual `authority_index_mutation_reader._acquire_indexed_primary_batch` with
the complete potential-write head union and real computed mutations, not merge
these seven read heads into a fabricated write proof.

Independent root/currentness and index-population admission, immutable source
and database provisioning, original assertion/encrypted-delivery custody,
composition with the real full kernel and [signed-plan mechanics](oidc-session-activation-plan.md), reservation/protected execution and
the final public/portal activation sequence remain separate work. The owner
does not infer any of them from database success. Driver allocation, ordinary
primary-proof SQL and metadata admission keep their existing separate bounds;
this is not whole-process work accounting or a preemptive watchdog. A hostile
host/driver is not excluded by local handle/status checks or sampled clocks.
