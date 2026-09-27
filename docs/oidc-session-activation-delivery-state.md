# Current-state observations for consumption planning

`authority_oidc_session_activation_delivery_state.py` connects consume plans
to a genuine current-root head observation and exact complete-vector projection.
It is source-only: no runtime, provisioning or production acceptance is claimed.

The query context commits the exact typed consume request, real old-token
original, independent fourteen-field subject/policy/planner scope and complete
root-vector bytes. The caller supplies a fresh unpredictable challenge and
independently admitted enrollment/root. Receiving verification authenticates
the actual enrolled state signature, matches the original challenge/context/
vector, rejects pending state and preserves the observation expiry. The signed
plan separately joins the projected primary roots and seven counted heads to
its actual acquired proofs. Neither a supplied head label nor a naked digest
can replace these originals.

`authority_current_root_delivery_head.py` fixes the distinct
`oidc.session.activation-delivery.consume` operation and DeliveryHead schemas,
query identity and signature domain. It shares bounded canonical and enrolled
signature machinery with the activation protocol, not activation authority.
Existing default and historical activation APIs remain activation-only.

The actual locked `CurrentRootDecisionOwner.observe_delivery_head` signs its
own sequence, vector, fence and pending state. It never signs caller-selected
state or creates a journal decision. Transport uses distinct `SWDHQR01` and
`SWDHST01` frames, exact bounded originals, EOF, peer checks and one inherited
deadline. Explicit root-signed state bootstrap/launch **v7** admits UID/GID
**65501** solely for this consume-head purpose. Profiles v1–v6 do not gain the
peer, and it cannot use activation heads, historical lookup, reserve or complete.
No installed account, socket ACL, signed bootstrap or cold consume planner is
created by this source change.

An observation can become stale immediately afterward. It is not an execution
reservation, SQL commit, live off-host witness, rollback protection, caller
permission or token-release approval. Actual one-use current-root execution,
retained/cold planning ownership and committed-original plaintext release are
still separate open work.

In particular, the existing activation-history custody owner is fixed to its
completion process (UID 65503). Supplying its successful output is not a way to
move that authority to UID 65501. A cold consume planner still needs a genuinely
root-admitted historical-custody purpose/connection; neither this head peer nor
the stateless plan owner relabels or transports the existing process-bound owner.
