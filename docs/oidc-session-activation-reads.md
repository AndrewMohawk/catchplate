# OIDC activation: original complete-read admission

This source-only component declares and genuinely verifies the original read
evidence for `oidc.session.activate`. It is not an enabled planner factory,
installed database/index population, public activation endpoint or production
acceptance. It creates no new work allowance or clock and accepts no prior
successful verification object as authority.

The implementation is
[authority_oidc_session_activation_reads.py](../serverware/authority_oidc_session_activation_reads.py),
using the existing primary-radix and counted-index proof machinery.

## Fixed read inventory

The source declaration has sixteen business queries plus the real framework
audit-capacity query. Exactly ten primary selections are required:

- The pending session, target credential and assertion challenge, each by its
  actual primary ID.
- Absence of the new delivery ID and audit ID, derived from the original request
  digest with the fixed `activation-delivery` and `activation-audit` purposes.
- The fixed trust high-water and its mandatory matching published row. The
  publication query resolves fields from the proved high-water; a zero-row
  result is rejected, not promoted to a complete absence claim.
- The user's exact RBAC binding and RBAC authority row `authority_id = 1`.
- The initialized global audit-capacity row selected by the actual framework.

Seven complete ranges must genuinely prove empty:

| Role | Complete equality partition |
| --- | --- |
| `session_new_token` | Session `token_digest = new_token_digest` |
| `delivery_session` | Delivery `session_id` |
| `delivery_old_token` | Delivery `old_token_digest` |
| `delivery_new_token` | Delivery `new_token_digest` |
| `delivery_assertion` | Delivery `assertion_digest` |
| `delivery_challenge` | Delivery `challenge_id` |
| `pending_trust_publications` | Global pending trust publications |

The six new fixed profiles in
[authority_index_projection.py](../serverware/authority_index_projection.py)
include every matching row, including expired, revoked or consumed rows. They
do not weaken the actual delivery table's five unique constraints by checking
only live rows. Existing profile definitions and the older revoke,
registration-finalize and trust-stage query families retain their behavior.
The global source/projection manifest changes and requires its own independent
admission; old indexes are not silently migrated or declared populated.

## Original-input APIs

`_queries(*, arguments, cutoff_us, request_digest, work=None)` returns only the
fixed declarations. Arguments are exactly `session_id`, `user_id`,
`credential_id`, `credential_record_id`, `challenge_id`, `old_token_digest`,
`new_token_digest`, `assertion_digest`, `delivery_ttl_seconds`, `businessIntent`.
TTL is an exact integer from 5 through 60 seconds. These inputs describe intent;
their type checks do not authenticate an assertion, token or semantic purpose.

`_admit_on_work(*, arguments, request_digest, database_now, selected_rows,
query_reads, business_before_roots, authorization_before_roots, before_proofs,
read_heads, query_frontiers, work)` holds the exact bounded raw graphs and query
records before declaration hashing or verification. It uses the supplied
cumulative work and exact UTC processing time throughout.

The helper invokes the actual
`authority_complete_query_batch._verify_complete_query_batch`: primary
membership/nonmembership, complete range reconstruction and the exact
index-leaf/primary-row joins are performed, not inferred from an empty SQL
observation. It then validates the entire mixed query-read association and
requires the seven actual empty joins and exact ten-point closure. The private
result contains owned `arguments`, `selected_rows` and `query_reads`, only for
the same invocation's real transition. No API accepts that result in place of
original proofs.

## What remains separate

Independent before-root/currentness and index-population authority, authentic
assertion and token custody, caller permission, trust/RBAC semantic comparisons,
the actual audit-capacity transition, protected DML, session-cookie delivery
and post-finalization public/portal integration remain the composing owners'
obligations. This read helper does not grant any of them. The existing
[login UX correction](oidc-session-activation-ux.md) is a different boundary.

No tests, builds, parser checks, database operations or browser execution were
run for this source batch.
