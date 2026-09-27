# Protected activation-delivery consumption contract

This `.157` source introduces the distinct operation
`oidc.session.activation-delivery.consume`. It is **source-only, unbuilt and
unexecuted**. Query declarations and original proof admission do not enable SQL,
release a token, establish public permission or register a working planning
factory. The legacy plaintext `recover_oidc_session_activation_delivery` path
is unchanged and is not this operation's adapter.

## Closed operation and effects

The [operation contract](../serverware/authority_contract.py) names the dedicated
`consume_oidc_session_activation_delivery` handler and typed-successor planning.
There is no generic verified-assertion receipt substitute: its policy is
`original-pending-token-possession`. The actual transition must independently
receive and hash the original old-token bytes, check its caller scope and prove
the current active session, credential, used challenge, trust and RBAC state.
The source declaration alone does not install or admit that handler.

The exact arguments are `delivery_id`, `session_id`, `user_id`, `credential_id`,
`credential_record_id`, `challenge_id`, `old_token_digest`, `new_token_digest`,
`assertion_digest` and `businessIntent`. The genuine business-intent synthesizer
retains `challenge_id`: it is the original delivery association, not a disposable
generic assertion-receipt selector. These are intent and digest commitments;
plaintext tokens, AES keys and purported success carriers are not arguments.

The only business writes are the delivery row's `UPDATE` and a deterministic
audit `INSERT`; actual shared audit-capacity finalization adds its aggregate
`UPDATE`. The transition must restrict the delivery change to `consumed_at`
under the proved original row and real database time. It does not modify the
session, credential, challenge, trust or RBAC rows. Business bounds are
**16 query rows, 2 mutations and 128 work units**; framework capacity makes the
exported bounds **17, 3 and 130**. Those bounds are not execution evidence.

## Exact current read closure

[`authority_oidc_session_activation_delivery_reads.py`](../serverware/authority_oidc_session_activation_delivery_reads.py)
declares nine business primary points: session, credential, challenge, delivery,
trust high-water and its dependent publication, subject RBAC binding, RBAC
authority state and absent deterministic audit ID. The capacity point makes
**10 exact selected envelopes**. The audit ID uses the actual operation/request
digest with purpose `activation-delivery-consume-audit`.

Seven complete equality ranges reuse existing authenticated index profiles:

| Role | Required complete population |
| --- | --- |
| `session_new_token` | Exactly the selected session at the new token digest |
| `delivery_session` | Exactly the selected delivery for the session |
| `delivery_old_token` | Exactly the selected delivery for the original token digest |
| `delivery_new_token` | Exactly the selected delivery for the new token digest |
| `delivery_assertion` | Exactly the selected delivery for the assertion digest |
| `delivery_challenge` | Exactly the selected delivery for the challenge ID |
| `pending_trust_publications` | Empty pending-publication partition |

Delivery indexes include expired and consumed rows; the session-token index
includes expired and revoked rows. No liveness filter can hide a duplicate.
The proof helper requires six singleton populations, unlike activation's empty
uniqueness checks. Each leaf joins the exact selected primary row and matching
`QueryRead` address through the real primary/range engines. The seventh range
must genuinely prove absence; observing zero rows is insufficient.

The full inventory is **17 QueryReads, 7 independent counted read heads and
7 original frontiers**. Existing primary-key and index declarations suffice;
no DDL, new index or outcome table is introduced. The shared batch verifier
derives its closed family from the source query declarations without a broader
operation allowlist.

## Private original-input APIs

```text
_queries(*, arguments, cutoff_us, request_digest, work=None)
_admit_on_work(*, arguments, request_digest, database_now, selected_rows,
    query_reads, business_before_roots, authorization_before_roots,
    before_proofs, read_heads, query_frontiers, work)
```

The admission owns raw graphs and records before declaration/proof callbacks,
then genuinely replays original membership/nonmembership and complete-range
proofs on the supplied cumulative work allowance. It returns private ordinary
`_AdmittedReads(arguments, selected_rows, query_reads)` solely for the same
invocation. No incoming result object is accepted instead of originals.

Roots, counted-head population authority, real database time, token possession
and current policy are independent composing-owner obligations. Read admission
does not validate business semantics or perform mutations. The protected write
adapter must rederive the actual effects and prove all affected counted indexes,
then real one-use/current-root/CAS execution must commit them atomically.

## Durable outcome and release boundary

There is no new consumption-outcome table. The intended durable evidence is the
original protected execution packet and its commit marker, retaining exact
token-free effects/result and the encrypted delivery. Recovery must genuinely
admit those originals against independently pinned caller and operation scope.
A `consumed_at` scalar, unsigned SQL result or source manifest is not proof of
commit or permission to release plaintext. Uncertainty must not trigger another
consumption or SQL retry.

Protected commit admission, independently keyed release custody, exact durable
response recovery and public/portal integration remain separate obligations.
Nothing here renews the original delivery/session lifetime or claims current
browser authentication, provisioning, off-host currentness or production
acceptance. No test, import, parser, build or runtime command was run.
