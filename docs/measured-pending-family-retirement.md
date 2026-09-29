# Measured staged-pending family retirement

This is the authority/control-plane path for a **known-subject, already staged**
measured OAuth pending credential. It is separate from refresh-issued work,
refresh-superseded work, ordinary exchange cleanup, and pre-subject captured
issuance. It does not close those other purposes, general reconnect, archival,
cross-deployment coordination or production/runtime acceptance.

The [native cold configuration and private helper](native-oauth-pending-retirement.md)
are separately source-selected and joined to these actual authority callers.
The authority schema is
`schemas/oauth-measured-pending-retirement-authority.v1.schema.json`; native
configuration is not inferred from an HTTP body or an observed receipt.

## Actual authority and originals

The signed authority-service configuration independently selects
`oauthMeasuredPendingRetirementPolicy`. Its grant root is distinct from the
configuration, role and other purpose roots. The policy admits the exact native
boot/key, full measured scope, enrollment/application material, provider TLS
root, KEK, target `pendingIds`, and separately enumerated recovery grants.
Verifier and planner independently check the original native signature/Nitro
document and the fresh external-family-retirement grant.

The grant uses `pendingId`; arguments use `pending_id`. Neither is a refresh work
ID. There is no invented pending currentness root or credential version zero.
The native statement has 18 fields, including `pendingId` and
`authorizationSha256`, but no credential ID/version masquerading as this target.

The actual kernel calls `read_staged_pending` on authenticated exchange and
measured-custody rows. It binds immutable stage arguments, initial pending row,
current cancelled/expired/rejected prestate, historical enrollment, normalized
staged envelope and normalized token hash. The minimal issued-token capture is
not the normalized staged token. A constructible binder result or matching hash
alone supplies no authority. Historical request digests are not recomputed using
the current operation manifest.

`tokenEnvelopeSha256` and `tokenSecretSha256` name the normalized staged values.
The inspection response's `enrollmentOriginal` is raw canonical ASCII; the
request's `enrollment_original` is base64url. Inspection returns encrypted/public
originals only and does not authorize decrypting or contacting a provider.

## Real claim and contact ordering

The fixed endpoint is `POST /api/data-plane/oauth-pending-retirement`. The
transport token is an ingress check, not retirement authority. Its retained
`Opening` pins the actual request, current cold custody owner, signed
configuration, creating PID/thread, and original at-most-30-second phase deadline.
No wait loop or later response grants a new deadline.

1. `inspect` authenticates all originals and both complete local inventories.
   Every matching local credential must occur in the grant's sorted affected
   list; currently unsupported/unclassified lineage state refuses. The actual
   control-plane coordinator drains each active current credential through its
   genuine current root and every registered holder. A missing holder or timeout
   is not proof. The pending object itself has no fabricated holder root.
2. `claim` atomically consumes the exact admitted barrier vector, changes each
   affected credential to `revocation_pending`, fences the target pending row,
   inserts the permanent pending-family marker, and records the exact grant,
   originals, nonce commitment and current request digest. Competing activation,
   refresh, cleanup or pending changes invalidate this protected transaction.
3. Only the independently admitted helper may decrypt after that authenticated
   claim. A separate `contact` transaction irreversibly reserves one selected
   token contact before a fixed provider request. No acknowledgement loss permits
   another socket/POST. A later token can be selected only after the earlier
   selected token has a definite accepted/rejected observation, never unknown.
4. `finish` retains exact encrypted transport capture and classifies its actual
   HTTP status as accepted/rejected/unknown. These are transport observations,
   not proof that every provider token has become invalid. The credentials and
   family stay fenced regardless of outcome; no automatic reactivation occurs.
5. `recover` authenticates durable originals under a separate current recovery
   assignment. It returns `no-local-claim`, `outcome-unknown`, `unknown`,
   `observed-accepted`, or `observed-rejected`. Missing/malformed associations
   refuse. Recovery cannot reserve contact, repeat execution, reset history or
   convert an expired grant into effect permission.

The HTTP response is exactly `apiVersion`, `requestOriginal`, `responseOriginal`,
`currentnessBarriers`. The last field is an array only for successful inspection
(including genuinely empty coverage), and null for every other phase. Each
barrier is exactly `{credentialId, credentialVersion, barrierSha256}` in grant
order. This envelope is data, not a permission carrier.

The journal's `original_affected_json` is a literal canonical list of
`{credentialOriginal,generationOriginal}` pairs in that same order;
`currentness_barriers_json` is a literal canonical barrier list;
`original_pending_json` is the exact pre-claim current pending row. Neither
stdout nor an HTTP response is the durable source of those facts.

## Bounded independent family inventories

The old refresh marker `oauth_family_retirements` retains its exact semantics.
The new `oauth_pending_family_retirements` never invents an active credential or
refresh history. Both are checked by actual activation, staging and refresh
consumers. The pending marker permanently blocks activation of other local
pending members of that family as well as new staging/refresh; no token rewrite
can manufacture provider validity or reopen it.

The source-fixed admission group accepts only the enumerated OAuth operations,
these two tables, exact complete-population query IDs, no predicates, ascending
`id`, limit 33, work 33 and the bounded-limit-plus-one primitive. Both group
members are mandatory and run before dependent source proofs. Each actual SQL
read remains separately metered. Sentinel 33 or combined observations above 32
refuse before proof construction; every table still reconstructs its own
authenticated complete root. There is no union-as-one-root or generic budget
subtraction.

The declared combined allowance is 34: 32 actual rows plus one sentinel for each
independent read. An old-only 32-row population remains readable, but a new retirement
cannot be inserted at full capacity. No truncation, deletion, pruning or archival
is authorized. The existing global 256-proof limit is unchanged.

The new pending kernel's worst-case declaration is:

| Source reads | Declared rows |
| --- | ---: |
| Two independently complete family populations | 34 |
| Complete credentials and pending populations | 130 |
| At most 24 actual generation/root/barrier triplets | 72 |
| Exact exchange/custody/pending/journal/retirement custody/two markers | 7 |
| At most two token attempts | 2 |
| Exact audit row | 1 |
| Total before the existing separately named audit-capacity read | 246 |

The affected-lineage limit of 24 is a capacity restriction, not partial family
coverage. The actual SQL acquisition refuses a larger/mismatching affected set
before dependent proofs, and the kernel repeats full coverage checks after
independent root verification. Credentials and pending tables each retain a 64-row cap.
Setup rows are not asserted absent; the actual staging/activation consumers
retain their separate setup inventory and now check both family fences.

Encoded originals are bounded before parsing: grant 64 KiB, arguments 1 MiB,
encrypted transport 384 KiB, journal 2 MiB, retirement custody 4 MiB. Newly
serialized writer originals are also checked against their corresponding bounds.
The result payload refuses above 3 MiB to preserve the existing authenticated
6 MiB and outer HTTP 8 MiB limits. Nothing is silently truncated.

## Provider and completion boundary

The grant explicitly covers an externally owned provider family, independently
of the complete local inventory. RFC 7009 permits revocation to affect related
tokens/grants; different token bytes do not prove isolation. Google's documented
revocation affects project clients. This is deliberate operator-authorized
family retirement, not automatic isolated superseded-token cleanup.
See [RFC 7009 section 2.1](https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1)
and [Google token revocation](https://developers.google.com/identity/protocols/oauth2/web-server#tokenrevoke).

Local complete roots are not proof about other deployments or external clients.
Fresh authenticated reconnect/successor work, pre-subject captured retirement,
capacity migration/archival and runtime evidence remain separate required work.
Source assertions for missing/forged group members, sentinel/combined overflow,
read ordering and an old-only 32-row population are authored in
`scripts/authority/check_oauth_family_query_group.py`; they were not executed in
this source-only slice.
