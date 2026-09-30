# Complete installed route classification

`serverware.policy/v2` is a new, explicit signed policy profile. Its route and
adapter semantics remain the existing policy semantics, including JIT, finite
numeric predicates, credential-free routes and generic adapters. The additional
`routeAuthority` object pins a complete deterministic mapping; it is not an
expansion-cell sample or a per-request plan hash. V1 policies retain their old
shape and ordinary behavior and do not acquire complete-classifier evidence.

## Producer and installed owner

`policy_route_authority.prepare_unsigned` accepts an explicitly unsigned v2
bundle and exact generic declarations. Each generic route must declare its
actual adapter operation name and one of read/search/write/publish/delete/
administrative. No method or name heuristic exists. Built-in classifications
come from the actual Gmail, X and npm operation catalog; declarations cannot
override them. `sign_policy_bundle` checks the mapping before using its existing
authorized signing key. No new signer, permission or callback is introduced.

Both Python `compile_policy_bundle` and native
`compile_signed_snapshot_with_expected_key` recompute the complete mapping.
The native factory runs after the original signature, policy capabilities and
schema admission, and checks each compiled route against its signed adapter
original. A retained `Snapshot` owns the map; the effect-free projection keeps
the same immutable map and includes its size in the existing memory budget.

The actual getter is
`PolicyPlanSnapshot::observed_authority_binding(&PolicyEvaluation, principal_id)`.
It requires the exact evaluated policy hash, real retained route/principal
membership, and operation emitted by that adapter evaluation. Early denials
without a matched route/operation and v1 snapshots refuse classification.
`ObservedAuthorityBinding` exposes typed getters for all five committed fields.
The detailed observation factory owns selection of the authenticated principal;
this helper does not turn an arbitrary principal string into authentication.

## Exact recipe and independent approval

For each route, sorted by route ID, the profile includes its ID hash, hash of
the **entire signed route original**, adapter type, and sorted complete operation
classification list. It also commits the complete signed principal definitions,
credential definitions and defaults, and expands exact principal membership
from the installed signed set (including wildcard routes). Thus credential reference, principal membership, JIT,
constraints, response rules and match semantics remain committed. The profile
hash is `compiledSemanticProfileSha256`. The full map, route-root and
operation-root use distinct versioned objects. No pin contains its own hash.
The complete policy signature includes the declarations and all resulting pins.

`analysis_roots(active, candidate)` produces distinct versioned active/candidate
pair roots for the existing independently signed compiler analysis. It grants
no signing or analysis authority. `retained_pair(state, record)` in
`authority_transition_policy_canary_route_authority` selects the protected
publication, rechecks its actual load/handoff/signature originals and current
compiler analysis, recomputes both policies and demands these exact roots.
Expansion cells must reference real candidate map entries and the same roots;
empty/no-expansion analyses receive the same complete-map check.

The actual compiler-analysis intake invokes this check for already-published
v2 generations. An earlier analysis is not proof of a later install. The native
detailed receiver must call `retained_pair` and `require_binding` when admitting
each real observation. That receiver/factory is a separate root-owned source
join; this batch does not claim it exists or claim readiness/activation.
Current full native classification requires both installed lanes to select v2;
no v1 migration, profile relabeling or first-expansion-cell fallback is implied.

## Finite-number canonical transcript

V2 signature/hash bytes and all mapping hash bytes are the ASCII bytes of
`serverware.policyTypedCanonical/v1`, NUL, and compact sorted-key JSON of a
fully tagged transcript. Object is `["object", [[key, child], ...]]` with keys
sorted by Unicode scalar order; array is `["array", [child, ...]]`. Scalars are
`["string", value]`, `["boolean", value]`, `["null"]`, `["integer", decimal]`
or `["binary64", bits]`. Integer range matches native signed-i64/unsigned-u64
JSON. Binary64 is finite IEEE-754 bits as exactly 16 lowercase hex characters,
big-endian; negative floating zero remains distinct. NaN and infinity refuse.
All strings use Python-compatible ASCII escaping, including DEL and surrogate
pairs. Every node is tagged, so an application object cannot imitate a numeric
tag. Standard Ed25519 primitives and the existing sole signature-field removal
are unchanged. All other policy fields are covered.

The existing serde_json version enables `float_roundtrip` for deterministic
decimal-to-binary64 parsing. This shared parser feature may correct previously
misrounded v1 edge-case floating values; it does not reinterpret old signatures
or provide a fallback between v1 and v2. No dependency version/lock update or
execution was performed.

## Bounds and evidence status

This explicit profile admits at most 128 routes, 128 total declared operations,
and 512 KiB each for route-original and map transcripts, under existing outer
policy/HTTP/proof/work bounds. The receiver charges canonical original size and
mapping work against the unchanged 8192-unit transaction ceiling. Large policies
may refuse even below one local limit; no transport/proof ceiling was raised.
Production-scale capacity and migration remain separate work.

This batch is source-only. No build, parser run, test, provider contact, native
execution or runtime acceptance was performed.
