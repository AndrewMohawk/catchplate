# Committed-release original input ownership

`authority_oidc_session_activation_release_committed_inputs.py` is the bounded
input-ownership helper for private committed-consumption verification. It is
source-only, unbuilt and unexecuted. It neither decodes a packet nor verifies
signatures, performs historical replay, reads SQL, opens a token or admits a
release outcome.

`_capture_on_work` accepts the original packet, signed completion request and
state ACK; four independently supplied caller/caller-enrollment/grant-enrollment/
current-root-enrollment originals; independent consume expectations, release
target and five consumption identities; actual planner/operation/root public
keys; configuration, caller, database, generation and pending sequence/head/
fence pins; the actual dedicated completion custodian and commit reader; and
the existing work, live window and mandatory positive transport deadline.

Every original is exact immutable bytes under its actual source contract's
individual cap. The seven public originals together must fit 64 MiB before any
packet decoding. This helper does not decode any of them. The custodian's
separately held controls are not new public request inputs; genuine custody
admission bounds and reauthenticates them on the same cumulative work later.

Ownership has two stages. First, a fixed wrapper containing all three mutable
graphs is copied by the operation-neutral exact-JSON structural copier. Its
byte/node/depth limits are source fixed, and every charge uses the original
work object. It invokes no key, native owner, clock or typed-commitment hash.
Only after all graphs are detached does the helper use the actual consume
expectation capture, derive its typed request commitment, validate the release
scope grammar and snapshot the fixed reader by exact class call. Thus a
callback cannot change a still-external release graph while another graph is
being hashed. The structural phase creates no replacement work allowance.

The release target is the [fresh intent's exact six-field target](oidc-session-activation-release-intent-admission.md), including its closed
five-field `consumeBinding`. The helper joins that binding to the independently
supplied five identities, joins `consumeRequestDigest` to the genuinely derived
typed request digest, and joins the expectation's configuration digest to its
independent pin. These are expected-data consistency checks, not evidence that
the packet, effects, marker or completion actually satisfy them. Original
delivery-scope grammar does not assert present validity or release authority.

`_Inputs` retains the same named inputs except `work`, plus the actual immutable
eight-field `reader_configuration` snapshot. It is ordinary held data, never
accepted by a public verifier as proof. Keys must be actual Ed25519 public
keys; owner classes are exactly the UID 65497 completion custodian and fixed
`CurrentRootCommitReader`. The genuine verifier still must reauthenticate owner
purpose/process/root controls, keep snapshot continuity, verify the original
packet/commit/completion and compare the real release target.

The original seven-field live window is preserved; only the inherited
monotonic deadline is intersected with its existing ceiling. No clock is
sampled and no expired historical interval is renewed. This helper supplies no
current-session, one-use disclosure, private handoff or production-verification
claim.
