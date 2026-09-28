# Active-context protected recovery exchange

`control_plane_oidc_session_activation_recovery_exchange._exchange_on_active`
connects the actual private recovery acquisition context to one RECOVERY release
exchange. It accepts only that source-owned live context, not posted originals,
an admitted-result carrier, a target, a clock or a caller-provided scope.

Source only: this path has not been built, executed, provisioned or demonstrated
to recover a session. Public recovery HTTP and post-cleanup cookie completion
remain separate. A prior staging ACK is not worker readiness or store proof.

## Original-only authority

The acquisition context must have durably retained its genuinely admitted
client/server/outcome triple and normally completed exact worker staging. Its
`exchange_token()` method spends the one-use exchange latch before calling this
coordinator. The coordinator checks the exact active class, global owner, actor,
work/lifetime seals, retained selections, original identities and capacity seal.

It reconstructs the fixed prefix7 from the retained intent/proof/enrollment and
encrypted-envelope hints, plus the actor's ephemeral old-cookie possession.
Nothing is selected by a posted subject or a signed-but-unverified scope. Fresh
derivation genuinely reauthenticates the independently configured policy,
historical custody, intent/proof and old-token possession, reconstructs the
canonical outcome, and builds the actual RECOVERY raw8 request identity. The
reconstructed outcome must byte-equal the durably retained original; the policy
and delivery scope must still match this freshly authorized actor.

The client scope17 is independently derived from those originals, the real
request identity and exact server-original identity. Both client and nested
server originals are then genuinely re-admitted against that scope. Exact
checkpoint1 storage/recovery scopes, custody, release target, launch and policy
interval containment are checked. The endpoint comes from the independent
recovery policy, never the issuer-acquisition endpoint or static LIVE client.

## Claim, exchange, response

The existing `claim_oidc_session_activation_release` durably burns the actual
client authorization before the sole socket contact. It retains only four
digests and the RECOVERY profile, not request frames, old/new tokens, cookies or
assertions. An uncertain claim/contact/close/response is terminal; the old grant
is not resumed, cleared or retried.

The source-fixed RECOVERY transport sends the exact raw8 request under the same
work and deadline. It returns unverified raw2 only after normal socket close.
The genuine response verifier then reauthenticates all originals, exact request
echo and token commitment; an echo or staging ACK alone cannot admit a token.
Its exact token64 is returned only to the actual acquisition context.

The context stores that token privately and exposes `token_bytes` only while it
remains active. Its public method result is `None`. Failure poisons the context;
cleanup clears the token and retained response guard. This is not a standalone
success response, current-session claim or authority to set a cookie after exit.
No SQL, outcome append, outcome reconstruction-as-store-evidence or token
journaling is introduced.

## Unchanged allowance and guard direction

All steps use the original actor work/window and running clock floors. The
existing held-capacity reservation stays charged to the same 64 MiB aggregate.
Before derivation/socket contact, length-only reservations cover new hint and
outcome representations plus both the pre-contact client/server admission and
later full response admission, including their retained nested original graphs
and fixed reply buffers. This is conservative byte-representation accounting,
not a heap, RSS or runtime guarantee.

Read-only `_derive_on_work` now accepts an additive held-byte reservation and
reserves its canonical outcome/raw8 construction. The unused grant-generation
output maximum moved to `_produce_on_work`, which preserves the prior complete
signing/readback preflight before any genuine decode. Keeping that roughly
32 MiB signing-only reserve in read-only derivation would reject every active
context already reserving roughly 32 MiB of parent representation capacity; no
aggregate limit or source authority was widened to avoid that conflict.

The receiving guard remains a separate child of the acquisition context. Its
ancestor calls only `_parent_current`/`_parent_continuity`, which retain real
actor/grant guards but never call the receiving child. The coordinator's own
retained derivation/client guards likewise have base-only nested continuity.
The genuine response verifier supplies the full final guard through
`_retain_receiving_current`; it is never attached back to its own ancestor.
Entry requires the in-progress phase, while subsequent guard checks permit the
completed, still-active context. Closing that context invalidates the chain.
