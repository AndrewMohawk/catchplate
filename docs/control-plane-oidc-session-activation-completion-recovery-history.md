# Pre-intent completion-recovery target

`control_plane_oidc_session_activation_completion_recovery_history.py` is a
read-only historical inspector. It does not weaken or substitute for the
existing post-intent recovery target. Its result is ordinary same-call target
data, never a reusable permission or a completed activation claim.

The actual retained preparation is raw5: caller authorization, signed planner
envelope, encrypted execution originals, canonical expectations, and complete
before-vector. The selected dispatch claim and prepared-record metadata are
locators only. Both real historical caller and planner signatures must bind
the exact typed request and original inventory.

Before those candidate expectations are admitted, bounded originals select a
unique independently root-admitted historical scope. Genuine caller and planner
signatures authenticate that selection; its original planner bootstrap and
caller/current-root/grant enrollments are then re-admitted. Configuration,
generation, runtime cohort, dedicated keys, state enrollment and before-vector
must join that selected authority. Current originals are used only when history
is disabled, never as fallback for an unknown archived scope. Static
RP/origin/authentication/trust policies and age/skew limits come from that root
original, not the candidate record. Dynamic request fields are trusted only
after their genuine signed request commitment is verified. The old original
deadline and plan/caller intervals remain historical evidence, never new clocks.

Genuine finalization ownership and its acknowledged completion are replayed
first. The authenticated activation request must name that same user, session
and credential, a distinct activation challenge and the independently pinned
delivery TTL. Hashing the actual ephemeral old 64-byte token must reproduce
the signed old-token commitment. No plaintext token is returned or journaled.

The distinct immutable result carries the genuine subject, authorization and
old/new-token digests, credential-record and challenge IDs, narrowed processing
window/deadline, retained guard, byte-accounting scalars and identity-pinned
`authority` reference. That actual selected scope carries independent archived
completion pins for the fresh actor; it is not external permission input.
There is no intent,
delivery ID, delivery timestamp, SQL-success claim or constructed delivery
scope. Fresh actor admission and independently configured completion recovery
remain separate consumers; an incoming result object cannot replace originals.

Capacity is reserved before either historical phase reads bodies. The existing
combined finalization reader retains its own replay headroom; temporary raw
finalization inventory is discarded before selecting the exact activation pair.
The new selector preflights three encoded footprints plus metadata; its 3/8
allowance leaves five more footprints for subsequent captures and verification.
The inspector also reserves the parent, actual planner/enrollment originals,
fixed metadata and caller-supplied already-held representations. The returned
`original_reservation_bytes` includes that parent and additional reservation:
later phases must not add them twice. These are conservative byte representations,
not a Python heap, RSS or runtime guarantee.

One original work/window spans every phase. Child historical guards use only
base-floor continuation; the final aggregate retains them without a child/parent
cycle. The original external current guard must itself remain upstream: it must
not reselect records or re-enter this inspector. No SQL, private AES opening,
socket contact, journal append, signing, cookie or automatic retry occurs here.
This source-only path is unbuilt and unexecuted; later old-authority consumers
and explicit source-version adapters keep the broader H05 milestone open.
