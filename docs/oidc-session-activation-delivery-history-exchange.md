# Historical consume caller/grant exchange

`authority_oidc_session_activation_delivery_history_exchange.py` authenticates
original consume caller/root/grant controls before one genuine historical
consume proof replay. It accepts original bytes, independent request/scope,
enrollments, keys and before vector—not a successful producer result or a stored
pin adopted as independent authority.

The original API `_verify_on_work` carries raw2 plan/ciphertext, expectations,
before vector, caller authorization, grant, caller/grant/current-root enrollment
originals, root/consume-planner/operation public keys and configuration digest.
Private replay also requires independently held activation expectations/scope
and activation-planner public key, the actual completion-purpose activation
history owner, and the distinct consume execution-bundle key. All use the
supplied `live_window`, positive `transport_deadline_ns` and cumulative `work`.

The closed caller and grant signatures, real root enrollments, known consume
plan signature, typed request, exact raw2 identity, journal and before-vector
commitments are checked before private opening. The caller must retain its
original post-plan containment; grant issue equals original plan issue and its
expiry cannot outlive original caller/plan authority. Each signed interval is
checked against its enrolled maximum age, with future issue rejected against
the actual current processing clock and original enrolled skew.

The dedicated historical replay then genuinely opens/replays original private
proofs and completed-activation provenance once. Its actual request, raw2,
vectors, result, plan/record identities and original interval must match every
signed grant claim. No live verifier is called with an old timestamp, and the
current processing window is not clipped to an expired plan/caller/grant deadline.
The actual completion-purpose owner's current guard remains in the replay's
continuation; old expiry does not authorize renewed execution.

`_HistoricalExchange` returns only same-call authorization/grant digests,
database/generation, the genuine historical replay facts and `live()`, which
returns a real current epoch. This output is not accepted as replacement
authority by another admission API. A completion consumer still must genuinely
join signed reserve/ACK, independent pending pins, actual protected packet and
commit originals; decoding the [recovery packet](oidc-session-activation-delivery-recovery-packet.md)
does not do those checks.

Live APIs and generic replay remain unchanged. There is no SQL retry, new grant,
signing, state publication, plaintext release or public recovery here. This is
same-source-cohort, source-only implementation, not cross-version authority or
runtime/production verification.
