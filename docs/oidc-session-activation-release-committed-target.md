# Committed-consumption release target comparison

`authority_oidc_session_activation_release_committed_target.py` is a bounded data
comparison helper, not authentication, a commit reader or a release capability.
Its `_match_on_work(packet_payload=..., expectations=..., expected_release=...,
work=...)` returns only an owned six-field release binding. No entrypoint accepts
a successful proof object, and no token, selected row or ciphertext is returned.

The dedicated [committed-original verifier](oidc-session-activation-release-committed.md)
must first authenticate the actual packet and historical replay, read the real
immutable commit marker and full vector, and join the original completion and
state ACK. This helper then compares the consume typed request, selected original
delivery/session/credential targets, all eleven delivery-scope fields, retained
ciphertext identity, exact token-free result and the three source mutations:
delivery consumption CAS, deterministic audit insertion and real capacity CAS.
The delivery update must preserve the ciphertext and every other original column.
Consumption time is checked algebraically against the original delivery interval;
the helper samples no clock and supplies no currentness or lifetime renewal.

Full activation request identity is **not** inferred from the truncated delivery
UUID. Deriving the expected operation/delivery IDs is only a consistency check.
The original verifier separately compares the four facts retained by the same
genuine historical replay: full activation request digest, delivery ID, complete
delivery-scope digest and encrypted-envelope digest. `_scope_digest_on_work`
uses the existing activation completion provenance scope domain and canonical
registration encoding, so its digest covers exactly the original eleven fields.
No second historical replay or decryption is performed by this helper.

The five consume bindings retain their distinct obligations: this comparison can
recompute effects and compare marker data; packet and completion request identity,
actual pending decision and authenticated after-vector membership belong to the
original verifier. All input graphs used here are detached before commitment
hashing, and fixed row/effect inventories and existing source work bounds apply.

This is source-only, unbuilt and unexecuted. Completion-purpose historical custody
at UID 65497 is not transferred to the delivery-only release role at UID 65502.
Neither this helper nor its ordinary result implements the independently
authenticated completion-to-release bridge, durable release outcome, token
opening, SQL execution, recovery or public caller permission.
