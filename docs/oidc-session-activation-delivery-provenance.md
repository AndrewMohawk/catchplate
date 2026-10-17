# Completed activation provenance for delivery consumption

This private source prerequisite connects genuine completed activation to one
distinct `oidc.session.activation-delivery.consume` typed request. It does not
prove current rows, committed consumption, fresh public consent or token release.
Source is unbuilt and unexecuted.

[`authority_oidc_session_activation_delivery_provenance`](../catchplate/authority_oidc_session_activation_delivery_provenance.py)
accepts the exact original signed activation plan/encrypted bundle, caller and
grant with their enrollments, signed reserve/snapshot/reserve ACK, and returned
signed complete/state ACK. Independent expectations, current-root enrollment,
keys, configuration, authorization/database/generation/pending/fence pins and
the actual historical custody owner remain separate inputs. A raw pending ACK
or posted successful result cannot replace completed-activation verification.

`_capture_on_work` owns the original kwargs and bounded request/current-delivery
graphs; its output is ordinary data, not admission. Composing callers must own
their other mutable proof/policy graphs before capture hashes typed expectations.
`_verify_on_work` uses the same work, original current processing window and
inherited deadline throughout. Original historical expiry is checked by the
genuine historical algorithm, never turned into a current clock or renewed
execution permission. Cold historical-owner processing bounds remain enforced.

The existing completion receiver's separately named private delivery suffix
replays the original activation **once**, then performs the same real complete/
state signatures, marker and signed-observation joins. Existing completion APIs
and four-field response results are unchanged. The new suffix derives only
diagnostic identities from that replay's single actual delivery `INSERT`, not
from a supplied row or alleged success. No original row, token or executable
effects escape the suffix.

The original activation request must match the consume's user, session,
credential, credential record, challenge, old/new token digests and assertion
digest. The delivery ID is rederived using the actual activation request digest
and fixed `activation-delivery` purpose. Domain-separated row/scope digests and
the exact ciphertext digest bind every column of the proposed current delivery
to the authentic original insertion, including creation/expiry and its unchanged
encrypted envelope. Both require `consumed_at` to remain null. The separate
[consumption transition](oidc-session-activation-delivery-consumption.md) must
still prove current membership, lifetime, active session/current credential,
trust/RBAC and actual old-token possession.

The private `_VerifiedProvenance` result contains activation/completion/delivery
identity scalars, a provenance digest and this invocation's current guard. No API
accepts that result as proof. The composing signed-plan path must invoke the
actual original verifier itself. No generic completion rejection is removed;
strict current-source historical admission is not cross-source history recovery.
Protected execution/commit retention, authorized one-use plaintext delivery and
public/portal permission remain separate work. No SQL, network, signature
production, retry, runtime validation or provisioning occurs here.
