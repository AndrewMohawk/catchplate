# Request-scoped release-proof setup production

This is source-only setup derivation, not private replay, proof production,
resource provisioning, token release or runtime acceptance. The producer is
[oidc_session_activation_release_proof_input_production.py](../serverware/oidc_session_activation_release_proof_input_production.py).

## Original-only contract

`_produce_on_work` takes these mandatory keyword arguments:

- `request_originals`: exact raw3 `(completion_request_bytes, state_receipt_bytes,
  intent_bytes)`.
- `consume_packet_bytes`: a separately acquired private packet original. It is
  not part of the public request and is not learned from a returned locator.
- `issuer_policy_bytes`, `completion_bootstrap_bytes`, `proof_enrollment_bytes`
  and `intent_enrollment_bytes`: independently provisioned public originals.
- The actual `root_private_key` and independently held `root_public_key`, plus
  the existing `live_window`, `transport_deadline_ns` and `work`.

Optional `_continuity` exchanges only restrictive epoch/monotonic clock floors.
The sole output is raw1 `(proof_bootstrap_bytes,)`; that original already embeds
the newly signed release custody. No input accepts a verified material, caller
payload template, release target, private history owner or successful result.
No old token is accepted, copied into the output or retained.

## Independent authority and derivation

The genuine [issuer policy](oidc-session-activation-release-proof-input-issuer-policy.md)
verifier authenticates the exact independent completion bootstrap and both
enrollments, the proof scope, caller and fixed launch. Its actual completion
material supplies the configuration/generation/runtime identities, original
activation planner, delivery-key commitment, enrolled state key, typed consume
expectations, packet identity and pending sequence/head/fence.

The supplied packet is decoded only against those independent packet and
pending identities. Its retained enrollment/caller originals and marker fields
must match the genuine completion material. The original signed complete
control and state ACK are verified against the same pending ancestry. Their
exact marker and complete after-vector joins are checked, including the signed
writer-observation bytes. Historical completion evidence is not renewed into a
new execution or retry allowance.

The producer derives the activation and consume identities, deterministic
delivery ID, full delivery scope, encrypted-envelope commitment and five-field
consume binding from the admitted typed requests and independently identified
packet data. It authenticates the intent with the independently enrolled key
and compares every derived field, enrollment identity and caller scope. It
does not use the intent's target fields as independent authority, and it does
not claim old-token possession or private correctness of the packet.

Only then does it sign the existing
[release custody](oidc-session-activation-release-custody.md) and
[proof bootstrap](oidc-session-activation-release-proof-service-bootstrap.md) schemas.
The exact original intent digest is pinned in custody. The output interval is
the intersection of the signed policy, original intent and actual delivery
expiry, bounded by the source maximum; current processing can only narrow the
original work/window. Genuine output bootstrap admission repeats the nested
original checks before raw1 returns.

## Bounds and retained guards

The combined source inventory is 64 MiB. Input, decoded packet-control and
nested cold-original reservations precede decoding. Empty-base64 placeholders
and exact unpadded expansion lengths measure the complete signed custody and
proof envelopes before output wrapper allocation; the check also reserves
nested originals and readback copies. Actual output lengths must match those
reservations. This is tightening-only capacity, not a renewed work allowance.
Optional `maximum_original_bytes` on production and its private derivation
helper is an exact integer from 2 bytes to 64 MiB; `None` retains the original
64 MiB ceiling. An actual owner can subtract its measured cold/resource/wire
holdings and pass the remainder. Both the initial decoded-input reservation and
the complete wrapped-output/readback reservation must fit before allocation.

The proof, consume-completion and release-custody bootstrap entry points now
accept optional `_current=None`. Dynamic callers retain their actual external
guard alongside the existing guards; the original external guard is forwarded
to nested cold admission rather than a closure that calls a child's result.
The selected historical activation/consume-planner and planning-history joins
receive only restrictive clock floors, including their real opening samples;
they remain evidence-only and require the separate fresh outer purpose.
Existing `None` callers retain their original behavior. Guard calls stay outside
stable native callbacks, and no generic callback interception is introduced.

## Remaining acquisition and runtime boundary

The current public permission has SQL response originals and completion/intent
originals, but **does not hold the consume packet**. A real issuer-side fixed
reader must acquire that packet against the independently pinned completion
configuration before calling this producer. That service/acquisition connection
is still open; the producer neither reads the database nor invents or decrypts
a public packet.

The subsequent proof worker must still perform genuine private replay and
commit observation with its separately provisioned resources and current old
token before signing a release proof. Setup output or a staging ACK cannot
stand in for that work, readiness, SQL success, a delivered token or a current
session. No build, test, deployment or provisioning evidence is claimed here.
