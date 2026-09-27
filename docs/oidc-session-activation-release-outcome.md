# Token-free release outcome record

`oidc_session_activation_release_outcome.py` is a pure bounded canonical codec,
not a proof verifier, release permission or storage owner. It is source-only,
unbuilt and unexecuted. An encoded or decoded record does not establish that an
intent, committed consumption, release proof or storage authorization was admitted.

```text
_encode_on_work(*, scope, release_binding, evidence_binding, caller_id, work)
    -> canonical bytes
_decode_on_work(original_bytes, work) -> owned record dictionary
_digest_on_work(original_bytes, work) -> exact-original identity digest
_slot_digest_on_work(*, database_id, generation_digest, delivery_id, work)
    -> stable slot digest
```

The closed record has exactly seven fields: `schema`, `sourceRevision`,
`slotDigest`, `scope`, `releaseBinding`, `evidenceBinding` and `callerId`.
Scope retains the [release-proof scope](oidc-session-activation-release-proof.md):
configuration, database, generation and runtime-closure digests/identity,
producer ID and producer/receiver identities. Release binding is the existing
six-field target with its complete eleven-field delivery scope and five consume
commitments. Evidence binding has exactly six digests:

- `releaseCustodyDigest`, `releaseIntentDigest`, `stateReceiptDigest`;
- `releaseProofDigest`, `proofEnrollmentDigest`, `intentEnrollmentDigest`.

Storage authorization is authenticated separately and is deliberately excluded
from the record identity. A checkpoint-one grant may pin the existing outcome;
including that grant's digest would be circular and would change the retained
outcome whenever fresh storage authority was supplied.

The slot is the fixed `serverware.oidcSessionActivationReleaseOutcomeSlotIdentity/v1`
framing of database ID, generation digest and delivery ID, in that order. It is
independent of caller, intent/proof identity, source revision and configuration:
changing those inputs cannot manufacture a second slot for the same delivery.
The record still binds the current source cohort and all listed commitments.
Its distinct record identity fingerprints the complete canonical original bytes.
Neither identity supplies authentication, freshness or a durable receipt.

All external mutable input graphs are jointly detached before encoding/hash
callbacks. Exact source shapes, digest grammar, deterministic activation operation
and delivery identities, and canonical original delivery-scope timestamps are
checked on the same supplied work. Original delivery lifetime is checked only
algebraically; no current clock is sampled or renewed. Canonical input/output is
bounded to 64 KiB, 512 JSON nodes and depth six, safely below the existing 1 MiB
journal record ceiling. Unknown fields, noncanonical encodings, other source
cohorts and inconsistent slots or targets fail closed.

Only commitments and token-free target metadata are retained: no original large
custody document, proof/enrollment bytes, old/new token plaintext, encrypted
token envelope or private key appears in this record. Exact original proofs are
still required by later admission and recovery; digest pins alone cannot replace
them. This codec performs no signature verification, file I/O, decryption, SQL,
durable write or plaintext egress, and it accepts no successful proof DTO.
