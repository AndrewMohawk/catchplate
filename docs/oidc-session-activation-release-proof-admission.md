# Independent original release-proof admission

`authority_oidc_session_activation_release_proof._verify_on_work` authenticates
the distinct signed release-evidence original and its root-enrolled producer.
It is source-only, unbuilt and unexecuted. It does not itself authenticate a
fresh release intent or old-token possession, read a commit, replay historical
originals, hold private custody keys or authorize plaintext release.

```text
_verify_on_work(*, proof_bytes, enrollment_bytes, root_public_key,
    forbidden_public_keys, expected_scope, expected_release, expected_evidence,
    expected_intent_interval, live_window, transport_deadline_ns, work)
    -> _AdmittedProof(payload, proof_digest, live)
```

The independent scope is exactly seven fields: configuration/database/generation
and runtime-closure identities, producer ID, producer identity and receiver
identity. The release binding is the existing six-field intent target, including
all eleven delivery-scope fields and all five committed-consumption identities.
Evidence is exactly `releaseCustodyDigest`, `releaseIntentDigest` and
`stateReceiptDigest`. Every signed field must match the independently held input;
the producer measurement must match both the actual enrolled key and producer
identity. Actual root enrollment rejects root/forbidden-role key reuse. The
activation operation and deterministic delivery identities are checked through
the existing source derivations, not inferred from a truncated ID.

Original bytes, native key references, the exact intent interval and all bounded
mutable graphs are held before key/hash callbacks. Proof and enrollment originals
retain their fixed aggregate ceiling; capture, signature verification, digest and
comparison share the supplied work. The [wire contract](oidc-session-activation-release-proof.md)
and [producer enrollment](oidc-session-activation-release-proof-enrollment.md)
retain distinct purposes and closed schemas; no successful result object is an
accepted input.

`expected_intent_interval` is the original `(issued, expires)` tuple from genuine
same-call fresh intent admission by the surrounding custody composition. It is
not a caller-selected clock sample or evidence of intent on its own. Proof issue
must fit the original intent/delivery ordering within the stricter admitted
clock skew, and proof expiry cannot exceed either expiry. Actual current checks
also enforce the root-enrolled maximum age, the unchanged opening samples and
inherited monotonic deadline. Bounds can only narrow; no clock, work allowance or
historical execution lifetime is renewed. The returned epoch guard retains
private lifetime scalars and sticky clock history independent of mutable output.

The release custodian must join this verifier to genuine intent signature and
old-token possession admission under its own root-pinned target and current guard.
Completion-purpose history remains at UID 65497; the UID 65502 receiver needs only
public proof-verification material plus its separately held delivery key. The
ordinary result is authenticated evidence, not a plaintext capability. Durable
exact outcome, guarded opening, recovery and cold/public handoff remain separate.
