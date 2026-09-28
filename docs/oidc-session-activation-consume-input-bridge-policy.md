# Historical activation to fresh consume input policy

The distinct signed consume-input issuer policy v2 is an original-only bridge,
not a result or execution permission. The actual current root authenticates its
signature before a receiver uses the historical root. Its producer admits both
original contexts and requires the actual current root signing pair. Existing
v1 policies retain the same single-cohort admission and 64 KiB envelope limit.

V2 preserves the v1 resource and purpose fields and adds exactly:

- `activationEvidence`: independently pinned old root public bytes/SPKI,
  configuration, generation, planner receipt, original snapshot interval and
  caller/grant/state enrollment digests;
- `currentActivationPlanner`: immutable wrapped current-root planner original,
  with byte count, raw digest and the existing planner identity digest;
- `compatibility`: the literal `same-generation-state-payload/v1`.

The separate activation planner original remains historical evidence, under
`activationPlannerBootstrapDigest`; its original root, signature, configuration,
generation, planner receipt, state enrollment and whole launch interval must
match the signed evidence pins. The embedded planner is genuinely verified under
the current root. Both use historical planner admission and the original current
processing window: neither old activation launch is renewed. The fresh signed
policy alone authorizes derivation of the new consume launch. Caller/grant
originals are not inputs to this policy API; the producer/receiver must separately
admit those actual request originals and join the independently signed digests.

Both state enrollments are genuinely admitted under their respective roots.
Their **complete signed payloads** must match, including database, generation,
initial vector, all state/computation/completion keys and measurements, and all
limits. Signature envelopes may differ. This permits a root re-signing without
pretending to authorize database, generation, vector or state-role migration.
It does not establish a currently published state head or physical DB identity.
The current configuration supplies the new consume planner/read-role authority;
key, AES-purpose and directory exclusions cover both old and current contexts.
Actual delivery expiry remains a later original-control derivation constraint,
not something this fresh policy can refresh.

The public-original verifier and producer retain their existing keyword APIs.
The existing `_IssuerPolicyMaterial` adds `historical_root_public_key`,
`current_planner` and `bridge`. `activation_planner` always means old evidence;
`current_planner` supplies independently admitted output configuration, runtime,
policy and state originals. V1 fills both with the same actual planner/root and
sets `bridge=None`. V2 supplies private `_BridgeMaterial` containing only the
original interval and independently pinned enrollment identities. No API accepts
these returned objects as caller-supplied authority.

V2 allows a 6 MiB envelope to carry a planner original bounded at 4 MiB plus its
encoding and metadata. The parent remains bounded at 4 MiB and the call at
64 MiB; those tighter aggregate reservations can reject otherwise valid individual
originals. The fixed nested capture/read footprint is checked and charged before
decoding the embedded planner. Issuer intake and downstream derivation must count
both genuine planners, state originals and vectors, without increasing a work
allowance. This is not a process-heap guarantee. Embedding the public original
does not introduce another FD or expose any historical private key.

Parent v21 carries a separate nullable `historicalConsumeInputAcquisition`
inventory, leaving ordinary `consume_input_acquisition` unchanged. Its genuine
cold admission joins the signed old selector, interval, root and enrollment pins
to the existing admitted archive scope; the embedded current planner and new
consume key/state pins must match the actual current parent. This lane retains
public originals only and enables no historical actor or private effect yet.

This slice connects policy, input issuance/receiving and cold intake only. The
actual protected delivery-plan old/current authority split remains a separate
integration gate, so the fresh consume actor stays closed to historical effects
until that connection is genuine. No SQL retry, unknown-attempt retry, old
permission reuse, cross-source adapter, deployment or runtime acceptance is
provided. Source remains unbuilt and unexecuted.
