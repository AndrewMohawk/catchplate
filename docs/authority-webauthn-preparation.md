# Private WebAuthn custody preparation

Source `.120`; implementation only, unbuilt and unexecuted. The actual verifier
now composes live planning, historical-observation admission, retain-intent
signing and planner-relay preparation. It returns exact originals for the caller
journal. It does not expose a public endpoint or contact the custody writer.

## Actual service entrypoints

`AuthorityProcess._prepare_webauthn_evidence_custody` accepts the fixed purpose,
independently admitted typed request, exact original input bytes, original
deadline and the caller's existing work allowance. Registration and installation
return raw six:

```text
intent, relay, envelope, inputs, evaluation context, admitted history
```

`AuthorityProcess._prepare_webauthn_transition_custody` additionally takes the
original evaluation instant and admitted invocation. Registration finalization,
trust staging and trust completion return raw seven:

```text
intent, relay, envelope, proof, inputs, plan context, admitted history
```

The real measured verifier process, configuration, generation and current
historical-archive lifetime govern the complete composition. Upstream request,
ceremony and invocation provenance are preconditions, not facts inferred from
these arguments. In particular, a stage capability ID and completion's committed
stage material remain independently admitted inputs.

## Live origin of historical expectations

```text
admitted invocation and originals
    -> verifier's independent root snapshot and signed planning request
    -> actual planner's signed response and plan originals
    -> verifier authenticates both controls and replays originals
    -> reconstruct history and admit bounded live observations
    -> genuine custody intent and authenticated planner relay
    -> caller retains raw six/seven before a separate forwarding action
```

The existing live-only planning API remains observation-only and keeps its
original return contract. The new fixed exchange-and-admit continuation performs
the same real request/response authentication and original signature, proof and
semantic replay before producing historical expectations. It accepts no
successful-verification token or caller-supplied history in place of originals.

| Historical fields | Provenance in the new continuation |
| --- | --- |
| Evidence request, roots and input commitment | Original authenticated verifier planning request |
| Evidence configuration, identities, keys and policy | Held measured configuration and runtime pins |
| Evidence database cutoff, issue instant and effective deadline | Only these three planner observations, authenticated and bounded by the original live request and policy |
| Transition request, roots, counted heads, inputs, evaluation time, deadline and invocation | Original authenticated verifier planning request |
| Transition configuration, identities and operation policy | Held measured configuration and runtime pins |
| Transition database cutoff | The sole admitted planner observation, constrained against the original invocation and live request |

The reconstructed history must equal the original canonical context. A stored
context or an arbitrary signed plan is not independently admissible merely
because it has these fields. This continuation records what the verifier
genuinely checked during the authenticated live exchange. It does not establish
independent database-clock truth, hold database roots current, or authorize
business execution.

Original request/plan/control intervals and historical evaluation/cutoff must
fit the held archive authorization interval. Current lifetime checks span all
phases. Nothing changes an original evaluation instant, deadline, plan expiry or
control window to make preparation succeed. The evidence intent also repeats
its existing fresh root comparison; a changed root can reject the preparation.

Intent and relay preparation genuinely replay the original plan under this
admitted history. Every phase uses the same work allowance and unchanged
transport bounds. Transport size limits do not promise that every maximum-sized
input fits the cumulative proof-work budget. No additional allowance, silent
retry, custody insert, SQL privilege or legacy execution operation is added.

## Caller and public-workflow boundary

The returned tuple is ordinary original-byte data, not a durable or signed writer
receipt. The caller must durably append it using the existing
[custody journal](control-plane-custody-journal.md), then explicitly invoke
forwarding. Preparation itself neither appends that journal nor sends a retain
request. Current-root authority, logical reservation, one-use capabilities and
atomic successor execution remain separate requirements.

The [public admission mapping](authority-webauthn-public-admission.md) identifies
the unfinished browser/operator continuations. Existing public execute/retry
contracts are not repurposed for this private preparation. The two evidence
admission operations are explicitly classified internal-only; this repairs an
API classification omission without granting them public access. No current
application-import or startup success has been demonstrated.

Actual deployment, independent services, cross-source historical replay and
consolidated frozen-build/runtime verification remain unfinished.
