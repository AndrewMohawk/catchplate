# Private WebAuthn transition custody

Status: source `.106`, implementation only; unbuilt and unexecuted. This is the
private retention path for `webauthn.registration.finalize`,
`webauthn.trust.stage` and `webauthn.trust.complete`, not execution of those
business transitions. See the [successor overview](webauthn-successor-transitions.md)
for signed planning and the `.105` PostgreSQL custody checkpoint.

## Originals and authority

The plan remains four original byte strings: envelope, proof, inputs and
evaluation context. Custody additionally carries independently admitted
historical expectations. A copied plan context, stored row, successful result
object or current configuration cannot supply that historical authority.
Request, root/count-head, cutoff, invocation, policy and key provenance must
already be admitted by the caller. Genuine raw-four signature, proof and
semantic replay still runs on the same invocation allowance.

The verifier signs a dedicated retain-only intent binding the exact originals
and historical expectations. The planner authenticates that intent and replays
the originals before signing its separate relay. These controls bind the fixed
operation, configuration, launch generation, record identity and byte inventory;
neither is an execution capability or proof that the database committed.

## Preparation and explicit delivery

1. Verifier prepares the original intent and requests a relay from the planner.
   This raw-six request is `(intent, envelope, proof, inputs, context, history)`.
   The planner returns the original signed relay without contacting the writer.
2. The caller retains the exact originals and explicitly chooses whether to
   forward. Delivery is raw seven:
   `(intent, relay, envelope, proof, inputs, context, history)`.
   The verifier forwards to the planner, which sends those originals to the writer.
3. The writer authenticates both controls and genuinely replays the plan before
   the fixed PostgreSQL custody operation. The returned digest and first-retained
   timestamp travel back through the planner as ordinary peer observations.

Preparation never automatically forwards, signs replacement originals or
retries. Before a potentially committing forward, the caller must durably retain
the exact request originals needed for later reconciliation. That durable caller
orchestration is still unfinished; this source path does not provide it.

All three hops use dedicated eight-byte operation/action prefixes, complete
length vectors, exact EOF and a 64 MiB aggregate including controls. Controls
are individually bounded to 4 MiB. Clients check configured Unix peer UID/GID
before sending and use one absolute transport deadline. The actual measured
configuration preserves verifier → planner → writer topology, explicit
transition policy and distinct verifier/planner keys; no ACL is widened.

## Commit and failure boundaries

The original intent/relay windows remain in force across authentication, replay
and transport. Writer composition checks them immediately before and after the
actual store operation inside the outer transaction, and again after normal
outer transaction/connection exit. The store separately
checks the original signed plan expiry and invocation deadline without retiming
either. Identical content must match every immutable field and preserves the
first stored timestamp; it does not gain a fresh lifetime.

The response is an **unsigned digest/timestamp observation**, not a signed
durability receipt. A failure after commit or during uncertain connection exit
does not prove rollback or absence and does not authorize an automatic retry.
Transport completion, source inspection and a returned ordinary object do not
establish tested deployment behavior or exactly-once business execution.

Independent historical resolution, durable caller retention/reconciliation,
authenticated retrieval/recovery, public orchestration and atomic successor
execution remain unfinished. This path does not keep roots current, reserve a
logical operation, issue execution authority or complete the public workflow.
Infrastructure admission and the consolidated runtime/build validation phase
remain separate release requirements.
