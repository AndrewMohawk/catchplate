# Signed registration-source exchange

Source-only `.124` implementation; unbuilt and unexecuted. This private exchange
connects an independent verifier root observation to the existing planner's
pre-signing registration-source read. It does not provision an evidence signer
or expose a public registration workflow.

```text
verifier: independent root read -> original signed request + context
  -> peer-checked planner: authenticate -> actual source acquisition
  -> original signed response + canonical source observations
  -> verifier: authenticate response -> genuine membership/query/cutoff replay
```

## Fixed private composition

`AuthorityProcess._produce_webauthn_registration_source_request` obtains the
source root inventory through the actual configured verifier read owner, then
signs the request that binds the original context. The selectors and original
deadline remain caller inputs requiring upstream admission; neither
a root read nor a valid request signature creates enrollment permission.

The request carries two original byte strings: `(control_bytes, context_bytes)`.
On the existing verifier-to-planner peer connection,
`_produce_webauthn_registration_source_response` authenticates them before the
actual configured registration-source acquisition. That read uses the existing
guarded PostgreSQL lifecycle and fixed challenge, publication, high-water and
optional OIDC-session query subset. It does not require a not-yet-produced
evidence envelope or manufacture an evidence digest.

The planner returns `(response_control_bytes, source_bytes)`: a signed control
binding the exchange and canonical original source observations: full before
roots, selected rows, primary proofs, query-read records and database cutoff.
The verifier's
`_request_webauthn_registration_source` authenticates the response before
adopting its source bytes for genuine membership, query-association and cutoff
validation against the independently held request context. A planner observation
does not replace independent root admission or become independent clock authority.

`_acquire_webauthn_registration_source` composes those fixed steps and returns
the four original byte strings in this order:

1. Request control.
2. Request context.
3. Response control.
4. Source observations.

This raw-four return preserves signature evidence. It is ordinary data, not an
accepted successful-proof object, evidence envelope, execution grant or receipt.

## Ownership, timing and transport

The composition retains the actual measured configuration, admitted generation,
fixed registration-source purpose, signed request interval, original deadline
and shared work across acquisition, authentication and replay. Mutable inputs
are owned before callbacks. Request issuance is sampled from the actual opening
window; its expiry is clipped to the caller deadline and configured lifetime.
The response keeps that exact request expiry and existing window. The planner's
source acquisition uses that signed issuance and expiry; replay checks the
database cutoff against the same interval and configured skew. This is not
independent clock authority or permission to renew the lifetime. Normal
read-owner exits and active-generation checks remain part of the private
service composition.

The fixed `SWRSQ001` / `SWRSR001` transport admits both lengths before allocating
either body. Each control is at most 4 MiB; context or source bytes and the whole
two-part aggregate are at most the existing 64 MiB input ceiling. One absolute
connection deadline covers peer checking, exact I/O, request half-close and EOF.
The planner checks its existing verifier peer before the prefix, receives the
complete bounded request and EOF, then allocates one existing work allowance.
There is no fallback frame, automatic retry or changed peer topology.

## Authority boundary

The verifier and planner keys authenticate this source exchange only. They do
not substitute for the independently configured registration-evidence signer.
The separate [original-evidence signing composition](authority-original-evidence-signing.md)
still requires its own signer and independently admitted enrollment, prior
publication and original ceremony inputs.

The later [source-to-signer handoff](authority-registration-signing-handoff.md)
now authenticates these original controls and replays the source proofs inside
the dedicated signing continuation. It does not supply the still-unselected
actor/session enrollment authority or connect public registration routes.

No credential mutation, custody write, root reservation, new clock authority,
signer provisioning or public business route is added. A root observation can
become stale; signed source bytes do not prevent concurrent changes or authorize
later execution. Physical deployment, runtime verification and authenticated
public successor orchestration remain separate unfinished work.

Source: [private service composition](../catchplate/authority_service.py),
[fixed exchange actions](../catchplate/authority_webauthn_registration_source_actions.py),
[bounded transport](../catchplate/authority_webauthn_registration_source_transport.py),
[source-byte replay](../catchplate/authority_webauthn_registration_source_wire.py),
[actual source acquisition](../catchplate/authority_webauthn_registration_source_acquisition.py),
and [membership/query replay](../catchplate/authority_webauthn_registration_source_proofs.py).
