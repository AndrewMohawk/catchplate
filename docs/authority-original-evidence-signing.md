# Original WebAuthn evidence signing

Source-only `.123` composition; unbuilt and unexecuted. The registration path
now provides private source acquisition and connects raw row proofs to genuine
original-attestation verification and configured evidence signing. Installation
has a separate fixed-purpose signing mapper. Neither is a provisioned signer
process or a public successor workflow, and neither accepts a successful-proof
object as authority.

The later [signed registration-source exchange](authority-registration-source-exchange.md)
connects this private read owner to actual verifier root observations over the
existing verifier/planner peer boundary. It preserves the original request,
response and source proofs for independent authentication/replay, not as a
transferable successful result or an evidence-signing grant.

The later [source-to-signer handoff](authority-registration-signing-handoff.md)
consumes that original exchange directly in the dedicated signing continuation;
source controls are authenticated before returned rows are decoded. Enrollment
authority and independent signer provisioning remain unfinished.

## Registration: source proofs before an envelope exists

`authority_webauthn_registration_signing._produce_from_source_proofs_on_configuration`
receives the original browser bytes, independently admitted user/enrollment
authorization, sibling inventory and evaluation time, plus explicit configured
signer inputs. Instead of accepting caller-selected challenge/publication/session
rows as established facts, it invokes the actual source-proof verifier with:

- Challenge, publication and optional OIDC-session selectors.
- Independently admitted business and authorization before-root inventories.
- Raw selected rows and before-proofs, and the actual query-read records.
- The same original work allowance.

`authority_webauthn_registration_source_proofs._verify_on_work` itself verifies
membership and query association for the fixed pre-signing subset: challenge,
publication, high-water and optional OIDC session. Its ordinary four-row result
is consumed in that same composition; the signing entrypoint does not accept a
caller-supplied `_SourceRows` result.
The full source five-table root inventory remains required; only the queried
subset excludes the not-yet-produced evidence record, without a fake digest.
Supplied roots are not enrolled merely because a proof matches them. Their
provenance and observation time remain independent admission requirements.

This removes the signed-envelope/read circularity: these fixed source reads do
not require an evidence digest that can exist only after signing. They do not
replace the later full evidence-admission query/proof program.

```text
independently admitted roots/selectors/time
  -> actual private source acquisition returning raw proofs
  -> genuine fixed membership/query checks
  -> derived ceremony and complete stored trust context
  -> actual original-attestation verification and evidence signing
  -> typed evidence-admission request + retained original inputs
```

The ceremony derivation joins original client data to the stored challenge and
the full independently admitted enrollment authorization. The trust derivation
reconstructs the complete certificate inventory from the committed publication
and high-water rows; no caller chooses a separate scope or root list. The real
registration producer then parses and verifies the original attestation and
signs its derived claims. The actual invocation assembler computes request
commitments and encodes the original inputs on the same work.
Prior publication signature/commit admission remains an owner responsibility;
matching row membership does not create that provenance.

The explicit registration purpose supplies the public key, signer identity,
SPKI, RP/origin and lifetime. The independently held evidence private key must
match that policy; a generic verifier or planner role key is not substituted.
The older row-input mapper remains a private continuation for owners that have
already admitted those rows, not an alternative source of their provenance.

### Private source acquisition

The planner-only `AuthorityProcess._read_webauthn_registration_source` uses the actual configured
`EvidenceAdmissionPlanner.acquire_registration_source` and its fixed physical
read worker. It receives challenge/publication/optional-session selectors, full
before roots, original evaluation/deadline and work; no envelope, evidence digest,
key or policy override is required. Original inputs are owned before callbacks.

The existing guarded PostgreSQL read owner supplies its manifest, TLS, identity,
ACL and serializable read-only snapshot checks. The three or four fixed source-row
queries accompany the existing manifest, root, database-clock and radix-proof
reads; they are not a three-or-four-statement SQL limit. The worker returns raw
roots, selected rows, primary proofs, query-read records, database time and read trace.
The owner returns only after normal transaction/connection exit; the service
then rechecks the original active launch generation. This is a private source
implementation, not an executed or provisioned signer workflow or a new route.
It does not enroll supplied roots or infer selector, clock, enrollment or prior
publication authority. Configured limits and the original work are retained.

## Installation: independent installer purpose

`authority_webauthn_installation_signing._produce_on_configuration` owns all
original bytes, rows, committed-stage history, configuration/generation/runtime
graphs and signer references before native callbacks. Only the explicit enabled
installation purpose selects the public key, identity, SPKI, installation target
and lifetime; requests cannot override them.

It invokes the genuine installation producer over original installed-bundle and
rollback-state bytes, the pending publication, predecessor high-water and
independently admitted committed stage. The existing input assembler retains
the resulting signed envelope, exact installed bytes, original observation time
and full committed-stage graph without retiming or inventing history.

The installer owner still establishes physical installation, durable readback,
target ownership and committed stage/fence/witness ancestry. Byte equality and a
retained stage graph do not prove fsync, activation or a committed transition.

## Outputs and remaining boundary

Both configured compositions return four ordinary values:

1. The actual signed original evidence envelope.
2. Finalization or completion arguments.
3. The derived typed evidence-admission request.
4. The canonical original-input bytes.

These are inputs to the existing genuine admission/planning/custody workflow,
not an execution grant, reservation, custody receipt or proof that a caller
journal retained anything. No clock renewal, replacement budget, SQL privilege,
route or automatic forward/retry is introduced by these signing helpers.

Provisioning and admission of the independent signer, and authenticated public
successor orchestration remain unfinished. Membership verification and the
private read owner do not keep observed roots current, admit
enrollment permission, or establish pending-publication absence and unused
global credential history. Installation likewise retains its independent
physical-readback and committed-stage requirements. Source composition alone
does not establish runtime startup, deployment or production readiness.

Source: [registration source proofs](../serverware/authority_webauthn_registration_source_proofs.py),
[source acquisition](../serverware/authority_webauthn_registration_source_acquisition.py),
[configured read owner](../serverware/authority_webauthn_evidence_planning.py),
[registration signing](../serverware/authority_webauthn_registration_signing.py),
[registration production](../serverware/authority_webauthn_registration_production.py),
[installation signing](../serverware/authority_webauthn_installation_signing.py), and
[original invocation assembly](../serverware/authority_webauthn_evidence_invocation.py).
