# Registration evidence production from admitted originals

Source `.122`; implementation only, unbuilt and unexecuted. The private
registration continuation derives ceremony and complete trust context from
independently admitted originals and rows, runs real attestation cryptography,
signs the evidence, and assembles the existing evidence-admission request.
It does not provision an independent signer, process, socket or browser route.
Public registration still uses the actual legacy finalizer in
[`webauthn.verify_registration`](../serverware/webauthn.py).

## Required upstream authority

The owning signer must independently admit all of the following before using
the new [`_produce_on_configuration`](../serverware/authority_webauthn_registration_signing.py):

- Exact browser `clientDataJSON` and attestation-object bytes, credential ID and
  transports; authenticated user and label; the unused registration challenge
  row belonging to that user; and expected enrollment authorization.
- The committed publication and matching high-water rows, including prior
  genuine stage bundle signature/schema admission and the committed transition.
  Required OIDC session and sibling-challenge state must likewise be admitted.
- The original UTC verification instant, not a replacement time selected to
  make expired evidence valid.
- Root-admitted signed configuration, active generation and runtime cohort,
  plus the dedicated evidence private key and independently admitted signer
  identity. Possessing matching dictionaries or a private key is insufficient.

Bootstrap, MFA, approval and OIDC enrollment policy remain the upstream
[public-admission boundary](authority-webauthn-public-admission.md). These
helpers do not prove row membership, pending-publication absence, current roots,
enrollment permission or signer provenance.

## Fixed source composition

```text
admitted configuration, purpose signer, original rows and browser bytes
    -> configured registration-purpose/key/identity joins
    -> row-derived ceremony + committed-publication trust context
    -> original attestation verification + genuine evidence signing
    -> evidence request and canonical original-input encoding
```

The configuration wrapper owns complete input/configuration/generation/runtime
graphs before native callbacks. It requires the enabled
`webauthn.registration.evidence.admit` operation and an explicit non-null
`webauthnEvidenceAdmission.registration` purpose policy. That policy supplies the
`registration-attestation` public key, SPKI, signer identity, RP ID, origin and
maximum age. The wrapper compares the independently supplied signer identity
and checks the actual private/public pair. Neither the generic verifier key nor
the planner key substitutes for the dedicated purpose signer.

[`registration_ceremony._derive_on_work`](../serverware/authority_webauthn_registration_ceremony.py)
joins the exact challenge row, authenticated user/label and complete canonical
authorization, and parses the original client data against configured origin.
The configured RP ID remains an input to actual downstream registration parsing.
It returns selected immutable originals and a genuine core `CeremonyScope`,
not a successful-verification token. No caller scope is accepted.

[`registration_trust._context_on_work`](../serverware/authority_webauthn_registration_trust.py)
rejoins stored canonical bundle/stage commitments, high-water counters/digests
and original evaluation interval. It extracts every stored root certificate
through the real trust core into the actual attestation context. This relies on
the previously admitted stage signature and committed state: extraction does
not freshly verify the publication signer or admit root/state provenance.

[`registration_production._produce_from_rows_on_work`](../serverware/authority_webauthn_registration_production.py)
passes those derived values to the unchanged original `_produce_on_work`.
Actual registration parsing, attestation verification, row/authorization joins,
bounded evidence lifetime and real evidence signing still execute. The
[`invocation assembler`](../serverware/authority_webauthn_evidence_invocation.py)
then derives request commitments from this invocation's signed original, not a
caller-supplied successful result. All phases retain the original verification
instant and share the supplied work; no new clock or replacement allowance is
introduced.

## Exact handoff, not execution

The continuation returns the ordinary tuple:

```text
(envelope_bytes, finalization_arguments, evidence_request, inputs_bytes)
```

`evidence_request` selects `webauthn.registration.evidence.admit` and binds the
actual evidence digest, registration challenge ID, committed publication ID and
optional OIDC session ID. `inputs_bytes` contains the canonical original replay
inputs. Finalization arguments are separate data, not permission to mutate
credentials or an already executed finalization.

An independently admitted verifier continuation can pass the returned request
and inputs to the existing
[`AuthorityProcess._prepare_webauthn_evidence_custody`](../serverware/authority_service.py)
with `purpose="registration"`, its admitted original deadline and the same work.
That [private preparation path](authority-webauthn-preparation.md) produces raw
six: intent, relay, plan envelope, inputs, evaluation context and admitted
history. It does not contact the custody writer. The separate caller must
[journal those exact originals before forwarding](control-plane-custody-journal.md);
an evidence signature or this tuple does not replace that durable preparation.

The public enrollment-to-private-signing/preparation continuation, independently
provisioned purpose signer and deployment remain open. No public successor
execution, reservation/capability authority, retry permission, durable signed
receipt, runtime verification or physical proof is claimed by this source work.
