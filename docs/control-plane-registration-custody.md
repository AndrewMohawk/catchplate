# Private registration evidence custody

Source `.131`; implementation only, unbuilt and unexecuted. This private
continuation connects already authenticated registration originals to genuine
evidence preparation and local durable custody. It is not a public registration
route, a registered credential, or a deployment/provisioning claim. The current
browser `/verify` handlers still use legacy finalization.

## Fixed source path

[`control_plane_registration_preparation.py`](../serverware/control_plane_registration_preparation.py)
provides `prepare_registration_custody(originals)` and the separate explicit
`prepare_and_forward_registration_custody(originals)`. The real operator/OIDC
handler must already have admitted enrollment and captured the original browser
data. An ordinary `_RegistrationOriginals` carrier cannot establish that prior
admission. See [public admission](authority-webauthn-public-admission.md).

```text
1. Authenticated original ceremony + existing cold owners
   -> 2. Genuine source exchange + dedicated grant/signer exchange; retain raw8/raw2
   -> 3. Verifier independently replays raw10; prepares exact custody raw6
   -> 4. Local journal durably appends PREPARED originals; returns local digest
   -> 5. Only explicit forwarding: durable ATTEMPTED marker -> one exchange
```

The actual publication lookup supplies a selector, not membership or a current
root reservation. The source exchange obtains independent verifier roots and
authenticated planner rows/proofs. The cold enrollment owner issues the dedicated
grant and uses the root-admitted signer endpoint. The independent signer performs
real grant/source/attestation verification and evidence signing; the caller then
genuinely verifies its response. Endpoint peer credentials alone are not evidence
or signer authority. These are trusted-host-local admissions, not TEE proof.

The [signer client](../serverware/authority_webauthn_registration_signer_client.py)
retains the exact original request eight and response two alongside ordinary
regenerated request/input fields. The existing evidence-only APIs keep their
old three-field result. No grant or exchange is repeated to obtain originals,
and no successful-verification object is accepted as a substitute for replay.

## Independent verifier admission before custody preparation

The dedicated
[`authority_webauthn_registration_custody_caller.py`](../serverware/authority_webauthn_registration_custody_caller.py)
protocol uses request magic `SWRCPQ01` and response magic `SWRCPR01`. It carries
the unchanged signer raw8 plus raw2 through the existing control-plane → relay
→ verifier topology, with current configuration scope and the original absolute
deadline. It returns only the exact prepared evidence-custody raw6.
The cold
[`ControlPlaneCustodyClient.prepare_registration_custody`](../serverware/control_plane_custody_client.py)
holds that raw10 and selects only its already admitted relay endpoint; this
transport method itself neither appends locally nor contacts the remote writer.

The verifier runs the actual configured
[`signer_response._verify_on_configuration`](../serverware/authority_webauthn_registration_signer_response.py)
against independent keys/configuration before its actual
[`_prepare_webauthn_evidence_custody`](../serverware/authority_service.py).
That replay authenticates the grant and source controls, verifies source
memberships/query associations and original attestation/evidence semantics,
and compares the regenerated input bytes. The real custody path then prepares
the evidence plan, independent history context, intent and relay controls.
No caller-selected roots, configuration, history, signer, budget or callback
registry can replace these fixed owners. Preparing raw6 is not a remote write.

## Durable handoff and uncertainty

`prepare_registration_custody(originals)` appends the exact returned raw6 through
the actual [custody client and journal](control-plane-custody-journal.md), then
returns only its local digest. That digest identifies retained originals; it
does not assert remote commitment, enrollment completion or business success.

`prepare_and_forward_registration_custody(originals)` first completes that same
durable append, then invokes the existing one-attempt forwarding path. Its
`CustodyForwardObservation` contains the local digest and unsigned remote
record/time observation, not a signed durability receipt. Ordinary uncertain
post-append failures use `CustodyForwardOutcomeError.local_digest`; inventory
also preserves discoverability. Neither failure nor a missing response permits
reset, resend, deletion or an automatic retry. Explicit read-only reconciliation
remains separate and never clears the attempted marker.

Preparation preserves one original work allowance and deadline across the fixed
composition; receiving services still own their existing bounded work. Durable
append may finish after the deadline so acquired originals are not discarded,
but expiry forbids forwarding. A prepared-only record is not evidence that the
remote store lacks it, and an observation is not new execution authority.

Public handler orchestration, complete OIDC sibling/history populations,
current-root reservation and issuer/executor/atomic business execution remain
unfinished. Independent service/key/storage provisioning and consolidated
frozen verification are still required. No source path here renews an original
grant, source window or receipt, or supplies cross-source historical authority.
