# Registration evidence custody and public preparation

Source `.132`; implementation only, unbuilt and unexecuted. The private custody
continuation introduced in `.131` now has separate authenticated HTTP `/prepare`
callers. They connect registration originals to genuine evidence preparation and
local durable custody, not a registered credential or remote business execution.
This is not a deployment/provisioning claim. The current browser `/verify`
handlers still use legacy finalization.

## HTTP preparation boundary

The actual [`app.py`](../catchplate/app.py) routes are:

- `POST /api/webauthn/register/prepare`: authenticated admin/approver admission.
- `POST /api/auth/session/webauthn/register/prepare`: actual pending-OIDC session
  lookup and current authoritative RBAC admission, without session activation.

Normal cookie CSRF checks remain. Both routes capture the original ceremony under
the existing shared trust lock and call only `prepare_registration_custody`.
Options-time MFA/approval is neither rerun nor consumed by preparation.

The request is strict JSON, at most 512 KiB, with exactly the required outer
fields `label` and `response`; no default label or extra outer fields are accepted.
It requires one exact `Content-Length` and `Content-Type: application/json`,
matching actual body length, no query string and no transfer/content encoding.
Bounded depth/node/string limits and strict JSON parsing apply before model use.

Success is a no-store **202**, schema
`catchplate.webAuthnRegistrationCustodyPreparation/v1`, with `status: prepared`,
`localDigest`, and `registrationCompleted: false`. It reports local PREPARED
originals only. These endpoints do not forward, retry, finalize a credential or
activate an OIDC session. A failure can follow grant consumption or a local
write; bounded error responses preserve `remoteState: unknown` and authorize
neither resend nor fallback to `/verify`.

## Fixed source path

[`control_plane_registration_preparation.py`](../catchplate/control_plane_registration_preparation.py)
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

The [signer client](../catchplate/authority_webauthn_registration_signer_client.py)
retains the exact original request eight and response two alongside ordinary
regenerated request/input fields. The existing evidence-only APIs keep their
old three-field result. No grant or exchange is repeated to obtain originals,
and no successful-verification object is accepted as a substitute for replay.

## Independent verifier admission before custody preparation

The dedicated
[`authority_webauthn_registration_custody_caller.py`](../catchplate/authority_webauthn_registration_custody_caller.py)
protocol uses request magic `SWRCPQ01` and response magic `SWRCPR01`. It carries
the unchanged signer raw8 plus raw2 through the existing control-plane → relay
→ verifier topology, with current configuration scope and the original absolute
deadline. It returns only the exact prepared evidence-custody raw6.
The cold
[`ControlPlaneCustodyClient.prepare_registration_custody`](../catchplate/control_plane_custody_client.py)
holds that raw10 and selects only its already admitted relay endpoint; this
transport method itself neither appends locally nor contacts the remote writer.

The verifier runs the actual configured
[`signer_response._verify_on_configuration`](../catchplate/authority_webauthn_registration_signer_response.py)
against independent keys/configuration before its actual
[`_prepare_webauthn_evidence_custody`](../catchplate/authority_service.py).
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

## Finalization remains a separate prerequisite

The fixed
[`signer_response._verify_finalization_on_configuration`](../catchplate/authority_webauthn_registration_signer_response.py)
now genuinely replays the original grant/source/attestation/evidence and exact
returned input bytes, then derives a typed `webauthn.registration.finalize`
request and the actual empty transition-input encoding. Its bounded sorted
sibling IDs are hints, not population proof; no unsigned derived response
metadata or successful-verification carrier supplies finalization arguments.
The existing evidence-only verifier remains unchanged.

The actual measured verifier's private
`AuthorityProcess._prepare_webauthn_registration_finalization` now composes that
original-byte verifier with genuine transition custody preparation. It returns
prepared transition raw7 under the original receipt/window and inherited
transport deadline, not a custody write or business result. The separate
[retained-original finalization facade](retained-registration-finalization.md)
now supplies an application continuation from the durable signer/grant
association and genuinely verified acknowledged evidence completion. Its
[public preparation routes](public-registration-finalization.md) return the
original execution locator and durably appended finalization raw7 locator with
`status: finalization-prepared`. Server-observed sibling hints remain required
and must pass the downstream complete-population proof. This does not forward
or execute the prepared finalization, finalize a credential or activate a session.

Complete OIDC sibling/history proofs, genuine business evidence admission and
consumption of the unconsumed v2 receipt, current-root reservation and
issuer/executor/atomic business execution remain required. HTTP preparation does
not perform finalization execution or separate OIDC browser-session activation.
Independent service/key/storage provisioning and
consolidated frozen verification are still required. No source path here renews
an original grant, source window or receipt, or supplies cross-source historical
authority.
