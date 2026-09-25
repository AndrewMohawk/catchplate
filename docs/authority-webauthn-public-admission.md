# WebAuthn public admission and private preparation

Current source checkpoint: `.130`. This is a source-only integration map, not a
tested import, running endpoint or deployment claim. Private preparation is
described in [WebAuthn preparation](authority-webauthn-preparation.md); the public
admission continuation below is still missing.

## Existing public boundary

[`ControlledAuthorityExecuteRequest` and
`execute_control_plane_authority_operation`](../serverware/app.py) serve
`POST /api/authority/control-plane/execute` with the closed outer fields
`requestId`, `operation` and `arguments`. The route uses authenticated, refreshed
RBAC, operation-specific roles, bounded JSON framing and the existing exact-result
request-ID machinery. It then constructs `ControlledWriterInput/v1` and calls
[`db.dispatch_policy_authority_operation`](../serverware/db.py).

This remains legacy execution dispatch. Assertion presence at this route is a
shape check, not signature admission; the actual
[`AuthorityRuntimeClient.request`](../serverware/authority_service.py) rejects
successor operations. Preparation must not inherit this endpoint's execution
result or exact-retry contract.

The `.120` classification fix places `webauthn.registration.evidence.admit` and
`webauthn.trust.installation.admit` in the explicit internal-only set. Source
comparison covers all 57 operation contracts: 43 controlled-role, seven
specialized and seven internal. It grants neither operation a public role and
does not widen legacy dispatch. No import or startup was executed to establish
that result.

[`authority_webauthn_challenge`](../serverware/app.py), at
`POST /api/authority/webauthn/challenges`, checks the operation's assertion policy,
the authenticated operator's role and ownership of the active credential before
calling `db.issue_policy_authority_webauthn_challenge`. Its real challenge binds
the requested operation arguments. A supplied actor, challenge or assertion
object alone is not equivalent admission. Authentication, current OIDC-role
refresh and cookie CSRF enforcement remain in [`auth.py`](../serverware/auth.py).

## Registration: browser originals are not derived authority

The existing options routes are `POST /api/webauthn/register/options` and
`POST /api/auth/session/webauthn/register/options`. Their
[`app.py`](../serverware/app.py) handlers distinguish authenticated operator
bootstrap/MFA/two-person approval from pending-OIDC first enrollment. User and
session identities, enrollment mode and authorization digest are derived from
those checks, not accepted as browser assertions.

The corresponding `/verify` routes accept `WebAuthnRegistrationFinish`:
`label` and `response`. The reusable
[`webauthn._capture_registration_originals`](../serverware/webauthn.py) now owns
the selected browser values and expected authorization before decode/database
callbacks, preserves exact client-data/attestation bytes and credential/transports,
and joins the unused stored challenge to user, label and server authorization.
Its frozen raw-data carrier contains the actual ceremony and configured RP/origin,
not verification success, roots, signer authority or an evaluation time.
`verify_registration` uses this helper, then performs real cryptography,
duplicate checking and the existing legacy finalizer; its return contract is
unchanged. A new continuation must not accept this carrier as a proof token.

A preparation continuation must instead preserve those originals and derive the
ceremony scope, expected authorization, configured RP/origin, admitted trust-root
DER snapshot and evaluation time. Published trust/high-water, optional OIDC
session and finalization's complete sibling/history populations require genuine
state admission. The actual `_claims_on_work` and `_produce_on_work` in
[`authority_webauthn_registration_production.py`](../serverware/authority_webauthn_registration_production.py)
perform semantic/evidence construction; client-supplied derived credentials,
evidence digests or successful-verification objects cannot replace it.

The private [row-derived production continuation](authority-registration-evidence-production.md)
now performs that ceremony and full-root extraction from already admitted rows,
calls the genuine cryptographic producer and assembles the exact evidence
request and input bytes. A fixed configuration mapper selects the registration
purpose's actual signer identity, public key, RP/origin and lifetime; it accepts
no generic verifier-key fallback. It does not independently admit row membership,
enrollment, currentness or the signer service, and it does not connect either
browser `/verify` route to successor execution. Those handlers still use their
legacy finalization path.

The two actual `/verify` handlers now call fixed raw-input helpers after their
real operator-role or pending-OIDC-session/current-RBAC admission. They capture
once and enter the shared genuine verification/finalization continuation under
the existing trust lock. Options-time MFA and approval consumption are unchanged;
no preparation path reruns or consumes them. These helpers do not export an
authenticated-user or successful-attestation token to a separate service.

The private planner now has a [pre-signing source-read continuation](authority-original-evidence-signing.md)
over the existing registration read families. Actual row memberships and exact
query/address associations can feed the configured evidence producer before a
signed envelope exists. Root, enrollment, time and signer provenance still need
independent admission and an authenticated cross-service handoff; no public
browser route calls this private preparation chain yet.

The [signed registration-source exchange](authority-registration-source-exchange.md)
now connects actual verifier root reads to authenticated planner source
acquisition and verifier-side membership/query/cutoff replay. Its planner-only
private transport authenticates the original request and complete returned
source bytes; it does not admit enrollment selectors from a browser, provision
the independent evidence signer or expose successor business execution.

The [source-to-signer handoff](authority-registration-signing-handoff.md) now
authenticates those four original byte strings inside the dedicated signing
continuation, replays their source proofs and derives its selectors and roots
from that same exchange. It preserves the original evaluation time and distinct
source-control/evidence lifetimes. The user has selected a
[dedicated signed control-plane grant](enrollment-authorization-decision.md).
Its private producer and configured verification now bind original browser
inputs and user/session/challenge authorization, with a durable one-attempt
marker before evidence signing. Protected key delivery and the fixed cold issuer
owner now exist in [enrollment startup](control-plane-enrollment-startup.md);
the private [signer exchange](registration-evidence-signer-exchange.md) adds
original-byte transport, real signing/replay ownership and caller verification.
The dedicated [.129 signer cold-start path](registration-evidence-signer-startup.md)
now supplies protected five-FD delivery, genuine bootstrap/receipt admission,
the fixed nonroot accept owner and uninstalled service templates. Its original
receipt expiry and existing replay domain are not renewed by a restart. Actual
independent provisioning, deployment and public orchestration remain unfinished.
Neither source-role signatures nor the generic response key supplies enrollment
authority. Public routes remain on their legacy continuation.

## Private caller-to-verifier source bridge

The fixed [registration source caller bridge](../serverware/authority_webauthn_registration_source_caller.py)
uses the existing control-plane → runtime relay → verifier topology. Both
listeners admit their actual configured Unix peer before the request prefix;
the verifier does not acquire a new direct control-plane peer. The canonical
request is closed to `schema`, `sourceRevision`, `registrationChallengeId`,
`publishedPublicationId`, `oidcSessionId` and `deadlineEpochNs`, with a separate
configuration-digest transport binding. It carries no caller roots, signer,
DSN, generation or replacement work allowance.

The actual `ControlPlaneCustodyClient.request_registration_source` accepts only
the three selectors, original epoch deadline, shared work and optional inherited
absolute transport deadline; its endpoint comes from the admitted binding.
The relay forwards the bounded original request without treating selectors as
enrollment authority. After exact request EOF, the verifier uses one original
work allowance to call its actual `_acquire_webauthn_registration_source`:
independent verifier roots, authenticated planner read, and genuine source-proof
replay. The result is four original byte strings (request control/context,
response control/source bytes), not a transferable successful-proof token.
Configuration/generation continuity and original receipt/deadline bounds remain
mandatory; the dedicated signer independently authenticates and replays that
same exchange before signing.

This bridge does not connect the browser `/verify` routes. Their authenticated
capture derives the live challenge ID and the actual pending-OIDC session ID
(or no session). The new fixed
[`db.observe_published_webauthn_trust_publication_id`](../serverware/db.py)
uses one bounded read to join the global published row to the
`webauthn-metadata` high-water tuple (rollback epoch, publication sequence/digest
and metadata-blob digest), rejects pending, absent or ambiguous state, and returns
only its bounded ID. It performs no lock, repair or write. That observed selector
is still only a lookup input: the source exchange must verify the selected rows
and their proofs, and neither lookup nor root observation reserves current state.

Server-owned enrollment authorization, publication selection, complete
finalization populations, signed evidence preparation and journal-before-forward
custody still need a complete authenticated public continuation. The bridge
neither consumes a grant nor writes custody, finalizes a credential or enables
successor execution.

The private [`prepare_registration_evidence(originals)`](../serverware/control_plane_registration_preparation.py)
now composes the existing cold owners, candidate publication lookup and that
source bridge with real enrollment issuance and signer-response verification:

```text
already authenticated ceremony originals
  -> server publication selector -> verifier roots + planner source proofs
  -> original UTC verification instant -> dedicated enrollment grant
  -> independent signer -> genuine caller-side evidence/input replay
  -> evidence-admission inputs (not a registered credential)
```

It derives any OIDC session selector from original canonical authorization and
accepts no time, endpoint, key, root, configuration or work-budget override. One
original request window reaches both private transports without renewal. It
does not authenticate a raw-input carrier or call either public handler, and
does not durably retain the resulting originals or forward a custody request.

## Trust stage and completion have different prerequisites

`POST /api/webauthn/trust/publish` accepts `WebAuthnTrustPublish` (`bundle`,
`reason`, optional `mfa`) under admin admission. Its existing handler verifies
the candidate and derives current trust/withdrawal information. A successor
continuation must preserve exact candidate bytes and independently bind the
candidate key/policy, previous trust state, authenticated actor, complete
withdrawal/dependent populations and approval to the proposed transition.
[`authority_webauthn_trust_candidate._admit_on_work`](../serverware/authority_webauthn_trust_candidate.py)
and the actual stage planner provide the existing private verification pieces.

The authority-shaped branch of `_require_control_plane_mutation_mfa` merely
extracts raw assertion fields. `_require_control_plane_two_person` can consume
approval state. Neither is an already-verified assertion token or a side-effect-
free preparation adapter; approval consumption must not be silently performed
as part of a read-only preparation promise.

Completion requires independently committed stage bindings and genuine signed
installer evidence for the configured target, not only a publication ID or local
disk observation. The stage bindings include request/operation, receipt, roots,
fence, witness and publication/high-water identities; see
[`authority_transition_webauthn_completion.py`](../serverware/authority_transition_webauthn_completion.py).
[`webauthn_trust.reconcile_trust_publications`](../serverware/webauthn_trust.py)
still uses legacy ID-only completion and explicitly does not supply that missing
signed installation authority.

## Concrete missing continuation

An authenticated adapter must derive the inputs above and reach the verifier's
`_prepare_webauthn_evidence_custody` or `_prepare_webauthn_transition_custody` in
[`authority_service.py`](../serverware/authority_service.py). Caller-selected keys,
roots, configuration/generation, work allowances, historical authority, capability
IDs or committed-stage authority are not admissible substitutes.

Raw-six/raw-seven originals must enter the [caller custody journal](control-plane-custody-journal.md)
before forwarding. This continuation grants no business mutation, reservation,
execution, retry or historical provenance. Deployment and runtime verification remain open.

The fixed private evidence-invocation assembler and verifier compositions now
derive typed requests from original signed evidence and admitted ceremony/rows;
see [private preparation](authority-webauthn-preparation.md). That removes caller
request/digest construction but does not supply the missing original evidence
signer or independent state admission. The new admin
[custody recovery workspace](control-plane-custody-recovery.md) operates only on
already retained local records and does not bypass this public admission work.
