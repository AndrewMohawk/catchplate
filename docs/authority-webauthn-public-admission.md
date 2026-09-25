# WebAuthn public admission and private preparation

Current source checkpoint: `.122`. This is a source-only integration map, not
a tested import, running endpoint or deployment claim. Private preparation is
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
