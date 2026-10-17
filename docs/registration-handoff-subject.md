# Retained registration handoff subject

The source implementation in
[`control_plane_registration_handoff_subject.py`](../catchplate/control_plane_registration_handoff_subject.py)
derives the owner of retained registration evidence before separately authorized
SQL or live-completion actions. This is source-only implementation: it has not
been built, executed or admitted for production.

`inspect_retained_registration_subject(local_digest)` returns an ordinary
dictionary with exactly seven fields:

| Field | Meaning and bound |
| --- | --- |
| `localDigest` | Canonical `sha256:` local execution-record locator. |
| `userId` | Replayed registration user; nonempty, at most 4096 UTF-8 bytes. |
| `challengeId` | Replayed registration challenge ID; same text bound. |
| `sessionId` | Exact pending OIDC session ID with the same bound, or `null`. |
| `mode` | `bootstrap-token`, `development-bootstrap`, `existing-webauthn`, or `oidc-session-first-enrollment`. |
| `requestDigest` | Canonical SHA-256 commitment to the genuinely reconstructed evidence-admission request. |
| `operationId` | Canonical SHA-256 identity for that source-fixed operation and request. |

Only `oidc-session-first-enrollment` has a non-null session ID. These are the
original registration mode and subject, not claims about the present browser's
authentication, permissions, MFA or session state. No raw ceremony, certificate,
credential, key, token, root vector or successful-status field is returned.

## Original-to-subject join

The actual cold enrollment and custody owners must be live and unchanged, with
the explicit SQL/completion handoff profile enabled. The journal supplies its
durable signer/grant association and the exact signer request-eight/response-two
and execution-grant raw-ten originals. Their fixed families, current source,
per-body/group bounds and combined 64 MiB ceiling, including the three original
enrollments, are checked. The association locates bytes; it does not prove that
the grant belongs to the signer exchange or to a particular user.

The narrow same-replay projection in
[`authority_webauthn_registration_signer_response.py`](../catchplate/authority_webauthn_registration_signer_response.py)
retains the existing full source-control, enrollment-authorization, ceremony,
attestation and evidence-signature replay. It reconstructs the actual typed
evidence-admission request before projecting subject scalars. Existing pair,
execution-issuance and finalization APIs keep their outputs unchanged.

The inspector then runs the existing genuine grant receiver: authenticated
planning request and response, dedicated caller authorization, complete original
plan/vector replay, grant signature and original scope/lifetime checks. Only
after that succeeds does it read the same immutable verified grant and compare
its signed request and operation commitments with the signer-reconstructed
request. A valid association between unrelated authentic exchanges fails here.

## Use and limits

The private `_inspect_on_owner(owner, local_digest, deadline_epoch_ns,
deadline_ns, work)` repeats this inspection under the actual owner's dispatch
lock using the caller's existing cumulative work and absolute deadline. It
creates no replacement work allowance. Original signer, planning, authorization,
grant and cold-owner lifetimes cannot be renewed; expired originals are not
accepted as historical recovery evidence. Clock checks are local bounds, not
hard watchdogs or independent currentness witnesses.

Public-action orchestration must authenticate the current caller, check its
current role/session and CSRF, bind the new action's MFA/two-person approval,
then repeat inspection immediately before the side effect and compare explicit
current user/session scalars. A previously returned dictionary is never an
accepted authority token. Inspection itself performs no socket exchange,
signing, SQL, attempt claim, completion delivery, checkpoint advancement,
credential finalization or OIDC activation. It proves neither a live database
pending head nor permission to retry an uncertain effect.
