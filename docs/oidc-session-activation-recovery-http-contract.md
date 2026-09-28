# Public recovery request data

`oidc_session_activation_recovery_http_contract` defines bounded DATA for the
[public recovery foundation](oidc-session-activation-public-recovery.md). It adds
no route, successful permission, activation retry, recovery authority or token
delivery. Source remains unbuilt and unexecuted.

`parse_request(raw_bytes, *, options=False)` accepts exact immutable JSON bytes
from 2 through 64 KiB, using the established strict duplicate/depth/key/node
limits. The required closed fields are:

| Field | Exact value or grammar |
| --- | --- |
| `schema` | `serverware.oidcSessionActivationRecoveryRequest/v1` |
| `purpose` | `recover-oidc-session-activation` |
| `localDigest` | Original finalization locator: `sha256:` plus 64 lowercase hexadecimal characters |

Options forbid `mfa`. The dispatch carrier permits only optional
`mfa`, whose only fields are an assertion object and/or a bounded `approvalId`.
Parsing an empty or absent assertion grants nothing: the real recovery actor
requires the fresh recovery ceremony before acquisition. No planning
assertion, target identity, bootstrap, grant, proof, outcome or token field is
accepted. The old cookie remains ephemeral possession, not a posted current
identity or permission to repeat activation.

`request_binding(subject8, *, activation_authorization_digest, old_token_digest)`
projects the actual independently replayed eight-field finalization subject
using the established exact OIDC first-enrollment and credential grammar. It
adds the distinct action `webauthn.oidc-session.activation.recover`, intent schema
`serverware.oidcSessionActivationRecoveryIntent/v1`, recovery purpose and exact
`activationAuthorizationDigest`/`oldTokenDigest`. These are ordinary binding
fields, not a successful admission carrier. The association digest is only a
retained-record locator; historical intent/possession admission must independently
establish the old-token commitment and join the genuine target before options.

The options schema is `serverware.oidcSessionActivationRecoveryOptions/v1`.
The existing `unavailable(local_digest=None)` remains unchanged for options:
fixed status `recovery-unavailable`, unknown dispatch/session states and
`automaticRetryAllowed:false`.

Dispatch failure projections use the same
`serverware.oidcSessionActivationRecoveryFailure/v1` schema and exact purpose,
optional validated local digest, unknown session state and no-retry field:

| Helper | Status | Dispatch state and required handler boundary |
| --- | --- | --- |
| `rejected_before_dispatch` | `recovery-rejected-before-dispatch` | `not-started`: selected only before this request enters private recovery acquisition |
| `outcome_unknown` | `recovery-outcome-unknown` | `unknown`: any failure after the conservative acquisition boundary, even before the first socket |

Neither says `activationExecuted:false`, noncommit or that earlier activation,
SQL or WebAuthn challenge/counter effects were absent. No failure projection
sets, clears or replaces a cookie; no exception text or foreign headers enter
the response. The [actual HTTP owner](control-plane-oidc-session-activation-recovery-http.md)
preserves the existing cookie and forbids automatic retry.

`SUCCESS_SCHEMA` names `serverware.oidcSessionActivationRecoveryResponse/v1`;
it is not a success helper or permission. Only the genuine terminal delivery
owner constructs the fixed nonsecret success fields: schema, purpose,
`status:recovered`, `sessionState:active`, `automaticRetryAllowed:false`.
That owner must verify the protected token, freshly authenticate the exact
current target, and retain original guards through known normal cleanup and
the actual signed cookie-send boundary. The contract accepts no token,
identity, successful target DTO or posted root authority to establish those
conditions. Earlier incomplete pre-intent histories remain separate recovery
work; source-only integration is not runtime or production acceptance.
