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

Options forbid `mfa`. The future dispatch carrier permits only optional
`mfa`, whose only fields are an assertion object and/or a bounded `approvalId`.
Parsing an empty or absent assertion grants nothing: the real recovery actor
must require a fresh ceremony when dispatch is implemented. No planning
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
`unavailable(local_digest=None)` returns only fixed failure data with status
`recovery-unavailable`, unknown dispatch/session states and
`automaticRetryAllowed:false`. It never claims `activationExecuted:false`,
noncommit, successful recovery or current authentication. No response helper
sets, clears or replaces a cookie. The source-owned handler must preserve the
pending cookie and distinguish future dispatch uncertainty without granting a
retry. This target-only foundation leaves incomplete pre-intent histories and
full recovery dispatch unresolved.
