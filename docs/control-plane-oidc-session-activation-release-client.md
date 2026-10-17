# Configured private release caller

[`control_plane_oidc_session_activation_release_client.py`](../catchplate/control_plane_oidc_session_activation_release_client.py)
connects the actual cold control-plane owner to one private release exchange
and [independent original response verification](oidc-session-activation-release-response.md).
Its only successful result is the verified raw 64-byte token. This is authored
source, not build, runtime, provisioning or production evidence.

## Actual owner and explicit configuration

The actual `_EnrollmentOwner` exposes the private method
`_request_oidc_session_activation_release(request_originals=..., live_window=...,
transport_deadline_ns=..., work=...)`. Under its existing lock it delegates to
`_request_on_owner` with those exact keywords. No new freely constructible
successful owner, generic authority dispatch or public route is substituted.

Only the explicit root-signed
[v5 release configuration](control-plane-oidc-session-activation-release-bootstrap.md)
enables the lane. Its nested immutable material holds the client-authorization
original, server-bootstrap original and canonical independently configured
scope17 bytes. Older profiles and explicit null stay disabled. Cold mapping is
not current permission: the request path genuinely authenticates both originals
under its supplied original allowance before any socket call.

The binding must be the actual control-plane custody owner at UID/GID 65532
and process mode `catchplate-control-plane`. The component checks the same PID,
owner/global state, environment, custody binding, root public key, nested
configuration identity, original runtime receipt and existing sealed-descriptor
identities throughout its operation. It calls the actual metadata-only
`_continuity`, not the other purpose's HTTP signing-key loader. No issuer,
execution or finalization key is required or borrowed; existing descriptors
remain owned by their original components. The private socket needs no relaxed
inherited-FD allowlist.

## One bounded exchange

The owner-local spent flag changes irreversibly before input holding or
admission. All immutable raw7/raw8 originals, actual owner/key references,
configured scope bytes and the supplied clock pair are held before callbacks.
The complete request plus configured originals and the maximum raw2 response
and both headers fit the fixed aggregate bound before admission or connection.
The same cumulative work object is used for capture, public verification,
durable claim, network I/O and receiving verification.

The caller preserves the supplied clock opening and only narrows its window
and deadline to the original runtime receipt and actual client/server limits.
It recomputes the exact request identity and compares the independently root-
configured pin. The endpoint and live/recovery profile come from that same
genuinely admitted configuration, never request-selected policy.

Before any socket, the actual custody owner performs
`claim_oidc_session_activation_release`, a dedicated nonforwardable
[token-free durable claim](control-plane-oidc-session-activation-release-attempt.md).
Its key is the exact client-authorization digest; metadata also binds source,
request identity, profile, server-bootstrap identity and expected outcome.
The fixed encoding/publication/readback work is charged before the native
callback. Existing claims reject even byte-identical reuse after restart;
uncertain publication cannot authorize a send. No old/new token, raw7/raw8,
raw2, proof body or plaintext-bearing exception is appended to the journal.

After successful normal-close claim publication, the caller invokes the actual
transport exactly once, directly rather than inside a metrics-constant callback.
The actual owner guard runs through every network chunk and client normal close.
Returned originals then go through the actual response verifier: public client
and server originals are reauthenticated rather than accepting preflight success
as authority; intent and proof originals are admitted once in that receiving
pass. Recovery remains separately root-authorized historical evidence, not
automatic fallback from a failed live request.

The receiver and actual owner exchange only increasing epoch/monotonic floors
through a private restrictive continuity seam. This retains observations made
inside verification through the final original intent/proof/client and actual
owner guards. Returned floors must remain below the receiver's current narrowed
epoch and monotonic deadlines. The caller tail-returns the genuine verifier's
token bytes, with no weaker native suffix or successful-result carrier after
those final checks. The seam cannot reset work, renew the clock pair or bypass
original admission. The actual startup continuity helper also returns its
existing receipt sample so that observation is not discarded between descriptor
checks and later clock checks.

## Terminal uncertainty and limits

Any failure is terminal for this owner's release lane. If the durable claim
has begun, it is preserved; there is no deletion, replacement, automatic retry,
second socket, token regeneration or recovery-profile selection. Only a
separately root-issued, explicitly configured new authorization has a different
claim identity and may permit another exchange, including deliberately
authorized recovery under its own still-valid constraints. This is not a
restart retry with the old grant, nor hostile-host rollback protection.

Transport alone owns and closes its newly created client socket. This lane does
not close borrowed bootstrap, custody-journal or other-purpose key descriptors.
Failure after a partial send or receive does not prove non-delivery or rollback;
normal-close uncertainty withholds the result while preserving the claim.

No token is persisted by this caller, and callers must not log request/response
frames or returned plaintext. A verified token commitment is not evidence of
server execution, store fsync, single egress, recipient acknowledgment or current
session state. This private configured handoff does not supply public
permission, CSRF/session admission, public routes or portal integration. All
independent production gates remain separate and unverified.
