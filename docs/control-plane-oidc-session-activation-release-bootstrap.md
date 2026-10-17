# Control-plane release configuration

The explicit root-signed control-plane enrollment bootstrap v5 adds the nullable
`oidcSessionActivationRelease` field. Versions v2–v4 keep their closed schemas
and behavior. The outer original remains capped at 4 MiB, uses its distinct v5
signature domain, and preserves the existing finalization FD204 reservation.
No release key or additional descriptor is introduced.

The isolated, stdlib-only `authority_fd_entrypoint` explicitly recognizes v5
and checks its closed public-data shape before optional existing-purpose key
delivery. It preserves the same three old slot projections and the v4/v5
FD204 reservation even when finalization is null. Release configuration adds
no slot or key; no repository crypto is imported into this selector. Original
root ownership, seals, 4 MiB intake, and exact canonical outer JSON checks stay
in place. Actual root authentication still belongs to child startup admission.

The non-null nested `catchplate.controlPlaneOidcSessionActivationRelease/v1`
object has exactly `schema`, `clientAuthorization`, `serverBootstrap`, and
`expectedScope`. Each public original is transported as canonical base64url
with an exact `byteCount`; the independent expected scope is the existing closed
17-field [release-client scope](oidc-session-activation-release-client-authorization.md).
Its exact request identity, target, profile, endpoint, caller, producer, receipt,
and expected outcome are root-selected, not learned from a response.

The unchanged outer bound applies to the entire configuration and encoded
originals together. A server bootstrap that fits its standalone 16 MiB limit
can still be too large to embed in this 4 MiB parent. There is no alternate
path, extra-FD fallback, or relaxed parser for that case.

`control_plane_oidc_session_activation_release_bootstrap._admit_on_work` owns
all input graphs before hashing, checks the actual parent configuration and
generation, and joins the client payload and exact server-original digest to
the independently held scope. Server shape, canonical bytes, and common scope
fields are checked as data. The root-signed v5 parent authenticates this cold
configuration; this step does **not** admit nested signatures or freshness.

The result is private `_ReleaseClientMaterial` with only three immutable byte
fields: `client_authorization_bytes`, `server_bootstrap_bytes`, and canonical
`expected_scope_bytes`. `_EnrollmentMaterial.release_client` defaults to `None`;
the nullable lane does not require an enrollment issuer policy or borrow its
key. `_scope_on_work` reads the retained scope as data, not authority.

There is no control-plane measurement role in the existing five-role authority
cohort. The client ID and identity are explicit trusted-host-local root pins,
not a relabeled planner, verifier, or issuer identity. Configuration and
generation join the actual parent graph. Runtime closure joins the original
client/server scope; it is not invented as a control-plane measurement claim.
Actual parent PID, UID/GID, runtime binding, and receipt continuity remain the
responsibility of the real control-plane owner at use.

The actual request path must freshly authenticate the retained client and
server originals under its supplied, nonrenewing work/window/deadline before
transport, and independently verify the response. Cold configuration does not
create a fresh processing window or renew expired authority. The private v5
producer signs only this configured-data statement with the actual root pair;
it is not a release endpoint or proof of outcome durability.

This is source-only configuration support: no provisioning, execution,
deployment, public token delivery, or current-session result is established.
