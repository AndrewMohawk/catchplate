# Cold enrollment issuer startup

Source `.130`; implementation only, unbuilt and unexecuted. This implements
protected trusted-host-local key delivery and a private grant issuer. It does
not provision services, establish Nitro/KMS custody, or connect public
registration to the independent signer and successor execution. The private
[signer exchange](registration-evidence-signer-exchange.md) is implemented
separately, including its [dedicated cold launch](registration-evidence-signer-startup.md).
Actual deployment provisioning and public orchestration remain open.

## Private release client extension

Source `.180` adds an explicit [v5 public-only release configuration](control-plane-oidc-session-activation-release-bootstrap.md)
and a [one-use private caller](control-plane-oidc-session-activation-release-client.md).
The original v2 issuer contract below remains unchanged; v3/v4 execution and
finalization retain their existing fields and reserved key slots. Explicit v5
through v7 can configure this release lane, including when the separate issuer is disabled.
The actual startup owner must run as UID/GID 65532 and keeps the same runtime
root, configuration, original receipt and inherited descriptor identities.
The release component receives no private key and introduces no descriptor.
Other enabled purposes in the same process can still have their own keys.

The private owner method preserves the supplied request work/window, admits
fresh original client/server authority, durably claims token-free dispatch
metadata, performs one fixed exchange and independently verifies the original
response. Failure never clears the spent flag or grants an automatic retry.
The existing continuity check now returns its actual receipt epoch so the
composition can retain that observation; it does not renew the receipt or
load an unrelated HTTP signing key. No public handler or session cookie is wired.

The optional source overlay
[`docker-compose.oidc-session-activation-release.yml`](../docker-compose.oidc-session-activation-release.yml)
adds only a read-only socket-directory bind at the fixed
`/run/serverware/oidc-session-activation-token-release`. Its required host-source
variable is `SERVERWARE_OIDC_SESSION_ACTIVATION_RELEASE_SOCKET_DIR`, with
`create_host_path: false`; it is not a process endpoint override. The separately
provisioned listener has mode 0660 and owner/group `65502:65532`, with searchable
parent directories. A read-only directory bind permits connecting, not replacing
the listener. Actual peer credentials and signed original response admission
remain mandatory. Select this overlay only for an explicitly enabled v5–v10 release lane;
it neither creates the worker/socket nor mounts a release or signing key.
The existing enrollment-only offline preparer is unchanged and does not compose
this overlay. Any separately composed artifact still requires independent
immutable-release admission and frozen verification. No deployment is performed.

## Dedicated activation caller extension

Source `.181` adds the explicit [v6 activation caller configuration](control-plane-oidc-session-activation-execution-bootstrap.md).
The nullable lane is separate from the issuer, registration callers and public-only
release client. The actual root entrypoint delivers only its fixed, independently
inventoried FD205 from the provisioned activation caller-key path. Null v6 rejects
that slot even when it is open but absent from the inventory; v2–v5 remain unchanged.

Startup authenticates the original parent and three enrollment originals, reads
the sealed Ed25519 key, checks the actual enrolled pair, and rejects reuse of the
HTTP response, issuer, registration execution or finalization keys. This works
with a disabled issuer; no other purpose supplies a fallback key. The actual
owner retains the dedicated key/FD/identity and checks the same process, runtime
receipt and descriptor continuity. Shutdown drops its key and permission-context
references without closing borrowed inherited descriptors.

`activation_execution_enabled` describes configuration, not present permission.
The private `_oidc_session_activation_permission` wrapper forwards the actual
request and permission bytes with the original work/window/deadline to the
lock-owned activation context. Fresh target permission precedes planning, and
the context's post-plan signer is revoked on exit. No public permission-success
object, renewed allowance, automatic grant dispatch or protected mutation is
created by this cold configuration. Step 21's permission/signing source is
landed separately; configuration alone is neither permission nor deployment.

## Post-permission planner extension

Source `.182` adds explicit v7 planning configuration without another key or
descriptor. The actual parent retains a root-signed planner bootstrap and a
fixed planner endpoint; the activation caller lane must also be enabled.
Older parent versions remain strict and do not acquire this new capability.

The private `_prepare_oidc_session_activation_authorization` method first holds
bounded immutable session-binding assertion bytes and the expected challenge
identifier. It then enters genuine permission on the actual request and
original work/window, makes the one-use durable pre-planner claim, and obtains
and signs the exact post-permission plan. The session-binding assertion is
distinct from the permission assertion. Existing
`/api/auth/session/webauthn/options` supplies its unused challenge; the
permission assertion must precede it in authenticator-counter order.
Returned originals are not reusable permission or evidence of SQL execution.

The optional
[`docker-compose.oidc-session-activation-planning.yml`](../docker-compose.oidc-session-activation-planning.yml)
overlay adds only a read-only, `create_host_path: false` socket-directory bind
at `/run/serverware/oidc-session-activation`. Its required source variable is
`SERVERWARE_OIDC_SESSION_ACTIVATION_PLANNER_SOCKET_DIR`. Combine it with the
separately enabled activation-execution custody overlay. The bootstrap stays
in the existing authority-trust mount; no planner, key, socket or production
infrastructure is provisioned. The enrollment-only offline preparer is unchanged.

This is partial step 22: the public dispatch route and complete
grant/reservation/SQL/completion/consume/release composition are still open.
No new public response or session cookie is emitted by this private method.
Current source is unbuilt and unexecuted; production acceptance remains 0/6.

## Private downstream dispatch extension

Source `.183` adds the private `_dispatch_oidc_session_activation` composition
under explicit nested activation-execution v2. It retains the same actual
request, bounded distinct assertion/challenge inputs, owner, cumulative work
and original processing window. Permission, planning, grant and reservation
remain inside the actual context before the one irreversible SQL-dispatch
boundary. Dedicated durable original records precede each downstream stage;
an existing claim cannot become permission to repeat it after restart.

The SQL boundary must stop checking the deliberately changed pending row
without dropping actual owner/key/receipt, exact original authority, deadline
or clock-skew continuity. The returned original raw4 is only an unsigned SQL
observation, not authenticated completion, released credentials or an active
session. No public route or cookie transition is added by this private method.
Completion/consume/release receiving and public dispatch remain in step 22;
independently authorized recovery and portal work retain their separate scope.

## Original-bound completion continuation

Source `.184` adds the private actual-owner facade
`_dispatch_oidc_session_activation_completion(*, request, permission_bytes,
assertion_bytes, expected_challenge_id, live_window, transport_deadline_ns, work)`.
It accepts the same original inputs as `_dispatch_oidc_session_activation`,
enters the same genuine permission context, and returns only the exact pair
`(sql_raw4, completion_raw4)`. No successful permission, SQL or completion DTO
is accepted as authority. The original work, window, sticky clock observations
and narrowed deadline remain held through the continuation.

This path requires explicit nested [execution/v3](control-plane-oidc-session-activation-execution-bootstrap.md#explicit-completion-endpoint-profile)
and an independently provisioned completion service with its new launch/v2
profile. Older caller and service profiles do not silently opt in. The caller
sends its exact signed authorization original; the service byte-joins that
original to its independently root-held authorization and chooses its own
root-pinned packet. There are no additional caller keys or FDs and no history,
AES or service-signing keys move into the control-plane process.

The SQL raw4 remains an unsigned observation. Completion raw4 is durably
retained in the sole remaining [activation stage slot](control-plane-oidc-session-activation-records.md)
before branch, digest or signature interpretation. Genuine public original
control checks can authenticate the signed complete request and state ACK
against the exact admitted grant/reservation; they do not replace the service's
private replay/commit admission or establish present currentness. Neither pair
return nor missing response releases a token, updates a cookie or permits
another SQL/completion send. Recovery requires separate authority.

No new completion overlay is needed: the existing
[`docker-compose.oidc-session-activation-planning.yml`](../docker-compose.oidc-session-activation-planning.yml)
mount already exposes the fixed `/run/serverware/oidc-session-activation`
directory read-only, with `create_host_path: false`. Its preprovisioned host
directory must contain the authorized `completion.sock` as well as the planner
listener. The endpoint remains fixed; the environment variable is only the
mount source, not an endpoint override. This source change creates no directory,
socket, key or service, activates nothing, and changes no live deployment.
Public dispatch, consume/release continuation and the cookie boundary remain
open; source is unbuilt/unexecuted and production acceptance stays 0/6.

## Same-context consume preparation

Source `.185` adds `_prepare_oidc_session_activation_consume(*,
planner_bootstrap_bytes, history_custody_bytes)`, under explicit nested
[execution/v4](control-plane-oidc-session-activation-execution-bootstrap.md#explicit-consume-planner-endpoint-profile).
It selects only this owner's actual active permission. The permission must
still hold the same acknowledged completion, original target, work, clock
window and dispatcher guards. The result is `(prepared_raw6, exported_raw7)`;
no completion DTO, new request context or execution permission is accepted.

This facade cannot be called after `_dispatch_oidc_session_activation_completion`
returns: that convenience method closes its context on return. A future public
composition must keep the original context alive through completion, independent
per-request root-original delivery and consume preparation. Reopening permission
or passing a retained result cannot substitute for that same call. The root
issuance and matching cold services are not provisioned by this method.

The [consume continuation](control-plane-oidc-session-activation-consume-planning.md)
retains only token-free control originals in a separate counted custody claim;
the original old cookie is used only for the bounded private prepare exchange.
This remains partial RELEASE integration, not consume execution, protected
handoff, a public route, cookie issuance or current-session confirmation.

## Dedicated consume caller extension

Source `.186` adds explicit parent enrollment `/v8` with nullable
[`oidcSessionActivationConsumeExecution`](control-plane-oidc-session-activation-consume-execution-bootstrap.md).
It independently reserves FD206, including when the consume lane is null.
Earlier parent versions retain their existing descriptor semantics. The lane
requires the actual activation caller and planner configuration; it does not
reuse the activation caller key or make a completed response into permission.

Startup authenticates the original parent and consume-only enrollments before
reading the separately inventoried, sealed Ed25519 PKCS8 key. It checks the
actual enrolled pair and separates it from the HTTP response, issuer,
registration, finalization and activation keys. The same parent owner retains
`_consume_key`, `_consume_key_fd` and `_consume_key_identity`; every existing
owner-continuity check now includes that descriptor. Null v8 rejects both an
inherited FD206 and an open-but-undeclared FD206. Shutdown drops its key reference
without closing the borrowed descriptor or claiming memory erasure.

`consume_execution_enabled` describes cold configuration only. The private
`_authorize_oidc_session_activation_consume()` facade takes no inputs and selects
only this owner's actual active permission context. Its
[one-use authorization continuation](control-plane-oidc-session-activation-consume-authorization.md)
uses the same call's prepared/exported originals and original processing bounds,
retains the signed authorization before return, and cannot reopen an escaped
context. It grants no automatic grant dispatch, SQL, token release or retry.

Explicit nested consume execution `/v2` additionally admits fixed reservation
and SQL endpoints and an independently root-configured predecessor scope.
The `/v1` lane remains authorization-only. The private no-argument
`_dispatch_oidc_session_activation_consume()` facade selects only this owner's
actual still-active, consume-authorized permission and its one-use dispatch
continuation. It accepts no returned record, successful result, replacement
window or work ledger. The [consume dispatcher](control-plane-oidc-session-activation-consume-dispatch.md)
must authenticate and durably retain the actual grant/reserve originals and
claim the SQL attempt before I/O; its unsigned SQL result is not completion,
token release or present session authority.

Explicit nested consume execution `/v3` additionally admits the fixed completion
endpoint. The no-argument `_complete_oidc_session_activation_consume()` facade
selects the same actual consume-dispatched context; it neither takes a SQL
result/packet locator nor reopens an expired permission. The
[consume completion continuation](control-plane-oidc-session-activation-consume-completion.md)
uses the original signed caller authorization with the service's explicit
launch `/v2` dispatch profile, retains the exact raw4 response before
interpretation, and authenticates public signed completion/state controls
against the original consume grant/reserve/snapshot/ACK. The service keeps its
own root-pinned packet and private custody. Completion uncertainty is not
noncommit, current session state, protected token release or retry permission.

The optional
[`docker-compose.oidc-session-activation-consume-execution.yml`](../docker-compose.oidc-session-activation-consume-execution.yml)
source overlay adds a read-only key bind at
`/run/secrets/serverware-oidc-session-activation-consume-caller-key` and a
read-only socket-directory bind at
`/run/serverware/oidc-session-activation-delivery-execution`. The required host
inputs are `SERVERWARE_OIDC_SESSION_ACTIVATION_CONSUME_CALLER_KEY_FILE` and
`SERVERWARE_OIDC_SESSION_ACTIVATION_CONSUME_EXECUTION_SOCKET_DIR`; both reject
automatic host-path creation. They are packaging inputs, not runtime path
overrides. No key, listener, account or infrastructure is created. The same
directory bind covers the independently provisioned authorizer, reserver, SQL
and completion sockets; mounting it does not authorize or perform a request.
The enrollment-only offline preparer is unchanged. Source remains unbuilt and
unexecuted, and production acceptance remains 0/6.

## Private proof continuation extension

Explicit parent `/v10` adds nullable public-only
[`oidcSessionActivationReleaseProof`](control-plane-oidc-session-activation-release-proof.md).
It admits the distinct proof enrollment, independently held producer scope and
fixed endpoint, and requires the actual parent release-intent configuration.
The root delivery projection has the same ten slots as v9; no proof private key
is delivered to the control plane. Older parent schemas retain their exact shapes.

`release_proof_enabled` is configuration only. The no-argument
`_prove_oidc_session_activation_release()` facade uses only the actual active
permission after its retained signed intent. Its irreversible durable claim
precedes transport, opaque raw4 retention precedes semantic admission, and
genuine root custody/proof verification preserves the original allowance.
The new worker is separately provisioned after intent; no new token or cookie
is released by this continuation. Source remains unbuilt and unexecuted.

## Dedicated release-intent caller extension

Explicit parent `/v9` adds nullable
[`oidcSessionActivationReleaseIntent`](control-plane-oidc-session-activation-release-intent-bootstrap.md)
and reserves FD207 even when null. Its closed four-field configuration holds a
genuine intent enrollment and independently root-pinned scope6, not a future
release target, packet digest, intent digest or outcome. It requires consume
execution `/v4`, whose unchanged v3 field set selects only the separate
release-hint response profile through immutable `release_hints=True`.
Earlier versions retain false and their existing wire behavior.

The actual stdlib delivery reads the fixed root-owned mode0400
`/run/secrets/serverware-oidc-session-activation-release-intent-key` into the
separate sealed slot. Startup requires its signed runtime inventory entry,
genuine enrolled Ed25519 pair, original PKCS8 bytes and separation from the
actual HTTP and other retained signing purposes. It precharges the admitted
byte length before reading that key, retains descriptor/receipt continuity in
`_intent_key`, `_intent_key_fd`, and `_intent_key_identity`, and drops the key
reference on shutdown. Null v9 rejects both inherited and undeclared-open
FD207. No issuer key is borrowed, including with a disabled issuer policy.

`release_intent_enabled` reports configuration only. The no-argument
`_authorize_oidc_session_activation_release_intent()` facade selects only this
owner's actual active permission and calls `authorize_release_intent()`; no
posted target, successful result carrier, new allowance or retry enters there.
The coordinator must preserve the original work/window and old-token binding.
Unsigned completion hints are candidate digests: later private proof admission
must independently reconstruct and verify them. Neither the hint nor the
intent grants committed-consumption, token-return, cookie or current-session
authority. This source remains unbuilt and unexecuted.

## Decision and trust boundary

The runtime root has one additional, explicitly domain-separated bootstrap
purpose. Reusing that independently admitted root avoids a second ambient trust
loader after custody startup has opened private descriptors. It does not reuse
the root as an online enrollment signer: enrollment has its own configured key.
The original runtime root and exact inherited-FD inventory are retained in the
existing frozen custody binding; they are never re-read from environment paths.

```text
independent provisioner
    -> root-signed enrollment bootstrap + dedicated issuer key
    -> root entrypoint: fixed files -> sealed inherited descriptors
    -> custody startup: actual runtime-root + exact inherited-FD admission
    -> enrollment startup: same root verifies bootstrap -> key/policy pairing
    -> application startup: require both original live owners
    -> private issuance: original browser inputs + prior authenticated admission
```

The last step is available as `owner.issue_registration(...)`. Its raw input
carrier is not proof of authentication. Only a future continuation of the actual
authenticated operator/OIDC handlers may call it. Current public handlers still
use legacy finalization; no grant is generated and discarded along that path.

## Independently provisioned inputs

| Input | Fixed container location or requirement |
| --- | --- |
| Signed bootstrap | `/run/serverware/authority-trust/control-plane-enrollment.json` |
| Enabled issuer private key | `/run/secrets/serverware-control-plane-enrollment-signing-key` |
| Existing response key | Actual configured `response_identity.RESPONSE_SIGNING_KEY_PATH`, read-only admission |
| Runtime trust inventory | Already includes the retained bootstrap FD and, when enabled, exact issuer-key FD |

The bootstrap is mandatory for the root control-plane entrypoint, including an
explicitly disabled policy. Its original canonical ASCII JSON is at most 4 MiB.
The envelope has exactly `schema`, `payload`, `signatureBase64Url`; its schema is
`serverware.signedControlPlaneEnrollmentBootstrap/v2`. The payload has exactly eight fields:

- `schema`: `serverware.controlPlaneEnrollmentBootstrap/v2`.
- `sourceRevision`: the current authority source revision.
- `configurationDigest`: the configuration already admitted by runtime trust.
- `configurationPayload`: the actual signed authority-service configuration.
- `generation`: the nine shared generation-binding fields, not arbitrary launch extras.
- `runtimeRoleIdentities`: the matching configured runtime cohort.
- `issuerPrivateKeyFd`: null when enrollment is disabled; otherwise an exact integer 32..1023.
- `signerEndpoint`: null when enrollment is disabled; otherwise the closed endpoint below.

The enabled endpoint has exactly `socketPath`, `requestTimeoutSeconds`,
`listenerUid`, and `listenerGid`. Its path is fixed to
`/run/serverware/registration-evidence/signer.sock`, its finite timeout is
0.05–30 seconds, and its observed listener UID/GID is exactly `0:0`. The runtime
material exposes only the immutable `(path, timeout, uid, gid)` tuple; no browser
parameter, environment endpoint or fallback can select another destination.

The endpoint pins the system-manager-created activated listener, whose Unix
peer credentials reflect the identity at `listen()`. It does not identify the
accepting child: the signer process still runs as `65517:65517`, the socket path
owner/group remains `65517:65532`, and incoming control-plane peers must be
`65532:65532`. Genuine response evidence verification against the dedicated
policy key and signer identity remains mandatory; root listener credentials
alone are not signer attestation or evidence authority.

This mandatory endpoint authority advances both bootstrap schemas to v2 rather
than changing v1's closed payload. The current `sourceRevision` check remains
mandatory too; v1 originals are not silently upgraded or accepted. The private
producer requires an explicit `signer_endpoint` object or null, with no default.

The signature message is the ASCII framed digest of the canonical payload under
the dedicated envelope schema. This deliberately differs from the existing
runtime-trust document's signature protocol. The private producer
`control_plane_enrollment_bootstrap._produce_on_work` performs genuine paired
root signing and returns original bytes; it creates no keys, files or FD slots.
The receiver authenticates the original statement before admitting its policy,
configuration, runtime identities, key descriptor or signer endpoint. Finite fractional timeout
values retain the real configuration's canonical encoding.

The enabled private key must already be root-owned, single-link, mode 0400,
regular, no-follow, 1..4096 bytes, and unencrypted Ed25519 PKCS8 PEM. Fixed
ancestors are opened without symlinks and must be root-owned and nonwritable by
group/other. Delivery reserves only the declared free FD; any collision fails,
including with an unlisted open descriptor. It neither overwrites another FD
nor substitutes a different slot. Seal/shrink/grow/write seals are mandatory.

For enabled enrollment, the optional source overlay
[`docker-compose.enrollment.yml`](../docker-compose.enrollment.yml) adds exactly
two read-only binds to the production service: the key at
`/run/secrets/serverware-control-plane-enrollment-signing-key`, and the socket
directory at `/run/serverware/registration-evidence`. Their required, nonempty
host-source variables are `SERVERWARE_CONTROL_PLANE_ENROLLMENT_SIGNING_KEY_FILE`
and `SERVERWARE_REGISTRATION_EVIDENCE_SOCKET_DIR`; both mounts set
`create_host_path: false`. These are Compose host-source interpolation, not
process key-path or endpoint overrides. The root-signed endpoint remains fixed.
The existing Linux Unix socket can be connected through a read-only directory
bind: its mode 0660 and owner/group `65517:65532` permit the control-plane group
`65532`, provided the directory is searchable. The bind does not create, replace
or admit the socket, and genuine peer/key/receipt checks remain required.
Select the overlay only with an enabled policy; disabled policy adds neither
mount and needs no dummy key or socket directory. The bootstrap uses the existing
authority-trust directory mount. The
readiness runner retains its single-Compose-file contract. The new
[offline preparer](enrollment-compose-preparation.md) can compose one standalone
artifact from the fixed base and enabled overlay after actual signed-bootstrap
admission. That artifact still needs independent immutable release enrollment;
preparing or mounting it alone is not release acceptance.

## Startup, issuance and shutdown

The root entrypoint clears every incoming `SERVERWARE_CONTROL_PLANE_ENROLLMENT_*`
setting and supplies only `SERVERWARE_CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_FD`.
The bootstrap FD is canonical decimal 3..1023. Both bootstrap and key must be in
the original root-admitted inventory; delivery never edits that signed inventory.

The runner initializes custody first, then enrollment, before importing the
application/server. Enrollment verifies the root statement, actual policy and
key pair. It compares the real existing HTTP response key and rejects reuse.
It never invokes the response-key generator or public-identity publisher.
Enabled lifetime checks re-read the actual response key and reject key/path
drift; rotation requires fresh cold admission. ASGI startup requires both owners
before initialization and again before starting workers.

The owner is singleton and PID/UID/GID/environment-bound. Only genuinely
unconfigured development may opt out. A signed null policy produces an explicit
disabled owner whose issuance always denies and whose signer endpoint is absent.
Failure or shutdown cannot trigger
in-process reinitialization; borrowed inherited FDs are never closed or mutated
by this owner. The runner closes enrollment before custody on return or failure.

Issuance owns the original browser inputs, ceremony authorization and configured
graphs before callbacks. RP/origin must match the admitted configuration; user,
label, challenge and optional OIDC session come from those original inputs,
not parallel overrides. The original UTC evaluation time is preserved. Grant
deadline is capped at the original runtime-attestation expiry, and receipt/key
continuity is checked before and after issuance on the request's existing work.

Public orchestration, replay-store
rollback/capacity operations, current-root business execution, deployed key/service
provisioning and consolidated frozen verification remain unfinished. See the
[enrollment decision](enrollment-authorization-decision.md) for issuer-compromise
trade-offs and the distinct grant/source/evidence lifetimes.
