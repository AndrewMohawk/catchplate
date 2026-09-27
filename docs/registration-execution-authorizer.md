# Dedicated registration execution-grant authorizer

This source-only service owns the dedicated successor-grant signing key for
`webauthn.registration.evidence.admit`. It is a separate **trusted-host-local**
process, not a generic authority-registry role or an extension of the evidence
signer. The code and packaging are unbuilt and unexecuted; the service templates
are unrendered and uninstalled.

## Permission and original-input boundary

The [registration execution authorization](registration-execution-authorization.md)
must be the original new-purpose caller authorization, authenticated under its
separate root-delegated enrollment. The older enrollment grant remains
evidence-signing-only. A common operation string, an evidence signature, a
planner signature or Unix peer credentials cannot replace caller permission.

The private request carries that authorization original, the complete original
signed verifier/planner planning exchange and the complete before-vector.
Actual original exchange admission derives the request, replay expectations and
raw3 plan; the service does not accept a posted successful replay carrier or
caller-selected expectations. It joins the genuinely replayed request and
operation identities to the authorization before signing an original
[successor execution grant](authority-successor-execution-grant-production.md).
The output is not a reserve, SQL result, pending receipt or successful execution
acknowledgement.

[`authority_registration_execution_exchange._produce_on_configuration`](../serverware/authority_registration_execution_exchange.py)
consumes the original three-frame planning request and four-frame signed
response, before-vector and caller authorization, together with the three
bootstrap-retained enrollment originals. Those 12 original inputs share the
existing 64 MiB source aggregate and cumulative work limits; individual frame
limits still apply. The response is the existing signed grant original, at
most 64 KiB, without a successful-execution or receipt wrapper.

The private [wire exchange](../serverware/authority_registration_execution_transport.py)
sends nine bodies in fixed order: authorization, planning request3, planning
response4 and before-vector. The three enrollment originals come only from the
cold bootstrap, never the request. Lengths are bounded before allocation, one
absolute request deadline covers framing, and trailing bytes or missing EOF
deny. Transport returns unverified original grant bytes. The separate
[opt-in control-plane v3 caller](control-plane-registration-execution.md) now
performs genuine local signature, original authorization, planning and vector
admission through
[`authority_registration_execution_response`](../serverware/authority_registration_execution_response.py)
before returning those unchanged bytes. It does not retry or mint a success
token; present operator/session permission must still precede the private call.

The key admitted by this owner is the dedicated **grant-authorizer** key. The
caller authorization key, planner key and evidence key remain distinct; no
general response/planner/evidence private key is borrowed or loaded as a
fallback. Original configuration, enrollments, public-key scope, runtime-closure
assertion and launch lifetime come from the independently root-signed bootstrap.
Matching those assertions is not fresh measurement, key-provenance proof or
production admission.

The dedicated
[`registration_execution_authorizer_bootstrap`](../serverware/registration_execution_authorizer_bootstrap.py)
uses envelope `serverware.signedRegistrationExecutionAuthorizerBootstrap/v1`,
payload `serverware.registrationExecutionAuthorizerBootstrap/v1` and launch
`serverware.registrationExecutionAuthorizerLaunch/v1`. The bounded original
bootstrap contains the configuration/generation/runtime bindings and original
`currentRootEnrollment`, `grantEnrollment` and `authorizationEnrollment` records.
Each record retains canonical base64url bytes, byte count, raw byte digest and
the distinct framed enrollment identity. Actual enrollment signatures and scope/
key joins remain required; hashing embedded originals is not their admission.
The bootstrap cap is 4 MiB. Its signed `trustMode` is `trusted-host-local`, with
hardware, native-stage-zero, HSM, TEE and external-witness assertions all false.

## Fixed delivery and inventory

The fixed isolated launcher is
`/runtime/authority-bootstrap/registration_execution_authorizer_launcher.py`.
Its only modes are `--root-delivery` and `--run`, under
`/runtime/python/bin/python3 -I` with the fixed `/vendor` and `/app` closure.
Root delivery starts with systemd's single activated listener, then drops
supplementary groups and root IDs/capabilities to UID/GID `65513:65513`.
The process mode is exactly `registration-execution-authorizer`.

The final inherited inventory contains exactly four descriptors:

| FD | Retained material | Fixed source or endpoint |
| --- | --- | --- |
| 198 | Sealed independent root public key, at most 16 KiB | `/run/serverware/registration-execution-trust/root-public-key.pem` |
| 199 | Sealed original signed bootstrap, at most 4 MiB | `/run/serverware/registration-execution-trust/bootstrap.json` |
| 200 | Nonblocking activated Unix stream listener | `/run/serverware/registration-execution/authorizer.sock` |
| 201 | Sealed dedicated authorizer private key, at most 4096 bytes | `/run/secrets/serverware-registration-execution-authorizer-key` |

There is no journal-directory FD, writable custody store, DSN or ambient
key-path fallback. Protected root-owned no-follow originals are retained before
delivery; descriptor collisions or unexpected inherited descriptors deny
startup rather than overwriting or admitting them. The original private key
must be independently provisioned, single-link and mode `0400`.

The rebuilt environment supplies only the fixed root/bootstrap selectors
`SERVERWARE_REGISTRATION_EXECUTION_ROOT_PUBLIC_KEY_FD=198` and
`SERVERWARE_REGISTRATION_EXECUTION_BOOTSTRAP_FD=199`, the process mode and fixed
interpreter settings. The
[startup module](../serverware/registration_execution_authorizer_startup.py)
exposes `initialize_from_environment()`, `require_started()` and `close()`; its
retained singleton owns the listener and `serve_once()` request handler directly.

The socket pathname is owned by `65513:65532`, mode `0660`; accepted clients must
have actual peer UID/GID `65532:65532`. Socket access is not actor/session
authentication. The activated listener's socket-FD identity and filesystem
pathname identity are different objects and must both match the signed launch.
In the reverse direction, the system-manager-created listener's peer identity
is distinct from the accepting nonroot child; a client must still authenticate
the resulting original grant against independently held enrollment/key scope.

Cold startup and every request retain the original process, descriptor and
launch-lifetime checks. Per-request deadlines can only shorten that lifetime.
The signed launch interval is at most 300 seconds and the configured integer
request timeout is 1–30 seconds. A new connection or restart cannot renew an
expired bootstrap or old plan.

## Packaging and remaining deployment work

The [socket](../ops/systemd/serverware-registration-execution-authorizer.socket)
and [service template](../ops/systemd/serverware-registration-execution-authorizer.service.in)
use three explicit placeholders: `@AUTHORIZER_RELEASE_ROOT@`,
`@AUTHORIZER_TRUST_DIR@` and `@AUTHORIZER_KEY_FILE@`. The release root must be an
independently approved complete runtime export, not a source checkout. Trust,
key and activated socket-directory mounts are read-only; there is no writable
journal/store mount. `Type=exec` does not establish readiness. `Restart=no` and
the one-start manager limit are operational controls, not durable launch
authorization or replay prevention. `RuntimeMaxSec=300s` adds a service-manager
runtime cap; the original signed deadline can expire earlier and is never
renewed by that setting. TERM and bounded cgroup escalation are not a hard
syscall watchdog.

[`Dockerfile.production`](../Dockerfile.production) includes the isolated
launcher and templates in the existing verified-source runtime image. The
ordinary package copy includes the service modules. The generic role inventory
and existing authority targets remain unchanged; copying a template does not
install or activate it. New files and their complete interpreter/import/native
closure must be included in the frozen source/image inventory and independently
admitted runtime-closure assertion. Old signatures or measurements do not
automatically cover changed bytes.

The service has no durable one-use ledger. Producing a grant does not create a
reservation, protected execution packet, attempt marker or database effect, and
it does not authorize credential finalization. The separate current-root,
complete-history, protected-custody, one-attempt, SQL and postcommit-completion
requirements remain unchanged. The caller-side private orchestration returns
an unpersisted raw10 original bundle, not a completed registration or durable
grant journal. Present new-purpose caller admission, public-route/UI integration,
independently provisioned accounts/keys/bootstrap/listener, rollback protection, immutable
release admission and consolidated frozen-source verification remain open.

Before the consolidated verification phase, coverage must exercise genuine
request/response/authorization signing and rejection controls; crossed request,
generation and key scopes; malformed or trailing frames; wrong Unix peers;
changed, extra or unsealed inherited descriptors; socket-FD versus pathname
substitution; privilege-drop failure; original-clock expiry/rollback; request
failure and shutdown cleanup; and absence of grant output after failed
admission. Those checks have not been executed for this source checkpoint.
