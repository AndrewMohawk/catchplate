# Cold finalization execution-grant authorizer

The dedicated `registration-finalization-authorizer` process composes genuine
finalization authorization, newly planned custody raw7 and the complete
before-vector into one original signed execution grant. It is separate from
the evidence-admission authorizer and from the control-plane finalization
caller. This is source-only, unbuilt, unexecuted and unprovisioned; no unit has
been rendered or installed and no production acceptance is claimed.

## Fixed process and private resources

| Resource | Fixed contract |
| --- | --- |
| Service UID/GID | `65511:65511`; no supplementary groups or retained capabilities |
| Request peer | Actual Unix peer `65532:65532`, before reading bodies |
| Root/bootstrap FDs | Sealed originals `198` / `199` |
| Listener/key FDs | Activated listener `200` / sealed grant-authorizer key `201` |
| Socket | `/run/serverware/registration-finalization-authorizer.sock` |
| Root/bootstrap paths | `/run/serverware/registration-finalization-trust/root-public-key.pem` and `bootstrap.json` |
| Private key source | `/run/secrets/serverware-registration-finalization-authorizer-key` |
| Runtime launcher | `/runtime/authority-bootstrap/registration_finalization_authorizer_launcher.py` |

The independently root-signed bootstrap uses
`serverware.signedRegistrationFinalizationAuthorizerBootstrap/v1`, payload
`serverware.registrationFinalizationAuthorizerBootstrap/v1`, and launch
`serverware.registrationFinalizationAuthorizerLaunch/v1`. The closed payload
holds original signed configuration/generation/runtime scope, current-root,
grant and **finalization caller** enrollment originals, their exact byte/domain
identities, database/generation, dedicated authorizer SPKI/measurement and
runtime-closure pins. Each enrollment record is exactly
`base64Url`, `byteCount`, `bytesDigest`, `identityDigest`.

Launch fixes the process, UID/GID/peer, four descriptors, socket path, both socket
FD and pathname device/inode pairs, and integer request timeout `1..30` seconds.
The bounded bootstrap is at most 4 MiB and its original lifetime is at most
300 seconds. `trustMode` is `trusted-host-local`; hardware, native-stage-zero,
HSM, TEE and external-witness assurance fields must all be false. These signed
claims require independent root admission; they do not measure an executable
or establish a live witness themselves.

## Admission before key access

The [bootstrap verifier](../serverware/registration_finalization_authorizer_bootstrap.py)
authenticates the actual root signature and canonical original, then uses the
real finalization transition configuration mapper and original enrollment
admissions. The planner and operation evidence key come from the configured
finalization transition policy, not an evidence-only role fallback. Grant key
pairing and separation exclude root/current-root authority keys, caller keys,
configured role keys, enrollment issuer and enabled evidence/transition keys.
The dedicated service UID/GID cannot alias configured roles. Independent
provisioning must also prevent key reuse across separately provisioned services.

Root [delivery](../serverware/registration_finalization_authorizer_entrypoint.py)
opens only fixed no-follow paths through protected root-owned ancestors,
authenticates bootstrap and listener identities **before** accessing the key,
seals original files, reserves the exact inherited inventory and permanently
drops identity. The private key is bounded root-owned mode `0400`, unencrypted
Ed25519 PKCS8 PEM; it is never a caller-provided path or request body.
The root-activated socket's kernel server peer remains `0:0`, although its
pathname is `65511:65532` mode `0660`; these are different identities.

The [cold startup owner](../serverware/registration_finalization_authorizer_startup.py)
repeats genuine bootstrap admission before loading the sealed key, checks its
actual pair with the enrolled grant authorizer, and owns a private duplicated
listener. PID, exact eight-entry delivered environment, empty supplementary
groups, unprivileged state, all sealed identities, listener/path identity and
descriptor inventory are rechecked through its original lifetime. Fork,
identity drift, rollback or expiry is terminal, not a singleton restart.

## One original exchange per connection

The [transport](../serverware/authority_registration_finalization_transport.py)
uses `SWRFGQ01` / `SWRFGR01`: request raw9 is original caller authorization,
custody raw7 and complete before-vector; the response is one original grant.
All individual limits, the complete length vector, 64 MiB aggregate and exact
EOF remain mandatory. The response is at most 64 KiB. Enrollments/configuration
come only from the authenticated cold bootstrap, never the request.

The serial owner admits the actual peer before reading bodies. One request work
allowance and live window open before body intake; the absolute timeout begins
before peer admission and is clipped to the original bootstrap deadline. Body
intake, [genuine grant production](registration-finalization-grant-production.md),
response send and final checks do not reopen it. Producer checks authenticate
the finalization purpose before custody replay, require plan issue at/after
authorization and expiry within it, and genuinely replay raw4 plus the complete
before-vector before signing. Receivers must still authenticate the returned
grant and its original live bounds. No copied verdict, evidence raw3 or posted
expectations can choose successful claims.

`initialize_from_environment`, `require_started`, `close` and owner `serve_once`
are the cold lifecycle APIs. The fixed [launcher](../serverware/registration_finalization_authorizer_launcher.py)
supports only `--root-delivery` / `--run`; the [runner](../serverware/registration_finalization_authorizer_runner.py)
serves serially until stop or original lifetime failure. Request denial does not
renew the launch. There is no request replay database, durable grant journal,
one-use guarantee, automatic resend or successful-outcome wrapper. Cooperative
signals and service timeouts are not hard kernel watchdogs.

## Packaging and remaining boundaries

The uninstalled [socket unit](../ops/systemd/serverware-registration-finalization-authorizer.socket)
and [service template](../ops/systemd/serverware-registration-finalization-authorizer.service.in)
are review inputs only. The template requires separately admitted
`@AUTHORIZER_RELEASE_ROOT@`, `@AUTHORIZER_TRUST_DIR@` and
`@AUTHORIZER_KEY_FILE@`, preserves only fixed read-only mounts, grants no writable
journal and uses `Restart=no`. Root activation, account/group access and signed
socket identities must be independently prepared; replacing the listener needs
new original admission, not inferred identity from its path.

`Dockerfile.production` now includes the package modules, the explicit fixed
launcher COPY/read-only permission entry, and both unit-inventory COPY entries.
This source packaging has not been built, rendered or installed. Frozen closure
inventory and consolidated verification must still establish the actual runtime
and cover the new process and installed originals; source COPY entries are not
release admission.

The service issues grants only. Current-root reservation, one-use execution
custody, atomic credential finalization, completion/outcome handling and
separate OIDC browser-session activation are not performed here. Present-caller
permission, independent service/key provisioning and production release gates
remain separate; source integration is not deployment authority.
