# Cold enrollment issuer startup

Source `.130`; implementation only, unbuilt and unexecuted. This implements
protected trusted-host-local key delivery and a private grant issuer. It does
not provision services, establish Nitro/KMS custody, or connect public
registration to the independent signer and successor execution. The private
[signer exchange](registration-evidence-signer-exchange.md) is implemented
separately, including its [dedicated cold launch](registration-evidence-signer-startup.md).
Actual deployment provisioning and public orchestration remain open.

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
