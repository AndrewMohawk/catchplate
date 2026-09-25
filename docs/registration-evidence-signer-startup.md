# Dedicated registration evidence signer startup

The `.129` source adds a separate **trusted-host-local** cold-start path for
the registration evidence signer. It is unbuilt and unexecuted; the service
templates are unrendered and uninstalled. Source composition is not a startup,
production-readiness, native-measurement or TEE result.

## Receipt and configuration order

An independent provisioner first root-signs the dedicated, configuration-independent
receipt. That receipt omits configuration-digest and bootstrap commitments. The
final registration evidence policy pins the framed identity of those original
receipt bytes in its signer identity. A separate signed bootstrap then binds the
final configuration bytes/digest, generation, runtime-role identities, original
receipt and fixed launch contract. This order avoids a receipt/configuration
fixed point without removing either actual root signature or the identity joins.

The receipt's `runtimeClosureDigest` is an independent root assertion, not a new
live measurement. Its original interval is at most 300 seconds. Cold admission,
idle acceptance and request handling remain within that interval; restarting or
reusing the bootstrap does not renew it. Per-request deadlines are also clipped
to the original receipt expiry. The configured request timeout is 0.05–30 seconds.

## Fixed delivery and cold admission

[Root delivery](../serverware/registration_evidence_signer_entrypoint.py) starts
as root with exactly one descriptor above stdio: systemd's activated stream FD 3,
named `serverware-registration-evidence`. It requires the actual current
`LISTEN_PID`, one listener, the fixed Unix socket path, and a listening stream.
The final original inventory is exactly:

| FD | Original retained material | Fixed source or endpoint |
| --- | --- | --- |
| 198 | Independent root public key, sealed, at most 16 KiB | `/run/serverware/registration-evidence-trust/root-public-key.pem` |
| 199 | Original signed bootstrap, sealed, at most 4 MiB | `/run/serverware/registration-evidence-trust/bootstrap.json` |
| 200 | Nonblocking activated Unix stream listener | `/run/serverware/registration-evidence/signer.sock` |
| 201 | Dedicated evidence private key, sealed, at most 4096 bytes | `/run/secrets/serverware-registration-evidence-signing-key` |
| 202 | Existing replay-directory handle | `/var/lib/serverware/registration-evidence-replay` |

Slots are reserved without overwriting occupied descriptors. Files and their
ancestors are checked without following symlinks; original material is stable,
root-owned and single-link before sealing. The private key must be mode `0400`.
The actual bootstrap signature is admitted before its signed replay device/inode
is used. The existing replay directory must match that identity, UID/GID
`65517:65517` and mode `0700`; delivery creates or repairs none of these resources.

Delivery drops every supplementary group and all root IDs/capabilities to
`65517:65517`. The socket is `65517:65532`, mode `0660`, and the actual service
accepts only peer UID/GID `65532:65532` before request bytes. Unknown inherited
descriptors are fatal. A rebuilt environment exposes only the two signer FD
names (`SERVERWARE_REGISTRATION_SIGNER_ROOT_PUBLIC_KEY_FD=198` and
`SERVERWARE_REGISTRATION_SIGNER_BOOTSTRAP_FD=199`), the fixed process mode
`webauthn-registration-evidence-signer`, and fixed interpreter environment.
There is no ambient key, DSN, root-path or generic authority-role fallback.

The fixed isolated launcher is
`/runtime/authority-bootstrap/registration_evidence_signer_launcher.py`.
Its only modes are `--root-delivery` and `--run`; it supplies only the fixed
`/vendor` dependencies and `/app` package location to the isolated interpreter.
[Cold startup](../serverware/registration_evidence_signer_startup.py) independently
re-admits the bootstrap and original receipt, joins the actual unencrypted PKCS8
Ed25519 key to the dedicated configured public key, and retains descriptor,
environment, PID, listener and receipt continuity. It does not mutate the borrowed
listener flags or grant authority merely because a descriptor exists.

## Replay and deployment boundaries

The existing durable enrollment replay owner is acquired over the independently
prepared directory, with a signed capacity of 1–4096 records. The same signer-key
replay domain must survive restarts and configuration/source generations: no new
namespace, TTL, deletion, reset or automatic retry makes a consumed grant reusable.
A failed request may already have consumed its grant. Hostile-host rollback
resistance still requires independently provisioned protection.

The [socket template](../ops/systemd/serverware-registration-evidence.socket) and
[service template](../ops/systemd/serverware-registration-evidence.service.in)
require an approved complete image export at `@SIGNER_RELEASE_ROOT@`, not a
checkout. Separate `@SIGNER_TRUST_DIR@`, `@SIGNER_KEY_FILE@` and
`@SIGNER_REPLAY_DIR@` bindings supply the fixed destinations above; the activated
socket directory is also bound into that root. `MountAPIVFS=yes` supplies the API
filesystem needed for self-FD checks, and service `NonBlocking=yes` sets the
activated listener contract. These are upstream systemd mechanisms, not an
attestation guarantee. See the official [service option source](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.service.xml)
and [execution option source](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.exec.xml).

`Type=exec` is not admitted readiness. `Restart=no` and a one-start limit suppress
repeat activation while systemd retains that counter. This is operational
backoff, not durable launch authorization: an operator reset, manager restart or
unit unloading can clear the counter, as described by the official
[unit option source](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.unit.xml).
None renews the receipt or replay state. Accounts, signed material, stable replay storage,
immutable image/dependency closure, rendering, installation and runtime proof
remain external prerequisites. Startup itself authorizes no actor/session
enrollment, switches no public registration route, and supplies no credential
finalization, successor execution or production-assurance claim.
