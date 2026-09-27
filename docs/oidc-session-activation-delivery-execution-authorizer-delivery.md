# Consume-grant authorizer cold delivery

The dedicated entrypoint, isolated launcher, finite runner and uninstalled
systemd units compose the fixed `oidc-session-activation-delivery-execution-authorizer`
role. They do not widen an activation, registration or generic control-plane
role. The process drops permanently from root to UID/GID `65500`, with empty
supplementary groups; the only service caller peer is `65532:65532`.

## Exact resources

The fixed listener is
`/run/serverware/oidc-session-activation-delivery-execution/authorizer.sock`,
activated under the exact name
`serverware-oidc-session-activation-delivery-execution-authorizer`. Its filesystem
owner/group/mode must be `65500:65532`, `0660`; its kernel listener was created by
root. A client observing kernel peer `0:0` is checking that socket-activation
provenance, not attesting that the serving process executes as UID `65500`.

Eleven descriptors survive the privilege drop:

| FD | Original/resource | Byte ceiling |
| --- | --- | --- |
| 198 | Independent root public key | 16 KiB |
| 199 | Signed authorizer role bootstrap | 4 MiB |
| 200 | Fixed AF_UNIX stream listener | Not a byte original |
| 201 | Signed receiving custody | 16 KiB |
| 202 | Signed consume-planner bootstrap | 4 MiB |
| 203 | Original planning-history custody | 8 MiB |
| 204 | Separate receiving-history custody | 8 MiB |
| 205 | Consume execution-bundle key | Exactly 32 bytes |
| 206 | Historical activation-bundle key | Exactly 32 bytes |
| 207 | Activation-delivery key | Exactly 32 bytes |
| 208 | Consume-grant Ed25519 signer PEM | 4096 bytes |

The six public trust files live below the fixed root-protected directory
`/run/serverware/oidc-session-activation-delivery-execution-authorizer-trust/`:
`root-public-key.pem`, `bootstrap.json`, `custody.json`, `planner-bootstrap.json`,
`planner-history-custody.json`, `receiving-history-custody.json`.

Private paths share the fixed prefix
`/run/secrets/serverware-oidc-session-activation-delivery-execution-authorizer-`
with suffixes `execution-bundle-key`, `historical-bundle-key`, `delivery-key` and
`signing-key`. These source-fixed receiver paths must hold the actual root-pinned
bytes for each purpose; they do not request newly generated AES keys. No planner
private signer, journal key, journal/store directory, database, TLS or state
socket is delivered.

## Admission and lifecycle

One real construction work/window begins before material reads. Every bounded
file is opened without following symlinks through protected root-owned parents;
identity, size, link count and path continuity are checked around the read.
Actual lengths are charged before read/seal allocation. Private files must be
root-owned mode `0400`. Immutable sealed copies, not mutable filesystem handles,
are retained at the exact descriptor slots.

The actual [role bootstrap](oidc-session-activation-delivery-execution-authorizer-bootstrap.md)
verifies all original role/receiving/planner/history/enrollment bindings before
any private key is opened. `_keys_on_work` then checks all three raw32 AES keys
against the root-authenticated receiving pins, including pairwise separation,
and checks the actual Ed25519 private/public pair and enrolled signer SPKI.
Original construction and signed-launch bounds remain checked; they are not
replaced by a fresh allowance after I/O or privilege drop.

Listener/path identities and all sealed descriptors are checked before the
empty-group permanent drop and again before same-process continuation. The
already isolated launcher accepts only `--root-delivery`; there is no standalone
`--run` or post-drop exec that could replace the construction allowance. The
entrypoint resets the environment to the exact eight source-fixed entries and
passes the actual work, original window and inherited deadline to the private
runner/startup continuation in the same PID. Descriptors `198..208` remain
close-on-exec; they survive the identity drop but are not exported to a child.
Failure closes task-owned descriptors; no key or original is logged. The runner
uses the actual [startup service](oidc-session-activation-delivery-execution-authorizer-service.md),
polls only while idle, stops after the first accepted request, and closes the
service on success, failure or cooperative termination. There is no automatic
new request, re-signing or delivery retry.

Sealed reads validate the original identity and actual bounded size, charge that
size on the shared ledger, then wrap only the raw read in the metrics-preserving
callback. Startup calls this charging helper directly between current-window
guards; it does not nest a ledger mutation inside a read-only callback.

`Dockerfile.production` copies the new fixed launcher from the verified source
tree and makes it read-only. The separate service/socket templates declare
read-only trust/key/socket-directory bindings, no writable state and no restart.
They remain unrendered and uninstalled; accounts, socket permissions, signatures,
keys and immutable release inputs require independent provisioning. Cooperative
timeouts are not a hard kernel syscall watchdog.

This is source-only, unbuilt and unexecuted trusted-host-local composition, not
TEE/KMS/off-host custody or runtime acceptance. A returned grant still needs
independent original-based verification; socket framing is not proof. No
reservation, one-use SQL, completion, public permission, current-session claim
or plaintext token release follows from this delivery layer.
