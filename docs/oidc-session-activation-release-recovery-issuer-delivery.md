# Cold recovery issuer delivery

The dedicated recovery issuer has its own root-signed bootstrap and process
role, `oidc-session-activation-release-recovery-issuer`. It does not widen the
LIVE issuer or reuse its staging admission. The fixed service UID/GID is
65493; the sole request peer is 65532:65532. Root supplies the listening socket
at `/run/serverware/oidc-session-activation-token-release/recovery-grants.sock`,
named `serverware-oidc-session-activation-release-recovery-issuer`. Its pathname
is 65493:65532 mode 0660. No socket or directory is created by delivery.

The exact eight inherited descriptors are:

| FD | Original/resource |
| --- | --- |
| 198 | Runtime root public key |
| 199 | Signed recovery issuer bootstrap |
| 200 | Root-created listening socket |
| 201 | Independent recovery issuer policy |
| 202 | Historical release custody original |
| 203 | Independent proof enrollment |
| 204 | Independent intent enrollment |
| 205 | Runtime root signing key |

The closed bootstrap payload pins the four independent originals through their
existing framed identity domains, the signer's exact byte count/digest, current
source/purpose/trust mode and interval. Its closed launch pins the role,
UID/GID, peer, exact eight-FD inventory, fixed listener path, kernel and pathname
device/inode identities and a 1–30 second request timeout. There is no staging
endpoint. The launch interval must be contained in the separately signed
[recovery issuer policy](oidc-session-activation-release-recovery-issuer-policy.md).
Historical evidence is authenticated without renewing its old authority.

`_verify_on_work` accepts only exact bootstrap, policy, release-custody and two
enrollment originals plus the actual root public key, original work/window and
deadline, with optional restrictive two-clock `_continuity`. Its immutable
`_IssuerMaterial` has fourteen fields: the five originals, genuine policy
material, owned launch, root signer byte count/digest, signed interval/opening
sample, narrowed window/deadline and retained current guard. `_produce_on_work`
substitutes a payload and additionally requires the real root key pair; it
admits independent originals before signing and authenticates its readback.
Neither API accepts an incoming successful material carrier.

Root delivery reads only these fixed public files beneath
`/run/serverware/oidc-session-activation-release-recovery-issuer-trust`:
`root-public-key.pem`, `bootstrap.json`, `issuer-policy.json`,
`release-custody.json`, `proof-enrollment.json`, `intent-enrollment.json`.
Each is a single-link root-owned regular file, mode 0444, reached through
root-owned non-group/world-writable ancestors with no symlink traversal. The
private path is
`/run/secrets/serverware-oidc-session-activation-release-recovery-issuer-root-signing-key`,
mode 0400. It is not opened until genuine bootstrap and independent policy,
custody and enrollment admission succeeds. Its exact bytes and Ed25519 pair
must then match the signed pin and actual runtime root.

The bootstrap/root/key bounds are 16 KiB each; policy is 64 KiB, custody 8 MiB,
and each enrollment 16 KiB. Actual held originals and source-known decoded
graphs are reserved under 64 MiB before further allocation. The private
`_material_bytes_on_work` helper measures only actual admitted originals and
finite graphs; `_retained_bytes_on_work` accepts only this root delivery's
unchanged continuation and original work, allowing startup to subtract retained
root state before reserving its own reread, request and response capacity.

The root entrypoint starts once with only the exact socket-activation FD 3,
checks its name/path and signed resource identity, reserves 198–205 without
overwriting inherited resources, and delivers sealed close-on-exec memfds.
The construction ledger and clock bracket start before file reads and survive
the permanent same-PID UID/GID drop, supplementary-group removal and literal
environment replacement. The existing source-fixed runner is called with
`work`, `live_window`, `transport_deadline_ns`, and `delivery_current`; there is
no exec, standalone allowance renewal, retry worker or detached process.
The retained guard checks actual sealed originals/listener and lifetime;
startup separately owns the exact accepted-socket inventory and finite request.
Cleanup failures remain failures.

This delivers only a narrowly configured root signer. It opens no TLS, AES,
history database, journal or outcome store. Fresh grant production and verified
response admission do not prove checkpoint-one storage exists, stage a private
release worker, perform the token exchange or deliver a public cookie. Those
connections and independent provisioning remain open. This is source-only
implementation, not deployment, runtime or production acceptance evidence.
