# Consume completion resource delivery

The dedicated root entrypoint delivers only the resources admitted by the
[consume completion bootstrap](oidc-session-activation-delivery-completion-bootstrap.md).
It does not create keys, directories, users, TLS credentials or database state.
The source/templates are unbuilt, unexecuted, uninstalled and unprovisioned.

| Descriptor | Fixed original/resource |
| --- | --- |
| 198 | Root Ed25519 public key, at most 16 KiB |
| 199 | Signed completion bootstrap, at most 32 MiB, containing four custody controls |
| 200 | Fixed nonblocking completion listener |
| 201 | Enrolled completion Ed25519 private key, at most 16 KiB |
| 202 | Existing private completion-journal directory |
| 203 | Consume execution-bundle AES key, exactly 32 bytes |
| 204 | Historical activation-bundle AES key, exactly 32 bytes |
| 205 | Historical delivery AES key, exactly 32 bytes |

Trust originals are fixed beneath
`/run/serverware/oidc-session-activation-delivery-completion-trust/` as
`root-public-key.pem` and `bootstrap.json`. Private root-owned mode-0400
originals are `/run/secrets/serverware-oidc-session-activation-delivery-completion-`
plus `signing-key`, `execution-bundle-key`, `historical-bundle-key` or `delivery-key`.
Sealed readonly originals replace path-based access before privilege drop.
The key helper returns `(completion_private_key, execution_bundle_key,
historical_bundle_key, delivery_key)` after genuine keypair/SPKI/hash joins.
The completion signer is not given to the independently admitted private caller.

The listener is
`/run/serverware/oidc-session-activation-delivery-execution/completion.sock`,
named `serverware-oidc-session-activation-delivery-completion`, with pathname
ownership **65497:65497**, mode **0660**. The actual private peer is fixed to
that same purpose/identity, not generic caller 65532. The journal is the existing
mode-0700 **65497:65497** directory
`/var/lib/serverware/oidc-session-activation-delivery-completions`; descriptor
and protected root pathname must match its signed device/inode.

The five original TLS files are under
`/run/serverware/oidc-session-activation-delivery-completion-tls/`:
`ca.pem`, `custody.crt`, `custody.key`, `commit.crt` and `commit.key`.
Public originals are root-owned mode 0444, bounded to 64 KiB. Private originals
are root-owned group 65497 mode 0440, bounded to 16 KiB. All actual file lengths
are charged before bytes are read or hashed; the root-signed sizes/hashes,
descriptor identities and protected pathnames must match. Later checks retain
metadata continuity, not a claim of protection from hostile root.

## One real startup allowance

The fixed isolated launcher enters root delivery. Before any trust/key/TLS
read, `_construction_on_work(work)` obtains the one real processing opening.
Root/bootstrap admission, actual private-key joins, TLS hashing, journal and
listener checks use that same cumulative ledger. Admitted role expiry and the
minimum caller/planner age/skew can only narrow its original samples/deadline.
Size charging is outside native callback guards; it is not hidden inside a
callback that forbids ledger mutation.

After genuine original admission, root opens only the fixed private resources,
retains the exact eight descriptor identities, sets all of them **CLOEXEC**,
clears supplementary groups and permanently drops all real/effective/saved
UID/GIDs to 65497. It clears the environment to the exact eight fixed variables.
There is **no post-drop exec**, serialized clock claim or new startup budget.
In the same isolated PID it calls the private runner continuation
`_run_on_work(*, work, live_window, transport_deadline_ns)`, which passes those
actual original objects to mandatory startup. Standalone `--run` is not a
replacement for root delivery. No root private signing key is loaded.

Root delivery owns all temporary/reserved descriptors through failures; startup
owns its admitted duplicates, readers, custodian and journal/delivery objects.
The service accepts one request and terminates after success, uncertainty or
failure. Idle polling is allowed only while startup authority remains live.
There is no automatic retry, signer substitution, ambient secret fallback or
generic completion path.

The private receiving helper requires a separate genuinely admitted same-purpose
custodian and original scope. Sharing the trusted-host-local UID is not OS
isolation, and this server delivery does not provision a separate caller or
connect a public route. Cold application-caller packaging, plaintext token
release and public handoff remain separate obligations.
