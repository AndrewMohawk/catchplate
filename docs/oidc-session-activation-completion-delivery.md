# Dedicated activation completion delivery

Source-only, unbuilt, unexecuted and uninstalled. The fixed root entrypoint
delivers the independent completion/history originals, enrolled completion
signer and purpose-bound AES keys to UID/GID 65503. It does not provision them
or silently extend any live grant/reserve/SQL role.

| FD | Original or resource |
| --- | --- |
| 198 | Sealed root public key |
| 199 | Sealed completion bootstrap, including historical-custody original |
| 200 | Fixed activated completion listener |
| 201 | Sealed enrolled completion private key |
| 202 | Independently pinned completion journal directory |
| 203 | Sealed bundle AES key, exactly 32 bytes |
| 204 | Sealed delivery AES key, exactly 32 bytes |

Trust is fixed under `/run/serverware/oidc-session-activation-completion-trust`:
`root-public-key.pem` is bounded to 16 KiB and `bootstrap.json` to 16 MiB.
The larger closed bootstrap carries the genuine historical-custody original;
there is no separate custody descriptor or arbitrary path fallback.
Actual purpose-specific [root/launch admission](oidc-session-activation-completion-bootstrap.md)
precedes any private key, TLS or journal access. Startup repeats original
admission, not a returned material.

The completion PEM is fixed at
`/run/serverware/oidc-session-activation-completion-key/completion.pem`, bounded
to 4096 bytes. It must match the genuinely enrolled completion public key.
The bundle/delivery raw32 originals use fixed
`/run/secrets/serverware-oidc-session-activation-{bundle,delivery}-key` paths.
They must differ and match independently admitted historical purpose digests.
Signing and AES files are root-owned, single-link, mode `0400`; no passphrase,
other purpose signer, planner-journal key or plaintext token is delivered.

## File and process boundary

Protected root-owned ancestors, no-follow opens, bounded exact reads and
descriptor/path identities prevent accepting changed local originals during
capture. Trust and private originals become sealed descriptors. The journal
is separately preprovisioned at `/var/lib/serverware/oidc-session-activation-completions`,
owner `65503:65503`, mode `0700`, with independently signed device/inode and
checkpoint. No directory is created, cleared, pruned or inferred current here.

Five fixed TLS files live under
`/run/serverware/oidc-session-activation-completion-tls`: `ca.pem`, `custody.crt`,
`custody.key`, `commit.crt`, `commit.key`. Public files are root-owned `0444`
and at most 64 KiB; private TLS keys are root:65503 `0440` and at most 16 KiB
so libpq can reopen them after the permanent drop. Signed exact lengths/digests
and retained pathname metadata are checked; contents are never returned/logged.
These host-local checks do not defeat malicious root or later substitution.

The entrypoint reserves all seven fixed FD slots, validates listener/journal
identity, clears supplementary groups and permanently sets real/effective/saved
UID/GID to 65503. It retains exactly those descriptors and the literal eight-field
environment, then executes the fixed isolated launcher. Launch lifetime, original
seals, TLS, listener and journal are checked through the final pre-exec suffix.
The runner accepts one connection, including failure/uncertainty, with no retry.

Completion journal cold recovery can use the caller's supplied current
window/work/deadline cumulatively for enrollment and every retained record.
The optional inherited-allowance constructor path does not reopen per-record
work or time; existing callers with no supplied allowance retain their behavior.
Late failure preserves durable originals rather than undoing publication.

## Uninstalled service inputs

The [socket](../ops/systemd/serverware-oidc-session-activation-completion.socket)
fixes `/run/serverware/oidc-session-activation/completion.sock`, owner 65503,
peer group 65532, mode `0660`, backlog one and `Accept=no`. Recreating it
invalidates admitted inode pins. Its inherited kernel peer remains root 0:0.

The [service template](../ops/systemd/serverware-oidc-session-activation-completion.service.in)
requires independent `ACTIVATION_COMPLETION_` release/trust/key/TLS/journal
paths. Only the completion journal is writable; trust, private keys, TLS and
socket directories are read-only mounts. State-socket DAC access and a genuinely
admitted completion peer profile must be provisioned separately, as must the
read-only database roles, exact TLS identities and restricted database egress.

`Restart=no`, one-launch start limit and a 300-second runtime cap provide no
automatic resend or hard kernel watchdog. This delivery supplies neither SQL
retry nor protected token release, public permission, session activation or
production acceptance. No build, parser, test or runtime verification was run.
