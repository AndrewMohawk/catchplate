# Dedicated activation SQL delivery

Source-only, unbuilt and unexecuted. The fixed root entrypoint delivers
independent role/receiving originals and two purpose-bound AES keys to a
dedicated SQL process, not a relabeled reserver. It owns no signing key.

| FD | Original or resource |
| --- | --- |
| 198 | Sealed root public key |
| 199 | Sealed independent SQL role bootstrap |
| 200 | Fixed activated SQL listener |
| 201 | Sealed receiving-custody original |
| 202 | Sealed bundle AES key, exactly 32 bytes |
| 203 | Sealed delivery AES key, exactly 32 bytes |
| 204 | Independently pinned attempt journal directory |

The fixed trust directory is
`/run/catchplate/oidc-session-activation-execution-sql-trust`, containing
`root-public-key.pem` (16 KiB cap), `bootstrap.json` (4 MiB) and `custody.json`
(8 MiB). The genuine [bootstrap](oidc-session-activation-execution-sql-bootstrap.md)
admits the independent role, receiving custody, embedded planner and original
enrollments before AES keys, TLS files or the attempt journal are opened.
The receiver identity comes from the independent signed role statement, not
the request, a computation measurement or a successful caller-supplied DTO.

The AES originals use the existing fixed bundle/delivery paths under
`/run/secrets/catchplate-oidc-session-activation-*-key`. Each is root-owned,
mode `0400`, single-link and exactly 32 bytes. Actual key digests must match
genuine receiving custody. No computation, planner, grant, completion or state
signer and no planner-journal encryption key is delivered.

## Filesystem and privilege boundary

Fixed originals are opened without following symlinks through protected,
root-owned ancestors. Bounded reads retain descriptor and pathname identity
before and after capture. Trust/AES originals become sealed descriptors.
The attempt directory is fixed to
`/var/lib/catchplate/oidc-session-activation-execution-sql-attempts`, owned by
`65504:65504`, mode `0700`; its signed device/inode is checked without creating
or clearing it. The independent attempt checkpoint is not selected from disk.

libpq needs five fixed TLS paths under
`/run/catchplate/oidc-session-activation-execution-sql-tls`: `ca.pem`,
`issuer.crt`, `issuer.key`, `executor.crt`, `executor.key`. Each file is
root-owned, single-link and bound by signed exact length/digest. Public files
are mode `0444` and at most 64 KiB; private keys are root:65504 mode `0440`
and at most 16 KiB, allowing reopening after the drop. TLS originals are
hashed once per admission, then fixed-path metadata continuity is checked.
Key contents are neither returned nor logged. This trusted-host check does
not defeat malicious root or atomically prevent later pathname substitution.

The process permanently drops real/effective/saved UID/GID to `65504:65504`,
clears supplementary groups, retains exactly FDs 198–204 and passes only the
literal eight-variable environment to the fixed isolated launcher. Original
launch lifetime, descriptor inventory, listener, journal and TLS continuity
are rechecked before exec. Startup independently repeats original admission;
no root-delivery success object substitutes for it.

## Uninstalled service inputs

The [socket](../ops/systemd/catchplate-oidc-session-activation-execution-sql.socket)
uses `/run/catchplate/oidc-session-activation-execution/sql.sock`, owner65504,
peer group65532, mode `0660`, backlog one and `Accept=no`. Its FD is
nonblocking; recreating the socket invalidates signed inode pins.

The [service template](../ops/systemd/catchplate-oidc-session-activation-execution-sql.service.in)
requires `ACTIVATION_SQL_RELEASE_ROOT`, `ACTIVATION_SQL_TRUST_DIR`,
`ACTIVATION_SQL_TLS_DIR`, `ACTIVATION_SQL_BUNDLE_KEY`,
`ACTIVATION_SQL_DELIVERY_KEY` and `ACTIVATION_SQL_JOURNAL_DIR`. Trust, TLS,
AES and socket paths are read-only binds; only the attempt journal is writable.
No state socket, computation key or planner-journal/store is mounted.
The template does not provision accounts, ACLs, TLS, database permissions or
independent current-pending authority. PostgreSQL egress must be independently
restricted to the exact admitted database address. The DSN itself is source
constructed with verified TLS, literal hostaddr, fixed database roles and no
password, service-file or caller-selected path fallback.

The runner accepts one exchange, including rejection or uncertainty.
`Restart=no` and start-limit burst one prevent automatic service repetition.
The 300-second cap and cooperative shutdown are not a kernel watchdog or
proof of rollback. The [SQL service](oidc-session-activation-execution-sql-service.md)
uses actual issuer/executor owners and a durable no-resend claim. Its unsigned
observation is not completion, history, currentness, a public permission or
token/session release. Those remain separate work and production gates.
