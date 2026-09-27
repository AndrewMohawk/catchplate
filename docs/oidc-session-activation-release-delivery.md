# Private release worker delivery

This is source-only, unbuilt, unexecuted and unprovisioned. The fixed launcher
admits actual public root/bootstrap originals before any private key read or
sealing. It composes the [cold bootstrap](oidc-session-activation-release-bootstrap.md),
[resource intake](oidc-session-activation-release-resources.md) and actual finite
worker; it is not a public release route or evidence of a delivered/current session.

The only entry is isolated `/runtime/python/bin/python3 -I` invoking
`/runtime/authority-bootstrap/oidc_session_activation_release_launcher.py
--root-delivery`. Arbitrary module/path flags and standalone `--run` are rejected.
The root construction work/window begins before original/resource I/O. The actual
root-delivery guard remains retained alongside intake's own genuine admission and
clock guards through the sole permanent drop to UID/GID 65502, startup, operation
and response. There is no post-drop exec, serialized clock carrier or new budget.

| FD | Fixed resource |
| --- | --- |
| 198 | Sealed public root original |
| 199 | Sealed signed bootstrap original |
| 200 | Sealed raw32 delivery AES key |
| 201 | Already-provisioned exact outcome-slot directory |
| 202 | Nonblocking fixed Unix listener |

Every descriptor retains close-on-exec. Protected public originals are read from
`/run/serverware/oidc-session-activation-token-release-trust/{root-public-key.pem,bootstrap.json}`;
the single private file is root-owned mode 0400 at
`/run/secrets/serverware-oidc-session-activation-token-release-delivery-key`.
Source file types, links, ownership, sizes and before/after identities are checked;
actual admitted byte lengths are charged before reading/sealing. The original
current guard runs immediately before and after each raw read and sealing call;
metadata checks or work reservation cannot separate the read from its guard.
Public originals are capped at 16 KiB/16 MiB and the delivery key is exactly 32
bytes. No signing,
history, SQL, TLS or state-client key/resource is delivered.

## One independently pinned slot

The pre-provisioned root:root 0700 base is fixed inside the worker at
`/var/lib/serverware/oidc-session-activation-release-outcomes`. After genuine root
admission, the launcher derives `slot-<hex64>` using the existing outcome slot
domain over the admitted database, generation and delivery IDs. It does not use
the raw delivery ID as a pathname. No request, environment or command-line path
selects authority, and no scan, fallback, mkdir or inferred checkpoint exists.

No-follow descriptor-relative lookup opens only that child. Its actual
device/inode/UID/GID must match the independently signed storage directory pins,
with UID/GID 65502 and mode 0700. Both named and opened identities are compared.
The base descriptor is closed before drop; the role retains only its exact slot
FD and cannot traverse the root-only base. Missing slots fail. Live/recovery
checkpoint requirements remain those of the genuine signed bootstrap and storage
authorization; a directory's contents cannot select the profile or checkpoint.

## Finite worker boundary

The listener is fixed at
`/run/serverware/oidc-session-activation-token-release/release.sock`, owner 65502,
group/peer 65532, mode 0660. Its socket/path identities match signed launch pins
before the private read. Delivery passes the exact actual resource owner to
`runner._run_with_resources`; that continuation performs one actual startup and
finite service exchange, then establishes cleanup. It does not re-intake resources,
drop again, accept material DTOs as authority, or return a token/connection/owner.
The original eight-variable environment is fixed by source and checked by intake.
The startup-owned accepted socket and journal duplicate remain additional exact
owned resources, not a permissive descriptor allowlist.

Delivery retains exact descriptor identities through the resource-intake handoff.
Failure cleanup closes only still-matching owned descriptors, removes ownership
before its single close attempt, and skips already-closed slots. Changed or
indeterminate identities are not closed and make cleanup uncertain/failing;
cleanup never adopts a replacement descriptor or retries an uncertain close.

The uninstalled socket/service templates bind the independently selected release,
trust directory, raw key and outcome base to fixed internal paths. The only
tmpfiles input creates listener parents; it never creates the base or a slot.
There is no installer, user creation, permission mutation or automatic retry.
One accepted failure/uncertainty is terminal. `Type=exec` and a successful private
send are not semantic readiness, receiving verification or delivery acknowledgment.

This remains trusted-host-local confinement: retaining one Python process does
not erase key copies or protect against a hostile host. Independent receiving and
authorized private application handoff remain separate criteria; no browser or
public token delivery is claimed.
