# Fixed native guest cohort

This source-owned factory launches the seven actual custody roles inside the
guest. It is not a generic process supervisor, readiness verdict, secret
provisioner or production acceptance result. Native cold startup must select
and retain it explicitly; the DTO alone grants no role or launch permission.

## Inputs and owners

`serverware.nativeGuestCohort/v1` has exactly four fields:

- `apiVersion` selects this closed contract.
- `executable` pins the static worker at
  `/usr/local/bin/serverware-response-v2-guest-role` (at most 64 MiB).
- `configuration` pins the actual common signed-delivery-bound custody config.
- `deliveries` contains exactly one protected original for each of the seven
  service roles. Each has `serviceRole`, `path` and `sha256`.

The [schema](../schemas/native-guest-cohort.v1.schema.json) describes shape;
runtime also requires unique roles/paths, matching signed generation/trust/boot,
and every actual signed process executable hash equal to the fixed image pin.
Root admission reads only configuration and signed delivery originals. It never
reads a role seed. The independently admitted worker reads its own role material
only after its permanent signed UID/GID transition.

The launcher requires the genuine native privilege-preparation owner, not an
integer UID or a copied deadline. It retains that owner's private association
for the later irreversible serving-identity check. The inspector endpoint is
consumed once from the same retained inspector object, not paired with a
separately supplied identity. The router's actual config/delivery originals must
match the inspector's originals exactly.

## Process and descriptor sequence

Every child is created with `clone3(CLONE_PIDFD)` and a fixed `execveat` of a
pinned sealed copy. There are no arguments, environment selectors, pathname
exec fallback or numeric-PID reopening. Unrelated descriptors are closed on
exec; every duplicated source is above all fixed destination descriptors.

| Descriptor | All roles | Router only |
| --- | --- | --- |
| 3 | Private parent lifetime/progress channel | Same |
| 4 | Absent | Absent |
| 5 | Sealed exact role bootstrap | Same |
| 6–7 | Absent | Actual fresh bound listener and sealed handoff |
| 8–10 | Absent | Inspector channel, actual PIDFD, original bootstrap |

The startup order follows actual service dependencies:

1. Start state-authority; require its authenticated `listening` progress after
   genuine generation bootstrap/reconciliation and actual local readiness.
2. Start the other five nonrouter roles and require each `listening` message.
3. Start the router with the actual inherited private descriptors.
4. Require `started` from all seven. State-authority emits it only after real
   generation activation finishes; other roles emit it after their real role
   readiness artifact is published.

Each exact five-field `serverware.responseV2.guestRoleStartup/v1` message binds
the original nonce/bootstrap hash, service role and next phase. Actual kernel
SCM credentials must match the signed final UID/GID; the per-message PIDFD must
identify the exact clone-owned child. Duplicate, reordered or extra progress
fails. No commands, retries, renewed deadline or inferred file absence exist.

Both the signed delivery startup bound and the original native lifetime apply.
The most restrictive startup deadline bounds the whole cohort. After startup,
retained original descriptors are checked without reopening root-private paths
or treating the expired startup grant as a renewed serving grant.

## Readiness and retirement boundaries

Progress authenticates the fixed worker's local lifecycle. It does not replace
the independently signed generation artifacts or the native response client's
genuine readiness/identity checks. A running process, listener, message or
successful constructor is not independent production evidence.

Every startup failure retains cleanup ownership of already-created children.
All are stopped before any bounded exact reap is awaited. After gate privilege
drop, parent-channel shutdown, each child's parent/PIDFD monitor and its original
absolute kernel timer remain effective; a cross-UID signal attempt is not
assumed to succeed. Only a successful explicit reap before the original bound
can be reported as timely. Destructor cleanup attempts confer no success claim.

The fresh listener paths are not reused or silently removed. This factory does
not repair an interrupted generation, provision encrypted role secrets, create
durable backends or supply independent quote/signing authority. Those inputs,
native cold-profile integration, EIF artifacts and full frozen runtime/Nitro
acceptance remain required. No pilot or production readiness follows from these
source files.
