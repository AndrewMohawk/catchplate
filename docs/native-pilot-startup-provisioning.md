# Automatic late startup provisioning

The fixed `startup-provisioning` command supplies the six public inputs and
admission required by the [three-process startup](native-pilot-startup.md).
It runs separately with an independently supplied delegation. It does not
launch children, read private keys, initialize current state or approve a
checkpoint. This closes the manual late-file preparation step in source, not
the complete pilot deployment.

## What is delegated

`serverware.nativePilotStartupProvisioningDelegation/v1` pins the exact startup
configuration, supervisor/conductor/authority inventories and measured recipe.
It includes the complete provider-policy and decision-configuration selections
except for three fields that cannot exist until the real processes start:

| Destination | Value taken from the actual startup observation |
| --- | --- |
| Provider policy `lifecyclePeer` | Lifecycle PID, UID, GID and start time |
| Provider policy `currentHeadPeer` | Decision receiver PID, UID, GID and start time |
| Decision configuration `providerPeer` | Provider PID, UID, GID and start time |

All other policy selections, source originals and clock fields stay unchanged.
There are no arbitrary templates, commands, destinations or key inputs. The
complete new delegation is capped at **32 MiB**, including wrapper metadata,
to fit the existing protected-input reader. The separate provider policy keeps
its existing codec and 32 MiB limit; its unsigned source values are not coerced
into the narrower signed-integer codec.

Validating an observation is not permission to approve it. The protected,
externally pinned delegation explicitly authorizes these fixed projections;
the resulting files must also pass the existing complete startup admission
checks before anything is published.

## Actual publication

The provisioner retains six distinct protected FD/hash inputs, its admitted
supervisor runtime and the pinned root-owned `0700` startup directory. It waits
for the launcher's actual `observation.json`, validates the literal process and
socket graph, then prepares all six existing source originals and Admission1.
The six files are published first; `admission.json` is last.

Both the launcher observation and provisioner outputs now use the same fixed
startup-only atomic publisher. Complete bytes are written, fsynced and read
back in an anonymous file before a no-overwrite link exposes the final name.
The publisher retains genuine procfs descriptors for its own PID/FD table.
Readers never use a partially written final filename as readiness.

Existing files, unknown filenames, changed directory identities or expired
authorization refuse. There is no retry, deletion, replacement or automatic
reset. A failure may leave complete public files, including an admission that
another process has already seen. Descriptor cleanup does not retract it or
prove that publication never happened; uncertain cleanup retains the owner.

## Original startup window and command

The wait is bounded by the original listener/driver startup deadline, cleanup
reserve and wall-clock constraints, even before an observation exists. The
admission still contains its approved lifetime bounds and must contain every
resumed role's original lifetime. A shorter publication wait is not an unseen
restriction on a role, and neither wait nor admission renews the 30-second
startup window.

The admitted supervisor entrypoint selects `startup-provisioning`, followed by
these six FD/SHA-256 pairs in order:

```text
supervisor-inventory, delegation, configuration, recipe,
conductor-inventory, authority-inventory
```

For each pair the fixed flags are `--NAME-fd FD --NAME-sha256 sha256:HEX`.
This is a capability contract, not a deployment command with missing keys
silently supplied. The legacy default command is unchanged. Successful exit
means seven public originals were published and local cleanup completed; it
does not mean the startup accepted them or an application flow succeeded.

## Remaining pilot work

The [current-state worker](native-pilot-current-head-worker.md) still needs an
independently delegated initial-state commit from actual installed histories
and a connected worker launch before the first current-head request. Matching
approved packages, protected installation, independent policy/state ownership
and a real credential-replacement allow/deny/cleanup flow remain required.
Same-host root protection is not independent organizational custody, hostile-root
rollback protection or the production off-host witness.
