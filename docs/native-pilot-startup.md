# Three-process pilot startup

The fixed `commissioning-startup` supervisor mode connects the existing
lifecycle, approval provider and current-head decision receiver. It removes the
need to predict their PIDs before supplying the policies that bind those PIDs.
This is startup integration, not a deployed pilot or an approval backend.

## What runs

1. The launcher admits its installed supervisor inventory and protected startup
   configuration, then starts three fixed child commands with public inputs only.
2. Each child creates its own sockets. The provider listens for the lifecycle;
   the decision receiver listens for the provider. Kernel peer credentials,
   PIDFDs, process start times and parent identities bind the actual connections.
   A socketpair created in the launcher cannot stand in for child identity.
3. The launcher publishes literal process/socket observations. An independently
   authorized provisioner uses those observations to supply the six public role
   inputs and one admission file below. Observation alone grants no permission.
4. The launcher validates the complete existing provider policy, listener and
   decision configuration against the actual peers. It resumes the receiver,
   then provider, then lifecycle. Only the lifecycle receives authority-key FDs.
5. Each child calls its existing role entrypoint **in the same process**, retaining
   its authenticated sockets. Success requires the role's exact result, empty
   stdout, closed output pipes, a successful exit and consuming PIDFD reap.

The existing 244 approvals, two completion receipts and eight independently
supplied current-head decisions remain unchanged. A startup result does not
prove that an application request or a production ceremony succeeded.

## Protected inputs

The startup configuration is canonical
`serverware.nativePilotStartupConfiguration/v1`. It pins the supervisor inventory,
an invocation digest, boot/time namespace, original monotonic and wall-clock
bounds, and the device/inode of an initially empty root-owned `0700` directory:
`/etc/serverware/native-pilot-startup`. Abstract socket names are derived only
from the invocation digest; no arbitrary command or socket path is accepted.

The launcher exclusively creates `observation.json`. After checking its actual
process identities, the independently authorized provisioner supplies these
root-owned, single-link `0400` files in the same protected directory:

| File | Existing role and purpose |
| --- | --- |
| `listener-configuration.json` | Lifecycle's original listener/window configuration |
| `provider-policy.json` | Explicit delegation and the observed lifecycle/decision peers |
| `recipe.json` | Existing approved commissioning recipe |
| `conductor-inventory.json` | Separate installed conductor inventory |
| `authority-inventory.json` | Separate installed authority inventory |
| `decision-configuration.json` | Decision receiver's actual provider peer and protected directory |
| `admission.json` | Pins setup, literal observations, all six originals and accepted bounds |

On the authorized target, `scripts/prepare_native_pilot_resource_roots.py
--profile commissioning-startup` inspects the existing operational resource
roots plus both new handoff directories. Adding `--create` creates only missing
fixed directories after preflight; it never empties, repairs or replaces an
existing leaf. Inspection alone does not create anything. The shared
`/etc/serverware` directory may contain unrelated protected state.

Publish complete immutable files, not files that are still being written. The
launcher validates full originals and their hashes before passing them on; it
does not author or rewrite them. The decision receiver still needs its separate
initially empty `/etc/serverware/native-pilot-current-head-decisions` directory
and the [fresh-decision backend](native-pilot-approval-provider.md).

Each role's actual original lifetime must fit inside admission, and admission
must fit inside the original setup lifetime. Startup does not extend or reissue
the listener/driver window. In particular, the existing 30-second driver startup
window requires automated provisioning, not manual editing during execution.

The parent accepts the same **36 cold and 123 adopted purpose slots** as the
lifecycle CLI. They are already provisioned, sealed 32-byte key descriptors,
not key strings or paths. The launcher may retain metadata-checked duplicates
while awaiting admission, but never reads private bytes. Only the admitted
lifecycle receives them; its existing purpose-specific checks still apply.
The provider and decision receiver receive no private-key descriptors.

## Entrypoints and cleanup

The installed supervisor entrypoint selects `commissioning-startup`, with
`--configuration-fd`/`--configuration-sha256`,
`--supervisor-inventory-fd`/`--supervisor-inventory-sha256`, then the exact
source-ordered `--cold-authority-key PURPOSE=FD` and
`--adopted-authority-key PURPOSE=FD` slots. Its internal
`commissioning-startup-child ROLE` mode permits only `lifecycle`, `provider`
or `decisions`. Neither mode changes the legacy default command.

Cancellation requests normal child cleanup. A terminal line without real exit
and reap is insufficient; an abnormal post-admission death is not evidence of
safe cleanup. Unknown cleanup retains the owner and reports uncertainty.
After an authorization timeout, a separate fixed five-second observation window
allows normal cleanup to be collected; it grants no further workflow execution.
Published public files remain available for operator inspection; startup does
not erase them or silently reset the directory for another invocation.

## Pilot boundary

The startup source and its focused controls do not establish protected installed
execution. Matching approved packages, provisioning of independent policies and
fresh decisions, the protected deployment, and a real credential-replacement
allow/deny request remain necessary. See the [pilot checklist](../README.md#production-status)
and [engineering assembly](native-pilot-build.md#current-engineering-assembly).
