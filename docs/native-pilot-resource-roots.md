# Native pilot resource parents

`scripts/prepare_native_pilot_resource_roots.py` is a fixed Linux operator
helper for **empty parent directories only**. It does not configure or launch
a pilot. Run it before the retained resource owners and their original startup
windows; do not run it concurrently with resource allocation or a live pilot.

```sh
# Read-only inspection; requires real/effective/saved UID and GID zero.
sudo python3 -B scripts/prepare_native_pilot_resource_roots.py

# Explicitly create only missing allowlisted directories.
sudo python3 -B scripts/prepare_native_pilot_resource_roots.py --create

# Separately select cold-to-operational adopted parents; still inspect-only.
sudo python3 -B scripts/prepare_native_pilot_resource_roots.py --profile adopted-cold

# Explicit creation of missing parents in that exact selected inventory.
sudo python3 -B scripts/prepare_native_pilot_resource_roots.py --profile adopted-cold --create
```

The default profile is `legacy`; spelling `--profile legacy` selects exactly
the same existing inventory and report. The only successor is `adopted-cold`.
No arbitrary path, identity, mode or repair option exists. Both actions retain
and recheck the actual directory descriptors/names, reject symlink traversal,
and require root:root ancestors without group/other write permission. Existing
resource parents must be exactly `0711` and empty, except the selected core
handoff parent, which must be exactly `0700` and empty. Any leftover entry refuses.
Checks read at most one entry per leaf. The generation container admits only
the five fixed role names and each role directory must itself be empty.

Both profiles include this unchanged legacy inventory:

| Fixed parent(s) | Actual later writer and fresh child |
| --- | --- |
| `/run/catchplate-custody-business`, `/var/lib/catchplate/custody-business` | `BusinessResources` creates the five role directories, listener sockets and role-specific business directories. Do not precreate the roles here. |
| `/var/lib/catchplate/custody-generation/{durable-recovery-store,cleanup-authorization-consumer,recovery-target-provider,current-signature-authority,bounded-cleanup-helper}` | `GenerationInputs` requires these existing role parents, then creates `generation-journal` and the selected dispatch/spool journals. |
| `/run/catchplate-shadow-{retrieval,persistence,trusted-time,generation-install,commit-request,ingress-admission,terminal-append,dispatch-barrier,active-effect-barrier,active-effect-commit}` | The respective retained native owners create their real `listener.sock`; this helper never creates a socket. Braces denote the fixed literal inventory, not a caller-supplied pattern. |
| `/var/lib/catchplate/native-ledger-spool` | `SpoolInputs` creates the original invocation-ID directory and held `ledger.lock`; the helper leaves this root empty. |
| `/var/lib/catchplate/native-shadow-persistence` | `PersistenceInputs` creates fresh `journal`, then its held lock and independently admitted originals. |
| `/var/lib/catchplate/native-shadow-generation-install` | The GenerationInstall resource owner creates fresh `journal`, `generation.lock` and supplied genesis/record originals. |
| `/run/catchplate-native-pilot-bridge`, `/var/lib/catchplate/native-pilot-bridge` | The bridge resource owner creates its listener and `production-journal`; the helper leaves both parents empty. |

The `adopted-cold` profile adds only these parents:

| Fixed parent | Required owner/mode | Actual later writer |
| --- | --- | --- |
| `/run/catchplate-custody-genesis`, `/var/lib/catchplate/custody-genesis` | root:root `0711` | Cold ordinary resources create their two role directories, listeners and journals. |
| `/var/lib/catchplate/publication-genesis-endpoints` | root:root `0711` | Cold endpoint resources create the actual Retrieval object/spool directories and held store lock. |
| `/run/catchplate-shadow-publication-reconciliation` | root:root `0711` | The selected cold or operational Publication owner creates its own listener. These ceremonies must not share a populated parent. |
| `/run/catchplate/native-pilot-core-handoff` | root:root `0700` | The actual cold sender creates the protected sequence-packet listener; this helper creates no socket. |

The adopted profile also admits the shared ancestor `/run/catchplate`: it is
created as root:root `0755` only if missing. Existing protected modes and unrelated
contents remain untouched; this shared container is not enumerated. The handoff
leaf is still checked separately for its exact mode and empty population.

New resource parents use the exact selected modes above. The two shared containers
`/var/lib/catchplate` and `/var/lib/catchplate/custody-generation` are created
as root:root `0755` only if missing; existing protected modes are left intact.
The former may contain unrelated directories and is never enumerated. `/`,
`/run`, `/var` and `/var/lib` must already exist and are never created or changed.

`--create` checks all existing targets before its first write. Each missing
directory is created exclusively as `0700`, assigned its final mode through
the new descriptor, fsynced with its parent, and read back. No existing mode
or owner is changed. A concurrent creation, mismatch, interruption or failed
fsync refuses and preserves partial state. There is no rollback, unlink,
adoption of leftover runtime state, or automatic retry. After uncertainty,
retain the JSON report and inspect the fixed paths; do not infer that nothing
was created from a missing report.

One bounded JSON report is written to stdout. Exit `0` means this finite parent
inventory was present and checked at return; `1` means inspection found missing
parents; `2` means refusal/error (`130` for interruption). This is local
filesystem provisioning, not release custody or a retained launch capability.
The actual writers still check their filesystem/durability requirements,
fs-verity support, descriptor identities, exclusive fresh resources, originals,
authority and lifetimes. This helper does not test filesystem feature support,
prepare Retrieval objects, write configs/grants/keys/genesis, generate secrets,
provision namespaces, start children, enable services or claim readiness.

The legacy report remains `catchplate.nativePilotResourceRoots/v1` with unchanged
fields. The selected successor reports `catchplate.nativePilotResourceRoots/v2`
and `profile: "adopted-cold"`; neither report carries release authority. The
focused controls in `scripts/test_native_pilot_resource_roots.py` cover the closed
inventories and temporary-tree FD-relative filesystem behavior, not provisioning
of these host paths or an actual cold-to-operational lifecycle.
