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
```

No arbitrary path, identity, profile or repair option exists. Both modes retain
and recheck the actual directory descriptors/names, reject symlink traversal,
and require root:root ancestors without group/other write permission. Existing
resource parents must be exactly `0711` and empty; any leftover entry refuses.
Checks read at most one entry per leaf. The generation container admits only
the five fixed role names and each role directory must itself be empty.

| Fixed parent(s) | Actual later writer and fresh child |
| --- | --- |
| `/run/serverware-custody-business`, `/var/lib/serverware/custody-business` | `BusinessResources` creates the five role directories, listener sockets and role-specific business directories. Do not precreate the roles here. |
| `/var/lib/serverware/custody-generation/{durable-recovery-store,cleanup-authorization-consumer,recovery-target-provider,current-signature-authority,bounded-cleanup-helper}` | `GenerationInputs` requires these existing role parents, then creates `generation-journal` and the selected dispatch/spool journals. |
| `/run/serverware-shadow-{retrieval,persistence,trusted-time,generation-install,commit-request,ingress-admission,terminal-append,dispatch-barrier,active-effect-barrier,active-effect-commit}` | The respective retained native owners create their real `listener.sock`; this helper never creates a socket. Braces denote the fixed literal inventory, not a caller-supplied pattern. |
| `/var/lib/serverware/native-ledger-spool` | `SpoolInputs` creates the original invocation-ID directory and held `ledger.lock`; the helper leaves this root empty. |
| `/var/lib/serverware/native-shadow-persistence` | `PersistenceInputs` creates fresh `journal`, then its held lock and independently admitted originals. |
| `/var/lib/serverware/native-shadow-generation-install` | The GenerationInstall resource owner creates fresh `journal`, `generation.lock` and supplied genesis/record originals. |
| `/run/serverware-native-pilot-bridge`, `/var/lib/serverware/native-pilot-bridge` | The bridge resource owner creates its listener and `production-journal`; the helper leaves both parents empty. |

New resource parents are root:root `0711`. The two shared containers
`/var/lib/serverware` and `/var/lib/serverware/custody-generation` are created
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
