# Actual native bridge outgoing resources

`OutgoingResources.prepare(driver)` creates real unconnected outgoing resources
for the same live `DriverBootstrap`. It consumes the fixed protected provisioning
original `/etc/serverware/native-shadow-driver-outgoing.json`, binding the exact
bootstrap configuration, original window, actual driver observation, invocation,
C9 cold configuration, intended runtime bytes, and explicit native launch purpose.
It does not sign, generate keys, contact endpoints, or claim readiness.

The allocation original is staged before the final C9 delivery signature so that
the signer can bind actual allocated socket identities. It is not itself a grant:
the existing independently pinned C9 authority must sign the complete runtime and
activation inventory afterward. The existing phase-two authority then signs that
full operation under the unchanged original startup/lifetime. No digest fixed
point, new signer, new permission, or authority-history alias is introduced.

## Fixed selection and ownership

| Native launch | Actual bridge runtime | Native signer exclusions | Ordinary outgoing endpoints |
|---|---|---|---|
| v1 | v5, generationAdmission | none | 15 |
| v2 | v6, generationAdmission + commitRequest | LedgerAppend | 14 |
| v3 | v7, preceding fields + spool | LedgerAppend, IngressAdmission | 13 |
| v4 | v8, preceding fields + explicit completion spool/v2 | LedgerAppend, IngressAdmission, TerminalAppend | 12 |
| v5 | v9, preceding fields + explicit effects spool/v3 | preceding three, DispatchBarrier, ActiveEffectBarrier, ActiveEffectCommit | 9 |

All four actual native proof endpoints are excluded in every row. The producer
requires exactly the existing five service roles, ten signer roles, and four
proof kinds. Native endpoint paths are the source-fixed proof/commitment/spool
paths. No caller-supplied exclusion list or runtime flag can select them.
The full existing Rust runtime/grant/history/currentness admission remains
mandatory; the resource selector does not replace those semantic checks.

After filtering, activation names are lexicographically sorted. Endpoint ordinal
`n` receives its original runtime socket name and the fixed directory name
`bridge-outgoing-directory-{n}`. Every socket is fresh, unnamed, unconnected,
AF_UNIX/SOCK_SEQPACKET, CLOEXEC/NONBLOCK, owned by the actual bridge C9 UID/GID.
SO_PASSCRED is enabled and SO_PASSPIDFD explicitly disabled to preserve the
ordinary credentials/rights framing. There is no root connect or root credential
relabel. Only the actual Rust owner connects after permanent role drop.

Directories are actual retained O_RDONLY/O_DIRECTORY descriptors, not O_PATH or
caller JSON. Every pathname ancestor is retained and checked as root:root and
non-group/world-writable, without symlink traversal. The real socket leaf must
already have the independently expected server UID, bridge GID, and mode0660.
Its original identity is retained and rechecked. This producer creates no target
directory or listener and adopts no old invocation state.

The existing C9 and driver-operation inventories prohibit inode aliases. Thus
each outgoing endpoint must have a distinct actual parent directory: using two
names for duplicate FDs into one directory is refused, not given invented inode
identities. A future shared-parent-directory profile would need an explicit
paired admission change. Current complete-transfer ceilings (64 C9 activations,
94 operation inputs, 96 total rights) remain unchanged; a complete inventory
that does not fit is rejected before transfer.

## Genuine caller and release

The actual operator flow is:

1. Start the real driver; for lifecycle v4 consume its genuine gate binding.
2. Provision the exact intended public runtime and outgoing allocation original.
3. Call `OutgoingResources.prepare(driver)` and obtain `activation_originals()`.
   These are actual descriptor facts for the independent C9 signer, not a
   synthetic activation or process measurement.
4. Independently supply the exact signed C9 delivery/full native launch originals
   and the other genuine native/business resources. Call
   `OperationalInputs.prepare_outgoing(driver, outgoing=owner, ...)` with only
   those other resources in `activation_fds`. The caller cannot override an
   allocated outgoing socket/directory. Actual C9 verification checks the whole
   merged inventory, and runtime/launch originals must match the retained owner.
5. Sign the existing exact operation through the independent phase-two authority
   and use `DriverBootstrap.continue_scope`. The resource owner is consumed once
   immediately before the original irreversible send. No resend or replacement
   follows uncertainty. The Rust parent keeps exact duplicates; its selected
   post-drop bridge connects through the retained directory FD and authenticates
   the actual peers.

The owner is retained through construction and actual child exit. Operational
checks preserve inode, ancestor, socket mode, and original time bounds even after
connection. The established caller closes resources only after its actual cleanup;
v4 additionally requires the genuine subtree-terminal original. Preparation
failure closes only newly created socket/held directory FDs. No endpoint files,
journals, or directory trees are removed. Failed allocation cannot reset that
driver invocation into a second resource attempt.

## Integration and evidence boundary

The paired [Rust inspector and post-drop connector](native-shadow-facade-inspection.md)
consume these actual resources through the same full-admission bridge. The v7
spool profile additionally requires its genuine independently implemented
IngressAdmission and LedgerAppend owners; the resource selector alone does not
enable that path. The explicit v8 completion profile also requires the actual
separate [TerminalAppend owner](native-shadow-terminal-cohort.md). The explicit
v9 effects profile retains a separate cleanup grant original and requires the
three independently assigned [effect signers](native-shadow-effects-cohort.md).
Native proof socket
resources, production listener/journal, and generation-origin remain their actual
separate owners; they are never fabricated here. The native remote facade/full
configuration binding remains its separate required implementation.

Source only: no parser/build/test/runtime, resource allocation, signing, key
generation, provisioning, provider contact, or cloud action was performed.
