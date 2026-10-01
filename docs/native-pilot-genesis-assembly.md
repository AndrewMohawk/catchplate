# Cold launch and coordinator assembly

This continues the [cold endpoint and authority work](native-pilot-genesis-endpoints.md).
The new connections cover encrypted-key delivery, verifier authorization, public
launch bundles and the retained coordinator's actual outgoing resources. They
do not provision services, approve their own inputs or establish a running pilot.

## Key delivery and launch bundles

The cold producers accept only `publicationGenesisRetrieval`,
`publicationGenesis` and `publicationGenesisCoordinator`. They authenticate the
complete cold C9, assignment and key-admission originals instead of selecting a
hot-cohort role. Supplied encrypted inventory bytes must match the C9 credential
and KMS transport pins. This checks the public ciphertext association; it does
not perform KMS decryption or prove enclave key custody.

Verifier authorization retains the existing native signature domain and an
explicit parent port. Each cold role has its own source-fixed verifier path.
Role, signing authority and original intervals are checked before the packaged
entrypoint reads private key bytes. No new production key is generated.

Launch assembly is keyless. It authenticates the complete predecessor originals
and produces a public bundle containing the literal unsigned native launch and
its component originals/pins. Publication and Retrieval retain their distinct
native grants; the coordinator uses its complete late Runtime/v2. Bundle
creation is neither installation nor permission to release a child. The actual
native image/key/grant admission and separately signed releases remain required.

The packaged commands are fixed combinations:

| Command | Output |
| --- | --- |
| `--sign-genesis-native-{retrieval,publication,coordinator}-encrypted-delivery` | Existing native encrypted-key delivery authorization |
| `--sign-genesis-native-{retrieval,publication,coordinator}-verifier` | Existing native verifier transport authorization |
| `--assemble-genesis-native-{retrieval,publication,coordinator}-launch` | Public launch bundle, without a signing key |

Braces abbreviate three literal commands. They are not caller-selected modules
or wildcard arguments. Complete input and installed runtime pins remain
independent; complete output and successful process exit are both required.

## Coordinator resources and approval order

The actual retained coordinator, ordinary-service and endpoint owners supply the
process observations and resources. Preparation precedes independent approval,
so the approver can bind real PID, executable and cgroup facts instead of
predicting them. Public observation JSON cannot recreate any of these owners.

The coordinator receives this fixed inventory:

| Native descriptors | Source |
| --- | --- |
| 6–9 | Two ordinary-service sockets and their listener directories |
| 10–13 | Publication and Retrieval sockets and their listener directories |
| 14–15 | Result pair already created and retained by the native controller |

The four outgoing sockets are intentionally **unconnected**. The native
coordinator connects after adopting its final service identity and performs
the real peer authentication. Root must not pre-connect them. Python transfers
only its eight actual outgoing descriptors; it neither duplicates nor fabricates
the native controller's result pair.

Runtime assembly joins authenticated histories, grants and the exact observed
peers. Activation metadata comes from the retained descriptors, not from a
template. All phases retain the original BOOTTIME and applicable UNIX ceilings;
later assembly, output or cleanup cannot restart those intervals.

## Verification and remaining work

Verification for this source batch is pending. No live owner, native service,
privileged signing entrypoint, KMS call or connected commissioning run has been
performed in this batch. Source checkpoints remain **36/46** and production
acceptance **0/6**.

The full independently operated commissioning graph, public installation,
retained cold-core transfer and adoption-signer ownership are still required.
Ordinary-service cleanup also needs an actual helper-reap protocol: killing the
direct service bypasses its inspection worker destructor, so direct-child exit
cannot prove helper retirement. The current owner correctly retains resources
on that uncertainty; coordinator completion must not claim all-service cleanup.

Operational recovery and authority transitions, independently approved release
dependencies, Nitro/KMS/signing/witness provisioning, and connected application
allow/deny, lifecycle, provider and hardware acceptance remain open. The older
hot graph's 164 jobs and 113 selectors do not include this cold commissioning.
