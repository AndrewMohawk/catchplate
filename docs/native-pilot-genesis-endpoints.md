# Cold endpoint ownership and authority

This continues the [cold ordinary services](native-pilot-genesis-ordinary.md).
It adds a distinct two-endpoint owner, cold credential-delivery and signing
inputs, and complete late coordinator runtime validation. These are source
components, not a provisioned or accepted pilot. Production remains **0/6**;
source milestones remain **36/46**.

## Ownership and authorization

The fixed `--parked-genesis-endpoints` native controller creates exactly two
parked children: `publicationGenesisRetrieval` and `publicationGenesis`.
It exports their actual PIDFDs and sealed-executable observations. It does not
select any hot-cohort role. A separately pinned root control and protected
`/etc/catchplate/native-publication-genesis-endpoints.json` authorize creation;
the coordinator's signed precreation supplies the original window, not endpoint
selection or permission to load keys. This deliberately avoids another
precreation signature that would add no authority to the protected selection.

The Python `GenesisEndpointControl` retains the real native parent, both
descendant PIDFDs, executable/cgroup observations, resources and originals.
Retrieval owns its listener, empty object directory, locked spool directory and
lock descriptor. Publication owns one listener. After authenticating C9, the
resource owner writes, fsyncs and rereads the actual sequence-zero store genesis;
the grant issuer cannot manufacture it from a supplied head or DTO.

The separate endpoint release authority signs both exact launches and approved
image pins. Its key must differ from the coordinator's precreation, release
and C9 keys and from the endpoint C9 keys. All five activation descriptors are
transferred once; both images and admission inputs are prepared before either
child gate opens. The acknowledgement means gates opened, not service readiness.
Stopping is acknowledged only after actual child reap. Unknown cleanup retains
ownership instead of reporting success; persistent names are not silently
deleted or adopted for a subsequent ceremony.

Public parsing authenticates source associations and signatures, not the
provenance of a process observation. Native admission still owns the live FD,
image, key-import, grant, peer and lifetime checks. No new code here generates
production keys, approves its own input, contacts AWS or renews a deadline.

## Acyclic issuance order

1. Approve the static three-member closure set, current assignment, cold binding
   and actual parked observations. Endpoint runtime images remain static.
2. Sign each endpoint C9 delivery, role-key assignment, key admission and
   Closure/Assignment v6 using those complete originals.
3. Issue Publication's native grant from the actual DRS/CSA initial epochs,
   endpoint guests and assigned Retrieval public key. It contains no future
   Retrieval grant hash.
4. Issue Retrieval's grant from that exact Publication original and the actual
   persisted sequence-zero store observation. Issue the two ordinary grants.
5. Assemble the complete coordinator Runtime/v2 and sign its C9/key/closure
   originals. Its image measures BootstrapRuntime/v1; C9 hashes the entire late
   runtime, not just the bootstrap. Release only after all required native
   admission inputs and retained resources are available.

The coordinator's signing role policy must be explicitly approved and nonempty
under the existing native key-admission contract. This producer supplies no
default role and cannot infer supervisor authority. Endpoint roles are fixed
singletons: Retrieval response and Publication reconciliation respectively.
Encrypted-key and verifier producers remain a separate unfinished cold intake.

Runtime validation authenticates both initial histories and root-signed grants,
checks the shared scope and original intervals, and joins coordinator and service
PID/start/executable facts. A source review fixed an impossible native comparison
between the peer-identity v4 hash and the isolated-service history identity hash:
their schemas and domains differ. The receiver now compares their common fields
without changing either digest or weakening actual peer admission.

## Packaged signing commands

The isolated publication entrypoint retains its separate package/input pins and
private key FD rules. It adds these fixed, source-selected combinations:

| Command | Selection |
| --- | --- |
| `--sign-genesis-native-{retrieval,publication,coordinator}-delivery` | Exact cold C9 delivery |
| `--sign-genesis-native-{retrieval,publication,coordinator}-role-keys` | Role-key assignment/v2 |
| `--sign-genesis-native-{retrieval,publication,coordinator}-admission` | Key admission/v1 |
| `--sign-genesis-native-{retrieval,publication,coordinator}-closure` | Closure/Assignment v6 |
| `--sign-genesis-native-publication-grant` | Publication-first native grant |
| `--sign-genesis-native-retrieval-grant` | Retrieval-second native grant |
| `--sign-genesis-endpoints-release` | Exact two-endpoint gate release |

Brace notation abbreviates three literal commands, not a wildcard accepted by
the program. Selected purpose and role are checked before private-key access.
Output and final package closure remain inside the earliest original BOOTTIME
and applicable UNIX ceilings. Complete output plus successful exit is required.

## Verification and remaining work

Native revision `24464781e83d2be782a401a436b76114efc12e87` passes the cached,
offline Rust 1.88 check for the gate, DRS, CSA, genesis controller and adoption
validator in **2m56s**. The first frozen attempt (`ef2bad82`) found a visibility
keyword typo; both attempts are retained. The pinned toolchain image reference
was restored after a missing-image preflight; its existing layers were reused.
No dependency update or release-image rebuild occurred. Compiler warnings remain
(312 library; 2,053 each DRS/CSA; 2,568 gate; 2,793 controller; 3,108 validator,
including duplicates).

Python integration revision `8e9459d508b379c57c4eb48d804566b41acd3b5a` passes
**59 focused controls in eight suites** in **10.294 seconds**, twenty-file
Python 3.11.15 grammar and both Make inventories. It uses one frozen source
archive, one CPU, an empty environment and an isolated network namespace.
Native source is unchanged from the passing native revision and was not rebuilt.

These tests use deterministic synthetic signatures and observations; they do
not launch owners, native services or signing entrypoints. The positive paths
authenticate real-format test signatures, not mocked validators. They cover
three C9 roles, full-u64 namespaces, late runtime/history/grant joins, key and
closure domains, Publication-first/Retrieval-second issuance, endpoint release,
protocol shapes and fixed CLI selection. Actual resource creation, descriptor
transfer, key import, cleanup and connected commissioning remain unexecuted.
An offline compiler check is not native runtime acceptance or an approved
release artifact.

Exact archives, commands, logs and checksums are retained at
`codex-offload/catchplate/engineering-builds/8e9459d5-genesis-endpoints-jApq7d/`.
No cloud resource, paid test or broad unchanged test suite was used.

The next [cold launch and coordinator assembly slice](native-pilot-genesis-assembly.md)
connects encrypted-key/verifier inputs, public launch bundles and retained
coordinator resources. Its verification boundary is recorded separately.

Still required: the expanded commissioning and public installation graph; retained cold
core transfer and actual adoption-signer ownership; operational composition and
uncertain recovery; independent release/Nitro/KMS/signing/witness provisioning;
and connected allow/deny, lifecycle, provider and hardware acceptance. The older
hot graph's 164 jobs and 113 selectors do not include this cold commissioning.
