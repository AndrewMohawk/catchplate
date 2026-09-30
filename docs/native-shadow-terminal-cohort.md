# Native terminal service launch

The explicit fixed-eight profile connects the independently assigned terminal
signer to the existing native ledger. This is source implementation, not a
built service, installed authority, successful operation or verified pilot.

`nativeShadowProofCohortConfiguration/v5` adds `terminalAppendConfiguration` to
the fixed-seven configuration. The actual retained parent creates eight children
in order: Retrieval, Persistence, TrustedTime, GenerationInstall, Bridge,
Ledger/CommitRequest, IngressAdmission, TerminalAppend. Each has its own pinned
cold configuration and distinct non-root UID/GID. All share the original signed
creation/startup/lifetime window; adding a service never extends that window.

| Owner | Explicit selector |
| --- | --- |
| Bridge | `nativeProofBridgeLaunch/v4`, production runtime/v8 |
| Ledger | `nativeShadowCommitRequestGuestLaunch/v3`, Ledger assignment/v2 |
| Retrieval | `nativeShadowRetrievalGuestLaunch/v3`, retrieval grant/v2 |
| Terminal | `nativeShadowTerminalSpoolGuestLaunch/v1`, `terminalSpool` pin |

Old five/six/seven configurations retain their exact selectors and refuse the
extra child or completion grants. The fixed-eight observations, release,
cleanup authorization, terminal observations and cleanup result use version4.
Release and cleanup signatures have their own version4 domains. Precreation
remains purpose-limited to creating retained resources, not admitting services.

## Actual resources and grants

The existing retained spool input owner creates one additional unconnected
AF_UNIX sequential-packet listener at
`/run/serverware-shadow-terminal-append/listener.sock`. It keeps the listener and
parent directory, socket identity and original C9 descriptor assignments until
the cohort is reaped. Existing paths are refused, never unlinked or adopted.
The Terminal child receives `terminal-append-listener`; the Bridge receives
`terminal-append-peer-directory` and its own actual outgoing socket.

The exact peer is derived from the real parked child and signed C9 runtime,
not a caller-selected PID or arbitrary socket path. The retained parent checks
the actual peer identity before and during traffic. Terminal gets its own
`TerminalAppend` session, never an alias of the Ingress or Ledger signer.
Both ordinary launch and the native driver's after-drop continuation carry
the same explicit completion selection and retained inspection ownership.

The Python authoring API has separate completion Ledger, Terminal, Retrieval,
and head/current signing entrypoints. Callers must supply actual approved
originals and independently provisioned keys. No key generation is provided.
Terminal has only its assigned terminal-signing role and no request HMAC.

Head grant/v2 retains the existing scope and adds the separately assigned
Terminal key/grant binding plus signed `regularAppendCapacity` (1–32).
Current grant/v2 embeds that exact head original. The real sealed-grant owner
requires four native originals and joins every grant to the same current C9
peer, assignment and scope. Retrieval grant/v2 binds the same Terminal key.
Bridge selection `nativeSpoolServices/v2` requires production runtime/v8;
the ordinary DRS/current service runtime/v7 inventory stays unchanged.

## Completion and cleanup are different

The [ledger completion implementation](native-ledger-completion.md) owns the
actual terminal append and definite capacity-unavailable result. The signed
capacity is evaluated against the retained DRS committed-append count, not a
timeout, failed RPC or uncertain write. Early sampling remains a different
commitment from the later protected request facts.

Cohort cleanup still requires actual terminal PIDFD observations and reaping
all eight owned children. That cleanup result is not business settlement,
enclave attestation, generation installation or permission to resume an unknown
operation. Barrier/compaction events, no-generation ingress authority, final
Setup, independent provisioning and consolidated acceptance remain separate.

Schema: [fixed-eight cohort](../schemas/native-shadow-proof-cohort.v5.schema.json).
This batch is built-first source work: no project build, parser, signing,
runtime or test suite has been executed.
