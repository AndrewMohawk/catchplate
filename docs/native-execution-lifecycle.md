# Native execution and terminal cleanup

This source is unbuilt and unexecuted. It connects the actual bootstrap entrypoint
to one native execution attempt, not a tested pilot, persistent deployment,
enclave custody or provider acceptance.

## Explicit selection and original owners

Only the independently pinned
[`nativeBootstrapClient/v5`](../schemas/native-bootstrap-client.v5.schema.json)
configuration selects execution. It requires nonnull `egress`, `attachment`
and `execution` originals and forbids `installation`, even null. Earlier
profiles reject `execution`, even null. A diagnostic response cannot upgrade an
old owner. The execution object contains four artifact roles: `authority`,
`authorityRoot`, `capabilityToken` and `executionManifest`.

Separate signed start constraints join egress authorization v4, launch manifest
v2, attachment, immutable EROFS/fs-verity image, static/dynamic ELF, isolation and
resources, and original absolute start/stop/cleanup deadlines. Cold preparation
precedes bootstrap contact; actual TLS proof and retained originals are then
consumed by the executable-parent binder. No parsed successful result replaces
those owners.

This profile does not implicitly install a CA, provision bridges/routes/NAT/DNS,
provide a writable workspace, or mount host proc/dev filesystems. Required
application dependencies and trust must already be in the admitted image.
Combined CA installation, broader workload profiles and production enrollment
remain separate integration work.

## One execution, not a reusable permission

```text
prepared start and executable parents → durable start/creation claims
  → new limited cgroup → actual isolated child → positive pre-exec ptrace stop
  → independent guardian READY → same-child firewall/attachment readback
  → consumed release latch → one gate send and PTRACE_CONT
  → positive original-leader EXEC → final network/guardian checks → DETACH
  → bounded lifetime observation → exact leader reap + both leaf-empty facts
  → guardian reap + bounded output EOF → nonactionable terminal capture
```

The genuine network-ready owner is moved into `GuardedChild::run_and_finish`.
Its private execution borrow cannot clone or serialize it. Bridge, journal and
backend owners stay retained through both cleanup paths. The child release latch
is burned before the sole send; short send, uncertain continue, wrong stop or
absent EXEC acknowledgement permit no retry. Gate EOF and pre-exec exit 127 are
not successful execution.

The exact first EXEC stop and original former-thread identity are observed
before user code executes. Final checks still use the original admission window.
Only then does `PTRACE_DETACH` return normal signal handling to the application;
the guardian remains armed for its whole signed lifetime. Kernel semantics follow
[ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html) and exact-pidfd
[waitid(2)](https://man7.org/linux/man-pages/man2/waitid.2.html).

## Continuation does not renew admission

Read-only continuation requires the consumed child, actual process/thread,
unchanged namespaces, start/creation journal integrity, original leaf and signed
resource limits. The absolute stop projection is never recomputed from now.
Additional processes in the bounded leaf are allowed; child cgroups and loss of
the exact leader association are not. The first running check, while the exact
EXEC stop is still held, performs the final firewall/attachment semantic readback
within the original aggregate query budgets. Later lifetime checks are query-free
child/socket/namespace/lock ownership checks. No counter reset, fresh query budget
or claim of continuous kernel-state sampling is introduced. Independently
privileged host mutation remains outside this trusted-launcher boundary.

No bootstrap, CA, TLS, approval, attachment or filesystem admission is renewed.
Continuation cannot clone, resend exec, claim a journal, write networking or
repeat provider effects. Failure requests exact-child and whole-leaf termination;
the guardian's independent absolute timer remains armed.

Stdout/stderr are drained fairly into fixed-memory byte counts and SHA-256
digests under the signed combined byte limit. Raw application bytes are not
printed or returned. A complete summary requires both EOFs after child cleanup
and before the original cleanup deadline; partial output never becomes complete.

## Terminal facts and failures

Natural exit is observed with `WNOWAIT`; cleanup separately reaps the actual
leader and compares its exact code/status. Leader exit does not authorize
surviving descendants. Launcher and guardian have independent one-shot kill
attempts, not a global exactly-once guarantee. Both empty observations and exact
guardian reap are mandatory. Cleanup and output observation are attempted before
returning run/cleanup errors; destructors never assert successful completion.

The closed
[`nativeExecutionObservation/v1`](../schemas/native-execution-observation.v1.schema.json)
has `actionAuthorization: null` and `okForAction: false`. `workloadSucceeded`
means only normal zero exit, not health or a successful provider/credential flow.
A nonzero terminal exit may be captured, but the launcher still fails. The four
network hashes identify the retained installation's historical semantic/evidence
originals, not a new permission or a claim that every network instant was sampled.
Uncertain or incomplete execution/cleanup produces no successful terminal capture.

[`nativeBootstrapClientCapture/v5`](../schemas/native-bootstrap-client-capture.v5.schema.json)
retains exact bootstrap evidence and is emitted only after process/cgroup cleanup. A blocked
capture writer cannot keep a workload alive. Delivery does not renew admission.
These cleanup facts do not claim independently observed host-link disappearance,
cgroup-directory removal, journal archival or restart permission.

## Remaining evidence

No build, parser, test or runtime verification has run. Frozen verification must
cover actual kernel/permissions and originals, same-child networking, normal and
failed exec, dynamic dependencies, signals/processes, parent/guardian death,
deadlines, output overflow, exit/cleanup races and surviving resources. These
local observations are not hostile-kernel isolation, off-host rollback evidence,
Nitro/KMS proof or production completion.
