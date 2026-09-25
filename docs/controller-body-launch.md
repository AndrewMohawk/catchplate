# Fixed controller body supervisor

Status: source implementation, unbuilt and unexecuted. The lifecycle now selects
a fixed supervisor and publishes its independently held launch context. This
does not supply the missing authoritative runtime observer or original terminal
publisher. Those remain mandatory: ordinary child exit is not an accepted body
result, a signed runtime observation, or permission to release anything.

## Separate launch authority from workload arguments

The signed `ContainerCommand` stays unchanged. The controller creates one private
launch directory per lane and binds it read-only at
`/serverware-controller-launch-v12`. Once the full admitted body is available,
it exclusively publishes `launch.json`, binding the plan ID, lane, complete
runner identity and body, and original absolute boottime deadline.

The container invocation is fixed:

```text
/usr/libexec/serverware-coder-body-supervisor-v12
    /serverware-controller-launch-v12/launch.json
```

No caller-selected context path, shell, environment, Docker socket or generic
execution IPC is introduced. The container configuration requires `Env: []` and
working directory `/`. Engine-added ambient variables are ignored by the
supervisor; the child receives only the exact signed environment and working
directory, never inherited process variables. This also avoids inserting a final plan ID
into signed command arguments and creating a commitment cycle.
Moby's [process-environment construction](https://github.com/moby/moby/blob/v26.1.0/container/container.go#L677)
adds defaults even when configured environment entries are empty; those defaults
are not child-command authority.

```text
admitted plan + exact runner and command
  -> retained root-owned launch directory
  -> one-use original context publication -> pre-start Docker inspect
  -> fixed measured PID1 supervisor -> descriptor-pinned workload execution
  -> actual child exit and descendant cleanup
  -> controller capture/output joins
  -> independent runtime observer + terminal publication [still unfinished]
  -> existing authenticated full-generation destruction
```

The context uses a closed, bounded typed JSON recipe. Its identity zeros only
`contextSha256`; exact original-byte admission rejects alternate representations.
The storage owner compares the full create-time command, including its timeout,
not merely `commandSha256`, whose existing recipe does not include timeout.
It also joins the complete runner and body scope. Publication cannot be retried
after partial I/O or reused through a cloned handle.

The root-owned directory is mode 0700 before publication, then 0555, with one
root-owned, single-link mode-0444 regular file. Retained descriptors, name/mount
identity and original-byte hashes are checked before launch and after execution.
The context is controller-write-once and read-only to the container; this is not
a claim of filesystem immutable-flag enforcement or hostile-root protection.
Its custody identity and published context digest join the generation record.

The exact additional read-only bind is mandatory in pre-start inspect. Signed
source/artifact/output destinations cannot overlap the context or fixed
supervisor executable. Other existing resource, private-namespace and mount
restrictions remain unchanged.

## Supervisor scope

The supervisor checks its actual UID/GID, PID1/proc state and restricted process
configuration. These checks do not independently prove isolation from the host;
the controller's separately inspected private launch remains necessary.
It measures its real executable descriptor against the independently admitted
runner pin using the existing immutable, root-owned static-ELF requirements.
The bounded measurement API adds an independent byte ceiling, original-deadline
checks and positional reads without changing the caller's shared file offset.

The child entrypoint is opened once, measured and executed through that retained
descriptor. Supported entrypoints are ELF executables; scripts use an explicitly
signed interpreter executable with the script in its signed arguments. Ordinary
root-filesystem symlinks can resolve within the retained root, but execution does
not reopen the command pathname. The existing effective-argv convention is
preserved: an initial executable argument is not duplicated; otherwise it is
prepended, exactly as the prior Docker Entrypoint/Cmd composition did.
The descriptor-execution choice follows the Linux
[execveat interface](https://man7.org/linux/man-pages/man2/execveat.2.html);
rooted resolution follows [openat2](https://man7.org/linux/man-pages/man2/openat2.2.html).

One supervised child receives the payload streams directly. The supervisor adds
no messages to stdout or stderr. It observes exec failure and actual exit,
forwards termination signals, and reaps children within its private PID1 scope.
Execution uses the controller's absolute deadline, never a newly granted
duration. Any extra cleanup allowance is kill/reap-only, not permission to keep
running work. Outer controller cancellation and full-generation destruction are
still required. Synchronous kernel file I/O cannot be forcibly preempted by a
userspace deadline; late completion is rejected before accepting its data.
Linux's [PID-namespace rules](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
are the basis for namespace-local reaping and init-exit cleanup, not proof that
this implementation has executed correctly.

This is supervision, not continuous observation of descendant/transient mappings
or independently signed launch events. No observer key is embedded, no absent
runtime fields are synthesized, and no `BodyExecutionResultV12` is fabricated.
An admitted image containing the genuinely immutable static supervisor, its
closure pins, observer ownership and terminal producer must still be prepared.
The observer design also needs an explicit treatment of kernel-provided
executable mappings: the current file-backed mapping contract cannot represent
`[vdso]` as an ordinary file. This checkpoint neither invents backing-file
digests nor silently accepts a smaller observation scope.

## Readiness transport repair

The local upgrade readiness probe previously passed forbidden connection headers
to the generic close-only HTTP builder. It now has a separate fixed recipe:
`POST` to the independently pinned target, `Host: docker`, `Connection: Upgrade`,
`Upgrade: serverware-readiness`, and `Content-Length: 0`. Its generated exact
header must still match the independently signed fixture pin. Generic Docker
HTTP header restrictions are unchanged.

The bounded local socket-pair exchange verifies the exact 101 response, a real
server payload byte before client half-close, the complete client stream and
EOF, then the remaining server bytes and EOF. Both streams have a 16 MiB ceiling;
client data must be nonempty and server data at least two bytes. All I/O shares
one original deadline, and every worker is joined on success or failure. This
is a local readiness transcript, not evidence of an actual Docker daemon attach.
The unsigned release-asset preparer checks these payload sizes before and after
copying supplied originals. It does not generate or replace the independent
signed header pin, stream pins or fixture signature.

## Verification boundary

No build, formatter, interpreter, test, container or runtime verification ran.
The implementation-first phase continues. The exact source must be frozen before
immutable preparation and consolidated sequential verification. Historical
results do not cover these changes; production Nitro/KMS, signing and witness
services remain unprovisioned.
