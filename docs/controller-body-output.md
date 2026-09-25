# Controller-owned body streams and output manifest

Status: source-implemented, unbuilt and unexecuted. Actual Docker stream capture
and retained-file collection now precede a controller-owned terminal publication
step. The fixed observer exchange client does not provide the still-missing
observer server or genuine event/mapping acquisition; this is not a passing
execution flow or production readiness. The separate
[fixed supervisor](controller-body-launch.md) is also source-implemented.

## Decision: capture before start

The controller subscribes to the exact retained container before sending its
one-use start request. It does not alter the signed workload command, inject
plan IDs into its arguments, replay Docker's rotating logs, or give the workload
a Docker socket. The selected container remains non-TTY with stdin disabled.

The fixed API 1.45 attach request uses `logs=0`, `stdin=0`, `stdout=1`, `stderr=1`
and `stream=1`. It requires HTTP 101, `Connection: Upgrade`, `Upgrade: tcp`, and
`application/vnd.docker.multiplexed-stream`, without a 200/raw-stream fallback.
Moby's versioned implementation installs the stream subscription before sending
this response. This is the source basis for pre-start subscription, not evidence
that our code has run successfully.
([API implementation](https://github.com/moby/moby/blob/v26.1.0/api/server/router/container/container_routes.go#L706),
[subscription ordering](https://github.com/moby/moby/blob/v26.1.0/daemon/attach.go#L40))

```text
signed command + retained container + original deadline
  -> private controller output files -> attach 101 and pending subscription
  -> start gated supervisor -> actual target custody -> observer handoff/ready
  -> root release / actual wait, alongside bounded stdout and stderr capture
  -> observed exit + complete framed EOF + joined capture worker
  -> collect retained streams/payloads and publish manifest [no terminal yet]
  -> fixed observer exchange returns original terminal bytes [server missing]
  -> genuine observer/static/scope admission and actual outcome/output joins
  -> held owner publishes its one fixed controller terminal -> outer destruction
```

The [capture owner](../data-plane/decision-gate-rs/src/docker_body_capture_v12.rs)
decodes eight-byte non-TTY headers, routing only stdout type 1 and stderr type 2.
Padding must be zero and length is unsigned big-endian. Zero-length frames count
toward the one-million-frame ceiling. Unknown/stdin/system-error frames,
truncated headers or payloads, excess bytes, deadline expiry and write failures
reject completion. A frame-boundary EOF is necessary but still must join the
controller's actual wait result; it is not by itself successful workload proof.
([Versioned stream format](https://github.com/moby/moby/blob/v26.1.0/api/swagger.yaml#L7371))

One worker uses a 64 KiB buffer and hashes bytes actually written into separate
files. Each stream is limited to the smaller of 32 MiB and one quarter of the
signed aggregate output capacity. This adds no capacity: streams still consume
the same capped output tmpfs. Overflow aborts rather than accepting a prefix.
Capture failure or panic cancels the concurrent start/wait exchange; cancellation
and error paths shut down the socket and join the worker. Successful finish
does not cancel later collection. Ordinary idle polling does not create a new
deadline. Start, wait, capture and collection all use the earlier of the original
operation deadline and signed command timeout; native work additionally retains
its full 5700-second pre-start admission rule.

## Fixed ownership and inventory

The [output owner](../data-plane/decision-gate-rs/src/body_output_v12.rs) exclusively
creates this mode-0700 root-owned directory within the admitted output tmpfs:

| Path below `.serverware-controller-output-v12/` | Meaning |
| --- | --- |
| `stdout.bin` | Actual captured stdout bytes, including a valid empty stream |
| `stderr.bin` | Actual captured stderr bytes, including a valid empty stream |
| `manifest.json` | Canonical manifest of the signed payload-file set |
| `terminal.json` | Original result, published only after separate genuine admission and final retained-output checks |

Controller leaves are root-owned mode 0600, regular, single-link files. The
payload cannot traverse this control directory. The controller retains its
descriptors and checks name, device, inode, mount, ownership and mode continuity;
renaming or replacing an entry cannot substitute a new original. Directory
timestamps are not frozen across legitimate workload writes. Full metadata
snapshots and exact inventories are checked after exit/collection.

Signed payload paths are literal printable ASCII, at most 4096 bytes and 32
components, with components at most 255 bytes. Empty/dot/parent components,
duplicate paths, file/ancestor collisions and a root component beginning
`.serverware-controller-` are rejected rather than normalized. There are at most
256 paths. The closed payload tree includes exactly those leaves and their
directories plus the fixed controller directory. Legacy worker-root terminal
aliases are rejected, including when listed as expected payload paths; there is
no lane-name/default-name fallback or worker-authored result read. Unknown
files/directories, symlinks and child mounts are not accepted. Traversal rejects
an unexpected entry without descending an unrelated tree.

Payload directories and files retain the private admitted runner ownership;
the signed workload must produce the required private modes. The controller
does not repair permissions or adopt existing control files. Shared
[retained-FD primitives](../data-plane/decision-gate-rs/src/body_output_files_v12.rs)
serve both this collector and native PostgreSQL collection without weakening
the native source/read-only checks.

`CaptureOutputsV12::collect` re-reads and hashes completed stream files and joins
their byte counts/digests to the capture worker's observations. It hashes every
signed payload file and publishes the measured manifest without requiring a
terminal. Its `HeldBodyOutputsV12` retains the actual root/control/payload
directory, file, stream and manifest descriptors; read-only measurement getters
do not provide a transferable proof or a constructor from claimed measurements.
Positional reads let later checks re-read the same original descriptors without
consuming a shared file offset.

The held owner keeps the original nonrenewed deadline and remaining signed
capacity. Inode accounting includes the payload root, every payload directory
and file, the control directory and all four control files; one terminal inode
is reserved before it exists. Logical-byte accounting includes both streams,
payloads and manifest, then admits only a terminal that fits the remainder and
the independent 4 MiB original-result cap. Sparse lengths do not escape this
bound. The kernel tmpfs-cap readback remains a separate requirement, not replaced
by file-size arithmetic or an assumption that publication will have space.

## Manifest and original-result joins

The [manifest contract](../data-plane/decision-gate-rs/src/body_output_contract_v12.rs)
is compact ASCII JSON with exactly `files` and `schema`, where schema is
`serverware.controllerBodyOutputs/v12`. Files are sorted lexicographically by
path. Each record has exactly the sorted fields `bytes`, `path` and `sha256`;
the digest is a lowercase `sha256:` string. There is no trailing newline.
`outputManifestSha256` is SHA-256 of those exact bytes.

Only signed payload files are in the manifest. Streams, manifest and terminal
are excluded to avoid self-hashing, but their actual storage is still bounded.
Manifest publication is exclusive and controller-owned. This two-phase choice
removes the earlier dependency on a terminal existing before the controller had
measured the manifest that terminal must commit.

After the separate [observer exchange and genuine admission](controller-body-evidence.md),
`HeldBodyOutputsV12::finalize` consumes the held owner and original result bytes.
It parses the bounded canonical result, validates its terminal/body-claims
commitments, and compares actual stdout/stderr/manifest hashes. These structural
checks are explicitly not observer-signature authority. The lifecycle must
first authenticate the observer and independently join the execution scope.

Finalization rechecks retained content, identities and exact inventories, then
exclusively creates root-owned `terminal.json` inside the control directory.
It synchronizes and re-reads the actual publication, compares exact original
bytes/hash/length, and rechecks the other originals and inventories before
returning ordinary publication observations. Existing files and uncertain or
partial publication never authorize overwrite, fallback, reset or retry.

For native selection, the generic manifest's exact 33 native records must produce
the same bare-array digest as the independently read and reconciled native
originals. This closes drift between the native and generic collection passes;
the native digest recipe itself is unchanged.

These files are temporary tmpfs observations, not durable exported evidence or
hostile-kernel assurance. A local flush or sync does not prove power-loss
persistence, independent runtime authorship or complete descendant destruction.
Controller publication is implemented; the actual independently measured
observer server, launch/event/mapping acquisition and valid original response
production remain missing. Sending root-measured output fields is not authority
for an observer to blindly sign them; independent observation/reconciliation
still belongs to that missing service. Admitted image/invocation, immutable preparation,
independent service provisioning and consolidated frozen verification remain
required. No test or runtime command ran.
