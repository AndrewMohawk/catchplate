# Controller-owned body streams and output manifest

Status: source-implemented, unbuilt and unexecuted. This connects actual Docker
stream capture and retained-file collection to the existing body-result consumer.
It does not provide the missing runtime observer or terminal-result publisher,
and does not establish production readiness. The separate
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
  -> actual start / wait, alongside bounded stdout and stderr capture
  -> observed exit + complete framed EOF + joined capture worker
  -> re-read streams and collect exact signed payload-file inventory
  -> publish canonical manifest and compare original terminal commitments
  -> unchanged independent observer/static checks and outer destruction
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
256 paths. The closed output tree includes exactly those leaves and their
directories, the fixed controller directory, and one selected existing terminal
basename. Unknown files/directories, both terminal spellings, symlinks and child
mounts are not accepted. Traversal rejects an unexpected entry without descending
an unrelated tree.

Payload directories and files retain the private admitted runner ownership;
the signed workload must produce the required private modes. The controller
does not repair permissions or adopt existing control files. Shared
[retained-FD primitives](../data-plane/decision-gate-rs/src/body_output_files_v12.rs)
serve both this collector and native PostgreSQL collection without weakening
the native source/read-only checks.

The collector re-reads and hashes actual completed stream files and joins their
byte counts/digests to the capture worker's observations. It hashes every signed
payload file, retains identities through the final checks, and bounds aggregate
logical bytes and inode count against the signed output limits. This accounting
also includes streams, manifest and terminal storage; sparse lengths do not
escape the logical-byte bound. The existing kernel tmpfs-cap readback remains
a separate requirement, not replaced by file-size arithmetic.

## Manifest and original-result joins

The [manifest contract](../data-plane/decision-gate-rs/src/body_output_contract_v12.rs)
is compact ASCII JSON with exactly `files` and `schema`, where schema is
`serverware.controllerBodyOutputs/v12`. Files are sorted lexicographically by
path. Each record has exactly the sorted fields `bytes`, `path` and `sha256`;
the digest is a lowercase `sha256:` string. There is no trailing newline.
`outputManifestSha256` is SHA-256 of those exact bytes.

Only signed payload files are in the manifest. Streams, manifest and terminal
are excluded to avoid self-hashing, but their actual storage is still bounded.
Manifest publication is exclusive and controller-owned. The original body
result must match both re-read stream hashes and the actual manifest digest.
The terminal file's later observed hash/length must also match the exact bytes
already parsed, preventing replacement between those reads.

For native selection, the generic manifest's exact 33 native records must produce
the same bare-array digest as the independently read and reconciled native
originals. This closes drift between the native and generic collection passes;
the native digest recipe itself is unchanged.

These files are temporary tmpfs observations, not durable exported evidence or
hostile-kernel assurance. A local flush or sync does not prove power-loss
persistence, independent runtime authorship or complete descendant destruction.
The missing measured observer/terminal publisher, admitted image/invocation, immutable preparation and
consolidated frozen verification remain required. No test or runtime command ran.
