# Controller body result and observer binding

Status: source-implemented admission, observer client and controller terminal
publication, unbuilt and unexecuted. The actual observer server and independent
launch/event/mapping acquisition remain unfinished and unprovisioned. A
[receiving-side target and gate owner](controller-body-observer-acquisition.md)
now validates actual handed-off descriptors but sends no ready response. A
[fixed supervisor and launch owner](controller-body-launch.md) and
[controller-side stream/output collection](controller-body-output.md)
are now source-implemented but unexecuted. This document does not
authorize verification or provide passing execution evidence.

## Why this contract changed

Tracing the missing result producer found three concrete source blockers:

- The lifecycle used the v11 request encoder for v12 Docker configuration and
  terminal results. That encoder permits only the integer `11`, so ordinary
  exit codes, resource sizes and digest arrays could not pass.
- Observer signature verification serialized a 32-byte digest to a JSON array
  and then required it to be a string. No normal digest could reach signature
  verification.
- The observer's signature did not cover the complete runtime/body claims.
  Comparing a namespace value with the same result's namespace did not supply
  independent observation. Runtime executable/rootfs pins and the two mapping
  inventories also lacked exact joins.

Those admission repairs are now followed by a retained-output publisher and a
fixed observer client. A helper that merely fills the required fields still
cannot replace missing process observations or an independently authorized
observer. No successful runtime flow is inferred from the client/publisher source.

## Separate byte formats

The legacy v11 signature/request encoder is unchanged. The private v12
[lifecycle JSON codec](../data-plane/decision-gate-rs/src/dind_json_v12.rs) admits
exact signed/unsigned 64-bit integers, sorted UTF-16 object keys and ordinary
Serde JSON string escaping. It rejects floating point and bounds output to
16 MiB, nesting to 64 edges and values plus object keys to one million nodes.
It is a purpose-specific integer JSON profile, not general RFC 8785 floating-
point canonicalization. V12 Docker requests, inspection/storage identities,
source/archive metadata and native prepared-manifest comparison use it.

The [shared body contract](../data-plane/decision-gate-rs/src/body_result_v12.rs)
is consumed by both the root lifecycle and plan executor. Original terminal
bytes must fit the existing 4 MiB plan frame and pass a bounded structural scan,
closed typed parsing and exact canonical wire reconstruction. Duplicate or
unknown fields, alternative encodings, floats and an explicit null in place of
an omitted native option are rejected. Wire object keys are sorted; all admitted
keys in this closed schema are ASCII.
The corresponding bounded `original_bytes` encoder preserves that exact wire;
it does not obtain runtime observations or sign observer claims.

The existing terminal digest recipe is preserved: serialize the typed result
in its declared field order with `terminalSha256` zeroed, then SHA-256 those
compact UTF-8 bytes. This digest representation is intentionally distinct from
the sorted-key original wire representation. Do not hash the original terminal
file including its own digest or substitute a differently ordered object.

## Acyclic signed claims

The enclosing body/runtime types remain v12. The embedded observer evidence is
now exactly `catchplate/runtime-observer-evidence/v13`; old v12 observer records
are not accepted or silently upgraded. It adds required `runtime_claims_sha256`
and `body_claims_sha256` fields.

```text
actual runtime observations + independently held launch context
  -> explicit runtime-claims digest (no observer or final report digest)
actual body outcome + streams/outputs + static evidence + runtime-claims digest
  -> explicit body-claims digest (no observer or terminal digest)
both digests + actual observer identity/events/mappings
  -> observer canonical digest -> independent observer signature
signed observer + complete runtime claims -> runtime-report digest
complete body result -> existing zero-terminal-field digest -> original wire
```

Both claims projections enumerate their fields explicitly in source. Runtime
claims cover the image, runtime executable/rootfs, source/artifacts, proxy peer,
namespace/cgroup identities, executable mappings, runner identity, inherited
proxy executable and command. Body claims cover version, plan/lane/body/command,
exit status, stdout/stderr/output-manifest digests, both static executable
records, the runtime-claims digest and the optional native inventory digest.
Adding a wire field requires deliberately updating the corresponding projection.

Observer canonical digest calculation retains the typed compact-JSON recipe:
zero `canonical_evidence_sha256` and clear `observer_signature_b64`, retaining
both claims digests and every other observer field. The Ed25519 message is
exactly the bytes `catchplate/runtime-observer-evidence/v13`, one NUL byte, then
the raw 32-byte canonical evidence digest. The signature must be exactly 64 bytes
encoded as canonical padded standard Base64, with no whitespace or alternatives.
This framing is explicit; it is neither digest JSON nor a hex string.

The independently pinned observer key/executable policy still authenticates the
signature. Runtime admission recomputes the full claims digest, joins the cgroup
identity to the namespace record, and compares the declared image, executable,
rootfs, runner identity and proxy/command with independently admitted pins.
Both mapping inventories must be nonempty, sorted, nonoverlapping and bounded
to 4096 entries, with exact matching runner intervals and content hashes.
Positional permissions must agree with executable, nonwritable file-backed
mappings; arbitrary four-character permission strings are not accepted.
The body consumer separately recomputes and joins the signed body-claims digest.

The root lifecycle retains the admitted runner identity from creation and now
performs genuine original-result admission before publication, not merely
structural commitment checks. The
[fixed admission helper](../data-plane/decision-gate-rs/src/body_result_admission_v12.rs)
checks both static executable roles, admitted source/artifact/body/native scope,
the original runtime report and image/closure bindings, the real pinned observer
signature, and terminal/body-claims commitments. Its observer policy and inherited
proxy executable pin come from the same readiness-trust configuration originals
authenticated by the release's `executor_config_sha256`; no new environment
selector, key, policy default or self-enrollment is added.

Before releasing the fixed supervisor's child gate, it now also holds the actual
pidfd, process start ticks, executable and namespace descriptors and generation
cgroup membership. The original result's observer PID/start ticks and runtime
namespaces must agree with those observations, and the held pidfd must indicate
termination after Docker wait. The client explicitly hands off that held pidfd
along with the other target descriptors before release; the response's pidfd
inode is joined to this shared descriptor identity, not to a separately opened
pidfd assumed equivalent. The local custody digest and ready response remain
unsigned. See [launch custody](controller-body-launch.md).
The executor still performs independent pinned-key verification and static-role,
source/artifact/closure checks. Native selection still requires actual collection
and equality with the [33-file native commitment](native-postgres-controller-consumer.md).
Neither layer synthesizes absent evidence or bypasses cleanup.

## Fixed observer exchange and controller publication

The fixed [BodyObserverExchangeV12 client](../data-plane/decision-gate-rs/src/body_observer_exchange_v12.rs)
uses only the root-owned Unix stream endpoint
`/run/catchplate/coder/v12/runtime-observer/control.sock`. It checks the actual
peer UID/GID `0:0` and immutable executable against the already admitted observer
policy. The shared closed wire codec is also used by receiving-side admission.
Peer custody requires Linux `SO_PEERPIDFD`, not a numeric PID reopen; the
[acquisition contract](controller-body-observer-acquisition.md) records this
kernel prerequisite and the still-missing serving/event ownership.
This is not permission to substitute any root process or a caller-chosen
socket. All phases retain the original absolute deadline; no retry or lifetime
renewal is introduced.

Before root releases the gated supervisor, the client sends a one-byte `L`
handoff with exactly nine `SCM_RIGHTS` descriptors in fixed order: pidfd,
`/proc/PID`, executable, user/mount/PID/network/cgroup namespaces, and actual
cgroup directory. A bounded versioned begin frame binds the retained launch
context and target PID/start ticks/pidfd inode/custody digest. The ready frame
must echo the held scope and deadline. Readiness is an unsigned protocol join,
not an observer signature or proof of continuous acquisition.

The fixed frame versions are `catchplate.controllerBodyObserverLaunch/v12`,
`catchplate.controllerBodyObserverReady/v12` and
`catchplate.controllerBodyObserverTerminal/v12`. The launch aggregate, including
original context and source/artifact/proxy bindings, is capped at 4 MiB; ready
and terminal-request frames are capped at 4 KiB each. These transport versions
do not replace the separately signed v13 observer-evidence contract.

After actual wait, complete capture and held-target termination, the controller
collects streams and payload files and publishes the canonical manifest while
retaining all original descriptors. Only then does it request a terminal. The
closed `BodyObserverTerminalRequestV12` carries exactly plan ID, lane, body/command digests,
actual exit status, stdout/stderr hashes and byte counts, manifest hash and the
optional native output digest. These are actual controller observations; the
client does not supply invented mapping/event evidence or an observer signature.
Control frames use bounded typed-canonical JSON with unsigned big-endian
32-bit lengths. The client half-closes after its terminal request, requires a
4 MiB-bounded original result plus exact EOF, and rejects inbound ancillary data.
The same connection retains its begin deadline; finish may only shorten it.

The root then authenticates the original response through the fixed admission
helper and joins actual exit, held kernel identities, captured streams, generic
manifest and any separately reconciled native inventory. Only after those checks
does it call the retained output owner's structural `finalize`. That owner
rechecks its own files and exclusively publishes the exact original as
`.catchplate-controller-output-v12/terminal.json`. Legacy worker-root terminal
reads and the lane/default fallback are removed. See
[two-phase output custody](controller-body-output.md#manifest-and-original-result-joins).

The architecture deliberately separates three responsibilities: the independent
observer must acquire and sign genuine runtime evidence; the root must authenticate
it and join actual execution/output observations; the held output owner must
publish and recheck exact bytes without granting signature authority. The source
client cannot stand in for the first responsibility.

In particular, terminal-request measurements are root observations, not authority
for a service to blindly sign supplied fields. The future independently admitted
observer must own launch/event/mapping acquisition and reconcile actual terminal,
static and output observations. Acquiring rooted output custody from the held
process target before ready is one possible missing step, not implemented proof.
The current client supplies neither that independent acquisition nor a signer/server.

## Still required for a genuine producer

The create path now invokes a fixed supervisor with a controller-owned read-only
launch context. The original signed command remains unchanged inside that context;
no final plan ID is injected into its signed arguments. The lifecycle now has
source paths for supervision, held-target handoff, capture, collection, original
observer-response admission and controller-only terminal publication. None is a
replacement for the missing independent observer server and its genuine launch,
event, mapping and original-response acquisition/signing implementation.

Docker's rotating log is not a complete stream capture. Native combined logs
are not separate stdout/stderr evidence. Generic stream/manifest digests must
now match actual controller capture and collection, not merely be nonzero. Static
measurement must use real retained executable descriptors; runtime acquisition
must own the actual launch, process identity, namespaces, mapping events and
terminal observations. Signing caller-supplied dictionaries is not that owner.
Kernel-provided executable mappings such as `[vdso]` still require an explicit
representation/acquisition decision; the file-backed contract is not widened by
this exchange and no backing-file digest is fabricated.

No observer key, policy, runtime, runner image or signed invocation was installed
or reissued. Future deployment must deliberately enroll the new observer contract
and measured binaries; no migration or production acceptance is inferred.
The complete frozen-source preparation and sequential verification gates remain.
