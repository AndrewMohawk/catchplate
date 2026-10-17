# Extracting a native packet from a local capture

The native bootstrap client emits a bounded local capture containing exact public
evidence plus a diagnostic. The issuance API instead consumes the exact native
packet within that evidence. `native_bootstrap_capture.extract_packet` connects
these representations without promoting the diagnostic to authority.

The extractor explicitly accepts nine closed
`catchplate.nativeBootstrapClientCapture` profiles. Each retains the same nine
base fields and permits only the children shown here, never additional fields.
Only v7/v8 explicitly permit a null installation child:

| Version | Required children | Total fields |
| --- | --- | --- |
| v1 | None | 9 |
| v2 | `installation` | 10 |
| v3 | `egress` | 10 |
| v4 | `egress`, `attachment` | 11 |
| v5 | `execution` | 10 |
| v6 | `execution`, `installation` | 11 |
| v7 | `execution` v2, `installation` (receipt or null) | 11 |
| v8 | `execution` v2, `installation` (receipt or null), `outcome` | 12 |
| v9 | `execution` v2, nonnull `installation`, `outcome` | 12 |

V9 selects the [ordinary-application CONNECT adapter](native-application-proxy.md)
and the distinct scope `local-fixed-endpoint-bootstrap-application-proxy-observation`.
Its required nonnull installation, execution and durable outcome children retain
their existing closed bounds. Extraction does not prove the app honored proxy
or trust settings, authenticate a provider response, or grant another CONNECT.

V8 adds the [durable terminal outcome](native-execution-outcomes.md) receipt.
The decoder checks its exact nine fields, nonzero hashes, matching execution
operation and recorded BOOTTIME within the original retirement/cleanup interval.
It does not consult the journal, verify historical fsync or grant permission.
The actual producer publishes before stdout; the separate protected read-only
lookup handles lost output without replaying execution or retirement.

These clients can preserve their original
evidence for later native identity submission without another bootstrap attempt.
No new extraction CLI mode or automatic acquisition is needed.

Supply independently selected `PinnedFile` descriptions for the capture and the
target request, plus an existing current-user-owned mode-0700 output directory.
The helper uses one at-most-30-second budget from before input acquisition through
publication. It reads only pinned regular originals, refuses changed paths/bytes,
and bounds capture (1.5 MiB), evidence (1 MiB), packet (512 KiB) and target request
(64 KiB) before their nested decoding. The closed evidence/packet containers must
retain their exact canonical encodings and one LF. The producer's diagnostic is
bounded but its success, identity, signature or measurement claims are ignored.

V2's installation child has exactly the eleven fields in
[the local receipt schema](../schemas/native-ca-installation-receipt.v1.schema.json),
with `okForAction: false`, status `installed` or `already-complete`, and at most
8191 compact UTF-8 bytes. The helper checks only the closed shape, constants and
bounded scalar spellings. It does not authenticate that receipt, inspect its
destination, verify its authorization or token, consult the reservation journal,
or infer current host/namespace/CA installation state. Its public capability ID
is not a token or live permission. The whole
[v2 capture](../schemas/native-bootstrap-client-capture.v2.schema.json) remains
bounded at 1.5 MiB; the v1 limits and behavior are unchanged.

The [v3 capture](../schemas/native-bootstrap-client-capture.v3.schema.json)
contains the exact ten-field
[egress observation](../schemas/native-egress-observation.v1.schema.json), also
at most 8191 compact UTF-8 bytes. Its scope is observation before owner teardown,
not a persistent deployed workload: both levels retain `okForAction: false`.
`observed-created` and `observed-complete` are data-only status spellings. The
extractor checks the five digest spellings and closed ten-scalar workload shape,
with exact unsigned 32-/64-bit JSON integers and no bool/float coercion. It does
not authenticate the grant, read a creation/kernel journal, check a pidfd/nsfs or
socket, inspect rules, infer current namespace membership, or authorize a retry.
The [v3 client](native-egress-client.md) retains genuine owners through output
and then tears down its never-executed child. No execution, network attachment,
CA installation or continuing kernel state follows from this public capture.
V3 does not combine CA installation with egress; explicit v6 is the separate
combined CA-and-execution profile described below.

The [v4 capture](../schemas/native-bootstrap-client-capture.v4.schema.json)
retains that same egress child and exact unsigned workload identifiers, and adds
the closed eight-field
[attachment observation](../schemas/native-network-attachment-observation.v1.schema.json).
Its scope is `local-authorized-network-attachment-observed-before-owner-teardown`,
its only status is `observed-attached`, and `okForAction` remains false at every
level. The helper checks only the four digest spellings, constants and bounded
shape. Each child is at most 8191 compact UTF-8 bytes; the complete capture remains
at most 1.5 MiB including its final LF. It does not read the attachment journal,
authenticate its grant, inspect link/address/route/neighbor state, or infer
connectivity. The [v4 client](native-network-attachment-client.md) retains actual
owners through output; this v4 capture supplies no application-start or
persistent-supervision evidence. Neither an UP-link observation nor a copied digest authorizes
network effects, recovery, a retry or CA installation.

The [v5 capture](../schemas/native-bootstrap-client-capture.v5.schema.json)
instead contains the exact eight-field
[execution observation](../schemas/native-execution-observation.v1.schema.json),
at most 16384 compact UTF-8 bytes. Its nested exit, output and cleanup objects
have exactly nine, five and five fields. The extractor checks digest spellings,
exact unsigned 64-bit boottime integers, bounded exit code/status and output
counts, actual JSON booleans, `actionAuthorization: null`, and
`okForAction: false`. The reported `workloadSucceeded` must agree with code 1
and status 0. It does not verify an EXEC event, a reap, leaf emptiness, output
hashes, network state or application health. Raw stdout/stderr are absent.

The [v6 capture](../schemas/native-bootstrap-client-capture.v6.schema.json)
adds the unchanged installation receipt to that same execution observation.
Its scope is exactly
`local-fixed-endpoint-bootstrap-ca-and-execution-observation`; no separate
`egress` or `attachment` children are accepted. The whole capture remains at
most 1.5 MiB including LF, with the same 8191-byte installation and 16384-byte
execution ceilings. A nonzero workload exit can produce terminal data while
the producer still exits unsuccessfully. Uncertain execution or cleanup does
not have a successful-capture fallback.
The independently authorized host CA installation can remain after a later
execution failure without a capture; neither capture absence nor extraction
failure rolls that effect back or authorizes a retry.

The explicit [v6 client configuration](../schemas/native-bootstrap-client.v6.schema.json)
requires all four `installation`, `egress`, `attachment` and `execution` inputs.
It selects [execution manifest v2](../schemas/native-execution-manifest.v2.schema.json),
whose additional `applicationTrust` pins a single runtime-CA PEM already inside
the immutable image, with separate whole-PEM and DER certificate hashes. The
signed `SSL_CERT_FILE` value must equal that in-image path. The actual runtime
owner, not this extractor or JSON Schema, checks the file, native CA and
independent installation association. Neither a writable image trust injection
nor a claim that arbitrary applications use that environment variable is
introduced. V5 still selects manifest v1; old profiles are not upgraded by
reading newer capture or receipt fields.

The [v7 capture](../schemas/native-bootstrap-client-capture.v7.schema.json)
retains eleven fields with scope
`local-fixed-endpoint-bootstrap-execution-retirement-observation`.
Installation is required, but null means this profile did not request CA
installation. A nonnull receipt uses the unchanged installation contract.
Execution is the explicit nine-field
[v2 observation](../schemas/native-execution-observation.v2.schema.json),
at most 24 KiB; the whole capture still fits 1.5 MiB including LF.
Its added eight-field
[retirement observation](../schemas/native-execution-retirement-observation.v1.schema.json)
reports the prior host veth identity, bounded absence-readback digest, exact
removed leaf and parent identities, and original cleanup deadline.
The extractor checks closed shapes, positive exact unsigned integers,
nonzero retirement digests, operation equality, and reported observation times
after cleanup and before that deadline. These are consistency checks on
untrusted historical data, not kernel queries or proof of current absence.

The [v7 configuration](../schemas/native-bootstrap-client.v7.schema.json)
requires explicit [start authorization v2](../schemas/native-workload-start-authorization.v2.schema.json),
including separate permission to remove only the actual owned empty leaf.
Null installation keeps manifest v1; nonnull installation requires manifest v2
and the same independently authorized immutable CA association as v6.
No incoming capture selects this runtime permission. Old configurations and
captures retain their existing exact shapes and limits. Neither successful
extraction nor retirement data authorizes restart, retry, directory repair,
host network deletion, journal pruning, or host CA removal.

The packet's embedded target request must equal the supplied request original.
Reconstructing the exact delegation/setup/target exchange must also reproduce
the capture's request digest. Both are data-association checks, not independent
authentication of the capture or its contents. No CSR, delegation, setup, quote,
policy, grant or certificate verification is claimed by this helper.

Successful extraction publishes exact `native-packet.json` with mode 0600 through
the existing descriptor-held, no-overwrite, fsynced and exact-readback publication
path. Its return value is a packet pin, not an enrollment receipt. A late failure
may leave the published original intact; it is not removed or overwritten.

The CLI exposes `--extract-native-bootstrap-packet` with `--workload-capture`,
`--workload-capture-sha256`, `--workload-request`, `--workload-request-sha256`,
`--workload-output-directory` and optional `--workload-timeout-ms`.
The [native submission path](native-workload-identity-submission.md) subsequently
sends exact packet/request/grant originals for genuine server-side authorization
and independently verifies the issued certificate against the retained target key.

Keep the bootstrap producer exit status separately. A parseable capture from a
failed producer is not proof of successful acquisition, and extraction cannot
recover that missing fact. An installation receipt in a parseable v2 capture also
cannot prove final producer success or that the installed file remains present.
Likewise v3/v4 observations cannot prove producer success or live workload/kernel/
attachment state after capture. V5/v6 terminal observations cannot prove those
events occurred, establish persistent supervision, or authorize restart; a v6
receipt also cannot prove that the host CA remains installed or an application
used its in-image trust. Extractors that do not support a newer explicit
profile refuse it; there is no relabeling or automatic downgrade.
Extraction starts no network request, reads no private
key, renews no signed lifetime, installs no CA and supplies no automatic retry.
An external watchdog is still needed for blocked filesystem calls. This is
source integration, not tested native enrollment or a production acceptance gate.
