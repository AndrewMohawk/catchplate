# Extracting a native packet from a local capture

The native bootstrap client emits a bounded local capture containing exact public
evidence plus a diagnostic. The issuance API instead consumes the exact native
packet within that evidence. `native_bootstrap_capture.extract_packet` connects
these representations without promoting the diagnostic to authority.

The extractor explicitly accepts the closed nine-field
`serverware.nativeBootstrapClientCapture/v1` and ten-field
`serverware.nativeBootstrapClientCapture/v2` profiles. V2 retains the same exact
bootstrap evidence and adds an `installation` child; v1 still rejects that field.
The installing client can therefore preserve its original evidence for later
native identity submission without making a second bootstrap attempt. No new
extraction CLI mode or automatic acquisition is needed.

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
Extraction starts no network request, reads no private
key, renews no signed lifetime, installs no CA and supplies no automatic retry.
An external watchdog is still needed for blocked filesystem calls. This is
source integration, not tested native enrollment or a production acceptance gate.
