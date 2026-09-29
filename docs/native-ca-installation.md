# Native local CA installation profile

`serverware-native-bootstrap-client` configuration v2 adds explicit, separately authorized local CA installation to its single fixed bootstrap exchange. This is source-only, unbuilt, unexecuted and unprovisioned. It does not establish Kubernetes installation, complete enrollment, full policy compatibility or production acceptance. The [v1 profile](native-bootstrap-client.md) remains diagnostic-only and rejects an `installation` field, including null.

## Independent inputs and authority

The [v2 configuration schema](../schemas/native-bootstrap-client.v2.schema.json) has exactly 19 required fields: the existing 18 v1 fields with `apiVersion: serverware.nativeBootstrapClient/v2`, plus `installation`. The configuration remains at most 16 KiB and uses the same explicit configuration path/hash invocation and original 100–30000 ms timeout. The three-field installation object contains only `{path, sha256}` artifact pins:

- `authority`: the independent [root-signed host-installation grant](native-ca-installation-authorization.md), at most 32 KiB.
- `authorityRoot`: independently pinned canonical nonweak Ed25519 SPKI PEM, at most 16 KiB.
- `capabilityToken`: protected exact 32–256 URL-safe ASCII token bytes, without newline or header prefix. Its actual-byte hash must match both the grant and genuine setup.

Real/effective UID and GID must all be zero. The configuration and token must satisfy the protected retained-original checks; they are not environment overrides or HTTP credentials. No token or private-key bytes are emitted or journaled. The installer root is separate from the actual setup, delegation and native runtime CA keys. The Python grant producer's signature admission is not a substitute for the native reader's original verification; the native reader also explicitly refuses weak Ed25519 roots.

Startup admission precedes protected token/key acquisition and network contact. The same full TLS connection, actual caller chain, exporter, challenge, peer endpoint and independent roots feed the genuine native role-3/role-5 verifier. The installer retains those original verifier owners; a successful JSON diagnostic is never an authority input. It requires exact setup/delegation/target-request matches, the whole grant interval within genuine setup/CA scope, and the actual native runtime interception CA DER/SPKI. The workload identity issuer CA and standard host-manifest diagnostics are not substitutes. No second bootstrap request is made to recover the packet.

## Observed host and protected destination

The signed `hostId` is an administrative label mapped by the independent host grant to its exact `machineIdSha256`, boot ID, network-namespace device/inode and root owner. It is not discovered hardware identity. The live owner reads `/etc/machine-id` as exactly 32 nonzero lowercase hex bytes with an optional final LF; **the hash includes that optional LF**. The boot original must equal the signed canonical UUID plus LF. The owner retains the actual current PID/TID namespace through held procfs directories, checks its magic link, nsfs filesystem/type, device/inode and root ownership, and rechecks those originals through completion. It does not accept a caller-provided namespace string as observation or claim hostile-host isolation.

All resources are preprovisioned by the operator; this guide does not provide deploy commands. The [local reservation journal](native-install-reservation.md) is the root:root `0700` directory at the independently signed path/device/inode. It is **not** the legacy control-plane CA-install session store or proof that a server reserved a token. Its stable slot derives from the signed journal namespace and exact capability ID; changing the operation does not create another slot.

The destination's root-owned, nonwritable ancestor chain must already exist. Its parent must contain `.serverware-native-ca-install/` as root:root `0700` on the same filesystem, and that directory's preprovisioned empty single-link `destination.lock` as root:root `0600`. The journal lock is acquired first, then this destination lock; both are nonblocking. The [destination owner](native-install-destination.md) enforces the signed path, UID/GID and `0644` mode, absent-vs-authorized-replacement condition and exact old-certificate DER digest, retains protected recovery originals and checks the installed CA from actual readback.

An irrevocable durable claim precedes installation. Partial claims or unknown outcomes are consumed and preserved, never reset or automatically retried. A matching completed association only permits read-only confirmation of the actual installed CA; it never repeats installation. A failure after replacement may leave the new CA installed even without journal completion or successful output. Preserve the destination, journal and recovery files for explicit investigation. No rollback rewrite, off-host rollback witness or general cross-session recovery authority is implied.

## One bounded output

Exit zero emits one `serverware.nativeBootstrapClientCapture/v2` JSON line, at most 1.5 MiB including its LF. It has the existing nine capture fields plus `installation`: `resultScope` is `local-fixed-endpoint-bootstrap-and-host-installation`, `okForAction` remains false, and the exact original evidence is retained in `evidenceBase64url` with the same request/configuration pins, endpoint, challenge source and verifier diagnostic.

The embedded installation object is at most 8191 serialized bytes and has exactly eleven fields: `apiVersion`, `resultScope`, `okForAction`, `status`, `authorizationSha256`, `operationSha256`, `reservationSha256`, `setupSha256`, `capabilityId`, `runtimeCaCertificateSha256`, and `destinationPath`. Its schema is `serverware.nativeCaInstallationReceipt/v1`, scope `local-authorized-native-ca-installation-only`, and status is `installed` or `already-complete`. It is a local guarded result, not a transferable signed receipt or general action permission.

The existing [capture extractor](native-bootstrap-capture.md) accepts the exact v2 evidence for packet extraction without another bootstrap. It treats both diagnostics and the installation child as data, never install or issuance authority. It cannot prove that a producing process exited successfully. Retain the exit status; any partial output, nonzero exit or lost reply remains failure/unknown, not retry permission. The same original guard covers bounded output writes and final checks; an external watchdog is still needed for already-blocked kernel/filesystem/stdout calls.

The result does not install firewall/Kubernetes policy, authorize canaries/provider traffic, issue a workload certificate, update unrelated trust stores, establish hostile-host custody or close lifecycle and production gates.
