# Authenticated native Setup CA readback

This source connects the real privileged native bootstrap installer to a new
protected Setup sidecar. The authenticated fact is **trusted-host-local CA-file
readback**, not native host attestation, operating-system-wide trust, proxy
readiness, application execution, audit inclusion or final Setup completion.
Legacy receipts, bootstrap profiles v1–v9 and the unsigned diagnostic
`nativeCaInstallationReceipt/v1` keep their old meanings.

## Connected producer and consumer

The Setup owner first has an actual protected `certificate_issued` C14 row.
`POST /api/setup/native-ca/options` takes the Setup session, exact signed CA
installation authorization wrapper and an independently assigned host key ID.
`/prepare` adds a fresh purpose-bound hardware assertion. Both authority roles
reverify the original native issuer/bootstrap/CSR/leaf and independent CA grant.
The protected kernel checks the exact retained enrollment, current policy,
credential root and original distinct issuance approver/key/trust. That original
approval is retained provenance, **not** permission to install: the separate
root-signed `native-ca-installation` grant authorizes the host effect.

The prepare transaction commits an immutable `installation_unknown` record and
real audit outbox event before returning HTTP 201. It returns the exact prepared
and enrollment originals and exact grant wrapper. Preparation creates no host
key and grants no generic signing capability. Its challenge is derived from the
unique controlled request; the original grant/Setup/issuance expiry can only
shorten its deadline. There is no reset, timeout unlock, reprepare or automatic
retry. Unknown contact and failed local output remain fenced.

An operator supplies those exact originals to the existing fixed
`serverware-native-bootstrap-client --configuration ... --configuration-sha256 ...`
with the explicit closed `nativeBootstrapClient/v10` profile. In addition to
the old actual v2 installation inputs, `setupInstallationObservation` pins:

- `prepared`: exact prepared12 ASCII file, at most 8192 bytes;
- `enrollment`: exact protected certificate-issued row, at most 1500000 bytes;
- `hostSigningSeed`: independently provisioned exact32-byte root-private
  Ed25519 seed; its public key must match `hostPublicKeyBase64url` and the
  independently signed control-plane purpose policy;
- `targetPrivateKey`: the original target P256 PKCS8 key, not a new key.

The source owns those actual retained files and the original clock. The live
native TLS/bootstrap proof must match the original target request, issuer,
policy, setup and delegation. The target leaf is verified under that issuer,
its entire SAN inventory must match, and its public key must match the actual
retained private key. The host key is distinct from all involved CA, authorizer,
caller and target keys. A protected config/pin is not independent host evidence;
the cold signed authority policy separately admits the host signing identity.

Actual `InstallGuard`, `HostOwner`, `Reservation` and `Destination` remain the
only installation owners. The one-use local journal is claimed before mutation;
the existing fsync/readback sequence and durable completion are required before
the new fixed signing method. It has no raw bytes or uploaded-success signing
API. It signs actual readback identity/CA, actual host/boot/network namespace,
grant and operation/slot commitments, and exact Setup/certificate/association
bindings. The same target key signs a separate possession domain. All owners
are rechecked through final output. Secret application-owned input buffers are
zeroized; this does not claim elimination of every crypto-library copy or
protection from a hostile root host.

The v10 capture has a separate schema and contains the exact
`setupInstallationObservationOriginal` string. Only that canonical envelope3
is submitted to `POST /api/setup/native-ca/complete`; the old diagnostic is never
accepted there. Both independently configured authority roles verify the host
signature, target possession, issuer/leaf and grant, while the protected CAS
requires the original unconsumed fence and current roots within its unchanged
interval. Completion stores the exact observation at sidecar revision 1 with
phase `ca_readback_authenticated`. It does not mutate legacy Setup revision 3.

## Portal handoff

The CA controls follow native certificate issuance in Setup and reuse its
session ID. The requester needs both `credential_owner` and `policy_author`.
Review the exact separately signed installation grant and independently pinned
host key ID, then use a fresh purpose-bound passkey to prepare once. Download
the three unchanged originals for the authorized v10 installer: preparation,
issued enrollment and installation grant. These may carry authority; use an
authorized operator channel, not public chat, tickets or logs.

The browser accepts either the canonical signed observation (at most 32 KiB)
or the actual v10 capture (at most 1.5 MiB, including its final newline). It
extracts only `setupInstallationObservationOriginal` unchanged. Structural
review is not signature verification: submit that exact string once for the
independent authority checks. Unsigned capture diagnostics cannot satisfy this
operation.

Read-only lookup recovers the same exact handoff after a lost preparation reply
and shows the authenticated observation after definite completion. Downloading
expired originals is historical recovery, never permission to run the installer.
Auth, session and file changes discard page-held material. Only nonsecret
submission digests enter session storage; clearing the form, lookup and expiry
do not remove them or authorize a retry.

## Trust and recovery

The independently signed configuration field `setupNativeCaInstallationPolicy`
contains the distinct installation-authorizer root, exact hardware policy and
sorted host key inventory `{hostId,machineIdSha256,keyId,publicKeyBase64url}`.
It is not request-selected and must coexist with the separately pinned native
issuer policy. A host key authenticates this trusted host's scoped observation;
it is not a Nitro/TPM quote and cannot establish measured-host assurance. Actual
key provisioning and protected host installation configuration remain operator
prerequisites, not generated artifacts of this source slice.

`/lookup` is read-only and returns the exact bundle after a lost prepare201,
or the exact observation after definite completion. Historical expiry is never
renewed. Recovered bundle availability does not prove the local installer was
never attempted, and it does not permit resending on uncertainty. The installer
still requires all current originals and its existing irreversible journal.
The existing external watchdog requirement for blocking filesystem/output calls
remains; polling `OriginalClock` is not an interruptible syscall guarantee.

The four HTTP contracts and both signature preimages are in
[`setup-native-ca-installation.v1.schema.json`](../schemas/setup-native-ca-installation.v1.schema.json).
The exact host profile and capture are in
[`native-bootstrap-client.v10.schema.json`](../schemas/native-bootstrap-client.v10.schema.json).
No browser install/sign operation or new runtime/cloud/provider action is added.
Native hardware/proxy evidence and the independent final Setup receipt authority
remain separate work. This change was not built, parsed, tested or executed.
