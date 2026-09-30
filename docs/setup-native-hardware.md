# Native Setup hardware and independent proxy verification

This is a connected source-only successor of the protected native runtime capture,
not the legacy `setupHardwareVerification/v2` or final challenge receipt. Its scope
is **enclave-hardware-and-proxy-only**. The separately authenticated host CA
installation remains **trusted-host-local**. `measuredHost`, `finalSetup`,
`enrollmentComplete`, `proxyReady` and action permission are not granted.

## Actual producer and effect

`control_plane_setup_native_hardware` consumes the actual retained enrollment,
host readback, canary association and completed runtime-capture rows. A fresh
requester hardware assertion causes `setup.native-hardware.prepare` to reserve
the exact original attempt in `setup_native_hardware_attempts`. Only after that
controlled CAS returns does this same request make one fixed management POST to
`/v1/native-setup-hardware`. No browser-selected URL, native assignment or key is
accepted. The existing protected management URL/token are retained around the
contact; public response authenticity is separately checked. This introduces no
transport confidentiality or measured-parent claim.

The actual `GateState` producer retains the immutable policy read guard, native
lifetime, actual process, native TLS identity and role-4 signing owner through the
signature and fresh NSM quote. It derives loaded policy/route, binary and key/boot
identity from those owners. Supplied Setup association hashes are commitments,
not locally verified host measurements. The signed statement is schema ASCII,
NUL, full canonical ASCII statement. Its derived NSM nonce is SHA256 of fixed
`serverware/native-setup-hardware-attestation/v1` + NUL + nonce32 + statement
SHA256 + signature64. The original role-4 user data and key binding remain intact;
user data is explicitly limited to 512 bytes. Legacy full JSON user-data is not
reused: [AWS's NSM documentation](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md) contains 1024/512-byte descriptions, so this
fixed compact binding stays below both without asserting legacy compatibility.
The fresh quote check retains its original signed millisecond timestamp with a
conservative plus/minus1ms quantization interval, not the legacy helper's lossy
whole-second projection. Both ends must fit the original attempt; existing cold
age/skew policy still applies. This does not claim an AWS clock-accuracy SLA.

Two separate executable producers, `scripts/verify_native_setup_hardware.py` and
`scripts/verify_native_setup_proxy.py`, verify original COSE, native signature,
independently pinned PCR/EIF/module/PKI/currentness, full original collector and
control-plane signatures, actual native enrollment/leaf, and both CA readback
signatures. They do not accept a caller-selected success payload. They compute
their purpose-specific receipt from those verified originals. Proxy evidence is
independently reverified **trusted-collector evidence**, not a claim that the
second verifier made a second HTTP request or measured the parent Linux OS.

`setup.native-hardware.complete` requires both independently pinned signatures
and repeats original verification in verifier and planner. The kernel compares
the actual protected originals, completed source audits, current credential and
policy publication, consumes the same unresolved reservation by CAS and emits
its own audit. No generation or legacy Setup phase is rewritten. Final Setup
authority is deliberately not inferred from this result.

## Independent producer installation contract

These are distinct fixed one-shot external services, not code or keys inside the
claimant enclave. Each requires isolated Python 3.11 (`-I -B`), the exact pinned
module closure and cryptography/Nitro dependencies, permanent separately assigned
UID/GID, empty groups/capabilities, nondumpability and no-new-privileges. FD3 must
be the actual root-owned0400 named configuration original under protected
`/etc/serverware`: `setup-native-hardware-verifier.json` or
`setup-native-proxy-verifier.json`. FD4 is its independently provisioned exact32
byte seed in a fully sealed0600 zero-link memfd, and FD5 is a distinct sealed0600
canonical public verifier request, at most4MiB. No seed file or argv/environment
authority is accepted. FD1 must be a private write-only pipe. Original files,
process/PIDFD, boot/time namespace and absolute operation window (at most30s)
remain held through bounded nonblocking public output. No signing key is returned;
the seed copy is cleared. Existing generic verifier/signature purposes are not
used as authority for these services.

Configuration exact9: `apiVersion` =
`serverware.setupNativeIndependentVerifierConfiguration/v1`, `role` = one fixed
entrypoint purpose, `uid`, `gid`, `operation`, `authorityRootPublicKeyPem`,
`authorityConfigurationOriginal`, `authorityConfigurationSha256`,
`controlPlaneConfigurationDigest`. `operation` is original bootIdBase64url,
timeNamespaceDevice/Inode and decimal issuedAtBoottimeNs/deadlineBoottimeNs. The
named configuration independently pins the actual signed v6 authority
configuration/root; signatures and full configuration digest are rechecked.
The new signed `setupNativeHardwarePolicy` contains separate hardware, proxy and
reserved final authority provider/public-key pins, hardware credential policy
and maximumAttemptNanos. All three must be mutually distinct and distinct from
collector, native, CA, workload, host, installation/issuance root and CP role keys.
No provisioning, supervisor installation or runtime acceptance is claimed by
these source definitions; those actual deployment owners still must be supplied.

FD5 is exactly the retained `inputsOriginal` object plus `attempt_original` and
`evidence_original`, serialized canonically. The UI downloads those exact bytes
as `verifierRequestOriginal`; it never creates a signature or supplies trust.
Both fixed producers emit a canonical no-LF envelope2, payload19, <=16KiB.
Signature preimage is `serverware/setup-native-independent-verification/v1`, NUL,
the fixed verifier role, NUL, full canonical payload. Their private seeds must
match the separately pinned public material before the only signing call.

## HTTP and unresolved outcomes

All four fixed POST routes are under `/api/setup/native-hardware`. Schema:
[`setup-native-hardware.v1.schema.json`](../schemas/setup-native-hardware.v1.schema.json).
Options/lookup request2 is apiVersion `serverware.setupNativeHardwareRequest/v1`
and sessionId. Prepare adds the assertion; complete adds exact canonical
evidenceOriginal/hardwareReceiptOriginal/proxyReceiptOriginal strings. Raw HTTP
request bound128KiB; response bound4MiB. Existing OIDC requester roles, CSRF and
fresh purpose-bound hardware checks apply. A conservative aggregate bundle bound
is checked before reservation, including both nested-original escaping levels;
individual maximum field sizes do not imply simultaneous aggregate admission.
Options serverware6 uses purpose
`setup.native-hardware.prepare`, not an older Setup ceremony.

Prepare201 returns `independent-verification-required`, public hardware5 and
bundle4: inputsOriginal, attemptOriginal, evidenceOriginal,
verifierRequestOriginal. Complete200 returns `hardware-proxy-verified`, public
hardware5 and resultOriginal. Lookup200 returns `observation`, nullable hardware,
bundle and resultOriginal. Common response flags remain nonactionable.
Public hardware5 is revision, phase, attemptSha256, prepareRequestDigest and
completeRequestDigest. The two phases are hardware_outcome_unknown and
hardware_proxy_verified.

Loss after reservation but before the returned quote stays fenced. Lookup can
recover the reservation, not an unretained quote or permission to repeat contact.
The preparation route cannot contact again once its protected slot exists. After
definite completion, exact quote and receipts are durably retained. All stages
keep the original runtime/enrollment/Setup expiry; lookup never renews it.

The next full-project prerequisite is a genuine independently operated final
authority and native final completion producer/consumer over these completed
audits and actual deployment inputs. A Linux host measurement claim additionally
needs its own genuine measurement authority; machine-id/DMI, browser downloads,
CA readback and role-4 Nitro quotes cannot substitute for it. Legacy receipt
profiles and their independent final authority remain unchanged. No build,
signing, deployment, cloud or runtime acceptance was performed for this batch.
