# Pre-start driver window authority

`scripts/authority/sign_native_pilot_window.py` issues the existing
`catchplate.nativeShadowDriverBootstrapWindow/v1` original for the fixed driver
configuration v4 / lifecycle v3. It supplies the previously missing issuer;
it does not approve its own inputs, generate a key, install files, launch a
driver, or establish a running pilot.

The independent authority must approve the complete input and provision the
matching `bootstrapAuthority` private key. This key is distinct from the
phase-two and constructed-admission keys. Its public identifier remains the
existing SHA256 of the raw 32-byte Ed25519 public key, not a new SPKI domain.

## Input and output

The input is canonical ASCII JSON with no trailing LF, at most 1 MiB, and
exactly four fields:

- `apiVersion`: `catchplate.nativePilotDriverWindowAuthorityInput/v1`.
- `configurationOriginal`: literal approved driver configuration v4, at most
  65536 bytes, including lifecycle v3, image pins and the fixed key transport.
- `deliveryConfigurationOriginal`: literal existing production-bridge C9 cold
  configuration, at most 65536 bytes. Its digest and UID/GID must match the
  driver's independently selected delivery-configuration pin.
- `payloadOriginal`: literal selected window payload, at most 32768 bytes.

The payload has the existing nine exact fields: `configurationSha256`,
`signingKeyId`, `bootIdBase64url`, `timeNamespaceDevice`, `timeNamespaceInode`,
`issuedAtBoottimeNs`, `startupDeadlineBoottimeNs`, `lifetimeDeadlineBoottimeNs`,
and `invocationId`. The authority supplies every value; the command invents
none. Nanosecond fields retain the existing canonical decimal-string grammar;
numeric namespace fields reject booleans. The invocation is an explicitly
supplied nonzero 32-character lowercase hexadecimal value.

The issuer checks its actual local boot and time namespace, and requires
`issued <= now < startup <= lifetime`, `startup - issued <= 30 seconds`, and
`startup < lifetime - cleanupReserveNanos`. The existing cleanup reserve remains
1 millisecond through 5 seconds. There is no new lifetime, grace period, or
deadline adjustment. The original allowance is already running during issuance,
installation and startup; expired inputs require a new independent decision,
not an automatic retry or refreshed timestamp.

The output is the existing exact three-field envelope (`apiVersion`, `payload`,
`signatureBase64url`), canonical ASCII without LF and at most 32768 bytes.
The unchanged signing bytes are
`catchplate.nativeShadowDriverBootstrapWindow.signature/v1`, NUL, and the exact
canonical payload. The producer verifies its output signature and repeats the
original-domain/deadline checks before returning it.

Static configuration checks cover the closed image/seccomp grammar and its
commitments, authority separation, fixed KMS transport and cold delivery
association. They do not replace Rust's canonical syscall-rule-to-BPF compiler,
actual image/hash admission, installed-filter checks or live descriptor owners.

## Protected invocation

The independently provisioned supervisor invokes the fixed source command:

```text
/usr/bin/python3 -I -B scripts/authority/sign_native_pilot_window.py --input-fd N --authority-key-fd K
```

`N` and `K` are distinct inherited descriptors >=3, never private key contents
or caller-chosen code paths. The input is a root:root mode0400 single-link
read-only regular file, or an equivalently fully sealed public memfd. The key
is an existing root:root mode0400, fully sealed, unlinked 32-byte memfd. The
shared authority I/O owner enforces isolation, makes the descriptors
noninheritable, and disables core dumps before reading key bytes. Python/OpenSSL
copies are not hardware key custody or guaranteed memory erasure.

Stdout must be the supervisor's root-owned write-only FIFO. Output is bounded
by both the original startup deadline and the existing one-second write limit.
The supervisor must collect a complete original and a successful process exit;
a truncated original or nonzero exit is failure even if bytes were received.
Blocking filesystem or cryptographic work still needs an external supervisor
deadline. No key bytes or detailed exception contents are printed.

The separate bootstrap installer consumes this literal signed window with the
approved configuration and control originals. This issuer makes no filesystem
publication, independent approval, cloud, runtime or release-eligibility claim.
