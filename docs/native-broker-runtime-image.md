# Measured broker runtime packaging

The default decision-gate production image selects a native-only entrypoint.
It cannot fall through to the host/development proxy when configuration is
missing. The old `production-decision-gate` Docker target remains an explicit
migration artifact, not the default production target.

This is source implementation, not a built image, accepted release or deployed
pilot. Actual EIF construction, independently reproduced measurements, signed
release/configuration admission, startup artifact delivery and Nitro/KMS tests
remain required. A local build manifest cannot supply independent authority.

## Why a sealed SquashFS image

Nitro boots the application filesystem from its measured ramdisk, not a host
disk. The published AWS x86-64 bootstrap
[kernel configuration](https://raw.githubusercontent.com/aws/aws-nitro-enclaves-sdk-bootstrap/main/kernel/microvm-kernel-config-x86_64)
enables loop devices and SquashFS, but disables EROFS and fs-verity.
The broker therefore uses a distinct `sealed-memfd-squashfs-v1` owner. Existing
host-side EROFS/fs-verity owners and their guarantees are unchanged.

```mermaid
flowchart LR
    S[Exact source and pinned dependencies] --> B[Offline runtime packager]
    B --> I[Complete SquashFS helper image]
    I --> E[Measured enclave image]
    E --> M[Copy and hash owned memfd]
    M --> F[Seal writes and size]
    F --> R[Read-only loop and private SquashFS root]
    R --> H[Unprivileged helper with private channel]
```

At runtime the actual native owner copies the full bounded image, checks its
independently admitted SHA-256 and installs/checks all four memfd seals:
write, grow, shrink and seal. It retains the readonly loop's exact backing
device/inode, zero offset and full size, plus its private readonly mounted root.
The helper executes the held interpreter inside that root, with no writable
overlay or host import paths. Hashes and a readonly mount alone are not Nitro
provenance: genuine NSM quotes and independent release/KMS admission remain
mandatory.

## Closed build inputs and outputs

The production Dockerfile consumes its verified source archive and hash-locked
Python wheelhouse. The pinned Python 3.11 image supplies the actual interpreter,
libpython, standard library and extension modules. Only locked `cryptography`,
`cffi` and `pycparser` distributions enter the helper's normal site-packages,
together with purpose-fixed Serverware helper/CMS modules. Package metadata
and licenses travel with those distributions.

`scripts/package_native_broker_runtime.py` runs only in the offline build stage.
It records and copies the actual loader and recursively resolved shared-library
dependencies of every admitted ELF file. Wheel-relative layouts are preserved.
A root-specific loader cache closes `/usr/local/lib` resolution. No external
host loader/library graph, `PYTHONPATH`, shell, pip or build tool enters the
helper root. CPython remains a measured general-purpose interpreter, not a
proof of language-level isolation.

The explicit source allowlist includes the capture-retirement and reconnect
owners, codecs, receipts, rows and TLS dependencies used by the actual broker
entrypoint. Their inclusion supplies modules, not permission to select those
purposes or call a provider. Capture retirement uses the shared standard-library
`oauth_retirement_values` predicates for revocation-shaped scalar/provider data
and encrypted response envelopes. The control-plane revocation/exchange APIs
delegate to those same predicates: exact fields, UUID/digest spelling, text
bounds, provider URLs, token purposes, original time windows and envelope limits
are unchanged. Native signed purposes and assignment checks are not translated.
This removes control-plane policy/storage imports from those scalar/envelope
validation paths. The actual capture and pending receipt `policy_key` and
`verify_grant` callers now use [shared portable policy validators](native-retirement-portable-policy.md),
included in this image's explicit module allowlist. They preserve distinct
purposes, historical signing roots, full strict assignment/trust/enrollment
checks and original time bounds; no successful marker replaces a missing check.
The pending helper's existing mandatory policy key and narrower 32 KiB enrollment
bound remain additional requirements. Actual quote verification remains in the
control-plane verifier, not in this data/signature dependency extraction.
The isolated no-build lane includes authored data-grammar tests plus a fresh
interpreter import/refusal probe of both actual receipt entrypoints. This probe
is not valid signed admission or complete image/runtime verification. No test
or image build has been executed.

### Static credential import and rotation preflight

The broker entrypoint also imports the AWS exclusion guard and the static
credential creation/rotation owners. The old explicit package roster omitted
those modules and their dependencies. An ordinary source-tree import hid that
defect; the isolated helper root could not import its entrypoint.

`BROKER_MODULES` now supplies the source-fixed roster through the same copier
used by production packaging. Rotation's historical-proof syntax is shared in
`static_credential_provenance_values.py`, rather than importing the authority's
database-transition and Nitro-verification graph into the helper. Existing
authority entrypoints delegate to the same parser. Signature verification,
native assignment and quote admission, and authenticated history/current-row
checks remain separate and unchanged; parsing a prior proof never authorizes
rotation. Dependency versions, native image bounds and purpose admission are
not expanded by this repair.

The fast preflight requires no image build or pilot:

```sh
make verify-native-broker-package-closure
make verify-static-credential-provenance-values
```

The package check stages only the reviewed source roster, isolates it from the
checkout and tests the actual helper import and rotation parser calls. It is
not a substitute for the full generated-root ELF check, reproducible SquashFS
build, native owner admission or credential-bearing application acceptance.

Offline validation on 2026-10-12 used the cached Python 3.11.15 test image with
network disabled, no writable source mount and no service restart. Six package
closure groups and eight parser/signature groups passed. Four authority rotation
groups, ten native rotation material groups and 37 additional planner, assignment
and historical lookup controls also passed across two runs. The first run exposed
an older rotation fixture hashing 17 stored challenge fields instead of the
producer's ten-field digest projection. Only that fixture was corrected, retaining
the full selected row and all existing assertions; the three affected groups were
then rerun with the previously unreached tests. These results do not establish a
deployed image, genuine Nitro admission or a live provider request.

### Private JIT sealing channel

The helper now dispatches `serverware.nativeJitReviewChannel/v1` on its existing
anonymous parent socket. Configuration requires the actually provisioned broker
KEK and completed encrypted service-token exchange. Configuration is one-use;
other active purpose operations exclude JIT commands. Existing idle owners may coexist, but
their configurations, request profiles and encryption domains are not exchanged.
Only `seal-pair` is available after configuration. There is no review/open,
plaintext-return, public listener or general decryption command.

The ordinary broker wire remains integer-only. After JIT configuration, the
decoder additionally accepts finite JSON numbers only inside the canonical
request and redacted-display private document subtrees of an exact `seal-pair`
frame. Configuration, policy, public commitments and every other command remain
strict. Duplicate/noncanonical JSON, nonfinite numbers, oversized commands,
depth/work overflow, replay, expiry and uncertain output remain fatal to that
helper process. Both document envelopes retain their original expiry.

The explicit source roster includes the 15 existing pure modules needed by the
actual JIT owner, its private-input validators and public request commitment.
It does not import app configuration, database access, SQL execution, planner or
transition registration, or Nitro admission. Dependency pins and package bounds
are unchanged. Both native source inventories include the new dependencies.

The connected process test target is `make verify-native-jit-broker-channel`.
It must run in an isolated test container as UID/GID 65534, with its test parent
not PID 1. It uses the actual helper entrypoint and private socket, local
RSA-OAEP/AES-CBC CMS material, encrypted service-token exchange and JIT AES-GCM.
Its synthetic identities and local test KEK are not KMS, Nitro or cold-purpose
admission. The package isolation checks remain a separate test boundary.

Offline validation on 2026-10-12 passed all 25 groups in the cached Python
3.11.15 image: eight package-isolation groups (4.877 seconds), eight owner groups
(0.149 seconds), and nine actual-process groups (19.149 seconds, 24 child
processes). Both runs used network-disabled, unprivileged containers with
read-only source mounts. All 20 recorded source/test hashes remained unchanged;
no test rerun, image build, service restart or pilot was needed. The process
suite used the source helper, not the full measured SquashFS/native runtime.

This connection does not make a working approval workflow: the authenticated
confidential native caller, private Rust preparation, distinct fresh proof,
independent authority verification, atomic writer custody and authorized review
opening are still required. The ordinary deployment is unchanged.

The [shadow-key helper](native-shadow-encrypted-keys.md#real-process-and-packaging-contract)
has a separate offline packager and image identity. Sharing the bounded copier
does not give either helper the other's entrypoint, key inventory or authority.

The image producer uses the checksum-pinned Debian SquashFS tool from
`production-dependencies/native-broker-linux-amd64.sha256`: one worker, gzip,
fixed timestamps and root ownership, without append, xattrs or recovery.
See its [documented options](https://manpages.debian.org/bookworm/squashfs-tools/mksquashfs.1.en.html).
The [snapshot candidate producer](production-dependency-snapshot.md) carries
these tool packages into the same unpublished candidate as Python and Rust
dependencies; it does not publish or accept that candidate.

| Artifact | Fixed location |
| --- | --- |
| Broker filesystem | `/opt/serverware/native-broker-runtime.squashfs` |
| Build inventory and expected pins | `/usr/share/serverware/native-broker-runtime.json` |
| Native-only entrypoint | `/usr/local/libexec/serverware-native-enclave-entrypoint` |
| Interpreter inside private root | `/usr/local/bin/python3.11` |
| Helper inside private root | `/opt/serverware/serverware/native_secret_broker_helper.py` |

The manifest lists each packaged file's path, mode, size and SHA-256, the source
manifest digest and image/interpreter/helper hashes. Its `helperImage` object
is the exact five-field broker input for independently admitted native startup
v5 and [encrypted service-token v6](native-encrypted-service-startup.md).
`releaseAuthority` is always false. The `native-broker-runtime-artifact` target
exports these same two outputs without mounting the image or starting custody.

## Startup boundary and remaining acceptance

The entrypoint starts as UID/GID 0 inside the enclave, checks the local NSM
character node, ensures root-only loop-control, clears the environment and
execs the fixed gate with `--native-encrypted-startup`. It accepts configuration
and launch artifact flags/pins, not an executable or arbitrary command.
The real parser requires v6 before constructing broker and measured audit
owners. Local device checks are only early refusal, never attestation.

The broker constructor needs mount/device and privilege-drop capabilities.
The helper drops groups, capabilities and UID/GID, disables dumping and uses
only the inherited anonymous channel. Private keys are generated inside that
helper; no key, provider token or host socket is baked into the image.
The gate [permanently drops privilege](native-serving-privilege-separation.md)
after retaining the actual NSM/helper preparation and before creating fresh
serving identities. V6 opens its encrypted service-token bundle only after
binding the actual measured broker, before publishing serving state. Separate
guest shadow/response service startup and confidential role-key delivery remain
required; including their binaries does not start or provision those services.

Frozen verification must check actual kernel features, recursive loader/import
closure, reproducible image bytes, refusal without v6/NSM, memfd/loop/mount
association, child isolation/cleanup, real KMS recipient decryption and
permitted/denied/revoked requests with audit delivery. The source changes do not
establish those runtime results. Measured OAuth issuance/refresh and remaining
credential custody connections are still required for complete N06.
