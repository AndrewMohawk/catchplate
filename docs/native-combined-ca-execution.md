# Combined native CA installation and immutable application trust

The explicit `serverware.nativeBootstrapClient/v6` cold profile composes the
existing independently authorized host CA effect with executable-child networking
and lifecycle. It requires all four nonnull inputs: `installation`, `egress`,
`attachment` and `execution`. Versions v1–v5 keep their previous closed shapes;
v5 still forbids installation, including null. Neither incoming signed bytes nor
a successful diagnostic selects v6.

This is source integration, not a built, provisioned or tested pilot. It adds no
host networking, writable image, trust overlay, implicit certificate issuance,
new application privilege or fallback authority.

## Separate genuine authorities

Startup verification still precedes private client-key loading and network
contact. The same actual TLS connection, original setup/delegation/evidence,
configuration, client key, host observations and original clock remain owned by
`ExecutionParents`. The combined installation guard retains that exact owner,
not a cloned verifier result or a second connection. It separately retains its
root-signed CA grant, protected token and actual `HostOwner`.

The CA grant must exactly match the genuinely admitted setup's destination,
capability, network owner and runtime CA. Its actual DER is obtained from the
held TLS connection. CA, egress, attachment and start authorizers and capabilities
remain separate; protected journals cannot alias or overlap, and the CA journal
and destination cannot overlap the network journals, bridge lock or start scope.
The start grant still selects its exact egress/attachment/launch/execution
originals. A receipt, digest or caller-selected success flag grants nothing.

All admissions use the identical `Arc<OriginalClock>`. The independently signed
CA expiry can only shorten that original allowance, never restart it. Actual CA
grant/original/destination/journal checks run during start admission and the
existing checks immediately before the first exec release and final detach.
After release, signed stop/cleanup bounds retain their existing meaning: there
is no renewed CA mutation or launch permission. An expired or damaged CA owner
does not suppress the independent whole-leaf emergency kill, exact leader reap,
guardian cleanup or bounded output completion.

## Immutable application trust is selected before the effect

V6 selects `serverware.nativeExecutionManifest/v2`; v5 selects v1 only. V2 retains
the exact prior eight fields and adds required `applicationTrust`:

```json
{"profile":"in-image-runtime-ca-pem-v1","path":"/etc/serverware/runtime-ca.pem","sha256":"sha256:<exact-pem-sha256>","certificateSha256":"sha256:<exact-der-sha256>"}
```

The illustration contains placeholders, not an admitted manifest. Actual hashes
are nonzero lowercase SHA-256. The full manifest remains canonical ASCII JSON,
without a trailing LF, at most 32 KiB, selected by the signed start authority and
the egress-authorized launch manifest. Its complete signed environment must
explicitly contain `SSL_CERT_FILE` equal to this path. The certificate path differs from entry and
loader paths.

This is an explicit supported **SSL_CERT_FILE application profile**, not proof
that arbitrary code or every TLS library honors that variable, validates peers,
or excludes its own additional trust sources. Use an application configured for
that profile and demonstrate its actual TLS behavior during pilot acceptance.
No code silently repairs a missing selection or substitutes the host trust store.

The file must already be inside the admitted single-device read-only
EROFS/fs-verity image: root:root, mode 0444 or 0644, 64–65536 bytes, exactly one
canonical PEM certificate with DER at most 16 KiB. Source opens it under the
actual detached root, checks mount/device and retained inode/bytes, and compares
its DER **byte-for-byte with the actual admitted TLS CA**, not merely a caller
digest. The child filesystem reopens and retains the same selected trust under
its own detached immutable root. Existing full-image, entry/loader, cwd, argv,
environment and no-ambient-submount checks remain.

Image provisioning must therefore include the selected CA before the image is
sealed and its manifest/start authority is produced. A different CA requires a
new image/manifest and independent admission, not an in-place write or mutable
mount. The host destination is checked not to overlap the admitted mount, block,
image or manifest. The host CA installation never writes or bind-mounts trust
into EROFS; bootstrap TLS itself still uses its previously verified startup trust.

## Effect ordering and interrupted outcomes

The combined path joins the immutable file and independent start constraints
before the CA journal claim. It then uses the unchanged CA destination mechanics:
protected journal lock, protected destination lock, irreversible claim, one
authorized installation and actual readback, then durable completion. Existing
completed records permit only exact read-only destination confirmation; incomplete
or uncertain claims cannot reinstall or retry. The completed journal and actual
destination owners remain held through executable-child execution and cleanup.

Only after actual CA completion can the combined `StartOwner` claim start and
creation, create the cgroup/blocked child, arm the guardian, install same-child
networking and consume the network-ready exec permission. Old diagnostic child
owners are never promoted. The preexisting running lifecycle, first positive
EXEC stop, original-budget final network snapshot, query-free continuation and
terminal cleanup are unchanged.

CA installation and workload execution are **not one atomic transaction**. If
installation succeeds but launch, execution or cleanup fails, the host CA can
remain installed. There is no fabricated rollback, automatic reinstall or fresh
attempt. An execution error after completed installation explicitly reports that
boundary; errors during an uncertain effect require inspection of the existing
protected CA journal/destination by an authorized local operator. No terminal
execution capture is fabricated when cleanup is uncertain.

A definite terminal result uses `serverware.nativeBootstrapClientCapture/v6`,
the existing v5 ten fields plus `installation`, with scope
`local-fixed-endpoint-bootstrap-ca-and-execution-observation`. The CA child is
the unchanged `nativeCaInstallationReceipt/v1`; the execution child remains
`nativeExecutionObservation/v1`. Source reserves 8 KiB and 16 KiB respectively
before effects, retaining the 1.5 MiB single-line capture limit including LF.
The receipt is historical completed-effect data, never post-expiry permission.
A nonzero workload exit can still produce the exact terminal capture while the
CLI returns failure. SDK extraction is data-only, not attestation verification,
installation authorization, restart permission or application connectivity proof.
