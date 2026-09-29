# Explicit native execution parents

The executable-parent lane is distinct from the existing never-executed egress
diagnostics. It admits originals and a separate durable creation claim; it does
not create a child, install networking, execute an application or report those
effects as complete. The independent signed start owner must consume the actual
retained parents and the actual creation permit before its own effects.

## Closed profile selection

Egress authorization v4 has the same closed 31 payload fields as v3, but its
envelope, payload schema and signature domain are explicitly version 4. Only
v4 accepts workload profile `native-egress-new-execution-v1`; versions 1–3 keep
`native-egress-create-new-workload-v1`. The `create-new`, `never-executed` and
`terminate-before-start` values remain pre-start obligations, not authority to
run the workload. Manual dual-stack child network policy remains mandatory.

The new canonical ASCII, no-LF launch manifest is bounded to 4096 bytes and has
exactly four fields: `apiVersion: serverware.nativeEgressLaunchManifest/v2`,
`profile: native-egress-new-execution-v1`, `executionManifestSha256`, and
`launcherBinarySha256`. Both pins are nonzero SHA-256 commitments. The launcher
pin equals the signed grant and the actual retained `/proc/self/exe` original.
There is no host executable placeholder, argv or environment in this manifest.
The separately pinned execution manifest supplies the real immutable-root entry
configuration, admitted by the distinct execution filesystem owner.

Only the explicit cold-selected `prepare_for_start` and `bind_for_start` path
can produce `ExecutionParents`. Ordinary `prepare`, attachment preparation,
legacy `bind` and the old `LaunchSpec` all reject the execution profile before
child creation. No incoming profile, observation or serialized verdict can
convert an old diagnostic owner into executable parents.

## Original ownership and start join

Preparation consumes the actual attachment `Pending` and retains the real
launcher, launch manifest, protected token and grant originals under the same
original clock. Binding consumes the genuine same-TLS bootstrap proof,
connection, host observations, cold/client/configuration originals and private
client key. It uses the same source-only original scope admission helper as the
legacy path; no signature, policy, target, SAN, interval or independent-key join
is replaced by a copied success object.

`ExecutionParents::check()` rechecks those actual objects. `require_start`
requires the identical `Arc<OriginalClock>`, exact start-selected egress,
attachment, launch, execution-manifest, launcher and machine commitments,
actual launcher host identity, independent start key/capability/token roles,
and distinct protected journals/bridge-lock scope. Start admission must fit the
genuine parent admission intervals. Separately signed stop/cleanup deadlines
do not renew the original clock, TLS proof or network authorization.

## Irreversible creation claim

`claim_creation(self: &Arc<Self>)` returns only a non-Clone
`ExecutionCreationPermit` from the actual protected creation journal. The
journal uses the unchanged `SWNEGCR1` bytes and stable namespace/capability
slot; old, completed, incomplete or uncertain records never become fresh by
changing the profile, proof or process. Old and execution permits are distinct
types backed by a closed source-owned enum, not a generic callback or supplied
scope. The existing legacy `claim` API and record format are unchanged.

The new permit's `require_owner` compares the exact retained owner pointer and
current original admission. Its cleanup-integrity method instead checks the
same immutable owner association and bounded held/named durable record without
an admission clock or deadline. That method cannot grant creation or reopen a
slot. Emergency termination may still use independently sealed owned kernel
descriptors when current admission or journal integrity has failed; such
failure cannot be silently turned into a completed cleanup receipt.

There is no claim of a running workload, persistent attachment, successful
provider request, independent guardian, leader reap or pilot verification in
this source layer. No build or runtime execution accompanies this change.
