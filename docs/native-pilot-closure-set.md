# Static native pilot closure set

`catchplate.native_pilot_closure_set` is an unsigned fixed-role producer and
validator. It describes supplied static manifests; it does not approve them,
verify an assignment signature, sign or install anything, reconstruct a live
guest, or enable a commissioning policy by itself. The later explicit assignment
and [endpoint composers](native-pilot-supervisor-endpoints.md) connect this data
to admission and extend supervisor coverage to seven jobs, not runtime acceptance.

## Exact public original

`catchplate.nativeCustodyExecutionClosureSet/v1` has exactly `apiVersion`,
`members`, `setRootSha256`, and `seccompSetRootSha256`. The canonical ASCII JSON
original has no LF and is at most 12 MiB. Each member is exactly `{role,manifest}`;
each canonical manifest is at most 1 MiB. There are exactly eleven members in
this source-fixed order:

```text
retrieval, persistence, trustedTime, generationInstall, commitRequest,
ingressAdmission, terminalAppend, dispatchBarrier, activeEffectBarrier,
activeEffectCommit, bridge
```

The first ten manifests retain the existing v1
`sealed-memfd-squashfs-static-amd64-v1` profile. The bridge retains the existing
v2 `measured-bootstrap-late-runtime-static-amd64-v1` profile. Complete manifests
include their actual image/executable, runtime, seccomp and build-provenance
commitments and existing manifest hash. Unknown, missing, reordered, duplicate
or extra roles and fields are rejected. Different roles may legitimately have
different runtime or seccomp hashes; no identical-filter shortcut is assumed.

The Python helper reuses the existing public seccomp structural commitment
checks and validates build-provenance and manifest hashes. The native validator
retains the existing full manifest/seccomp validation. Neither establishes the
truth of supplied build provenance, installed images or an active filter.

## Deterministic commitments and cycle boundary

Let `C(x)` be the existing canonical ASCII/integer JSON bytes, and
`F(domain,x)` the existing `hash_domain_frames` operation over one frame:
SHA256 of ASCII domain, NUL, big-endian u64 byte length and the bytes `x`.
For each fixed ordered member:

```text
leaf = F("catchplate.nativeCustodyExecutionClosureSetLeaf/v1",
         C([role, completeManifest]))
setRootSha256 = F("catchplate.nativeCustodyExecutionClosureSetRoot/v1",
                  C([leafDigestString, ...]))
seccompSetRootSha256 = F("catchplate.nativeCustodySeccompSetRoot/v1",
                         C([[role, actualStructurallyVerifiedPolicySha256], ...]))
```

Digest values in these arrays are their literal `sha256:` strings. The complete
set has no assignment payload/hash, guest delivery, process identity, invocation,
window, authority key or signature inside its static leaves or roots. Thus an
independently signed successor assignment can bind both roots without the set
hash depending on that assignment's own payload hash.

The common closure-set root, common seccomp-set root, per-role closure leaf
hash, existing manifest hash and actual per-role seccomp policy hash are
different commitments. The old assignment and proof-scope fields still denote
their legacy individual manifest/policy values: this helper never silently
substitutes a set root for either. Explicit versioned successor producers and
receivers must authorize the common roots and verify the actual guest's exact
role membership while preserving all image, runtime, guest, signature,
currentness and lifetime checks.

## Pure source API

```text
set_original(members) -> unsigned canonical bytes
validate(original) -> checked static dict
require_binding(original, expected_set_root=..., expected_seccomp_set_root=...) -> dict
leaf_binding(validated, role) -> explicit public commitments
```

`require_binding` compares both expected roots; their independent authority must
already have been authenticated by the caller's actual assignment owner.
Passing hashes copied from the candidate itself is not approval. Returned dicts
are data, not transferable runtime or authority owners. `leaf_binding` rechecks
the closed set and returns `role`, `setRootSha256`, `seccompSetRootSha256`,
`manifestSha256`, `leafSha256`, and `structurallyVerifiedPolicySha256`.

## Protected-input preparation command

`scripts/authority/prepare_native_pilot_closure_set.py` accepts a canonical
`catchplate.nativePilotClosureSetPreparation/v1` original with exactly
`apiVersion` and the complete ordered `members` array. Its 12 MiB input bound
and per-manifest checks are unchanged. The independently selected SHA-256 pin
must match the literal input bytes; choosing a hash does not establish approval.

```text
python3 -I -B scripts/authority/prepare_native_pilot_closure_set.py \
  --input-fd <already-open-protected-public-fd> \
  --input-sha256 <independently-selected-input-sha256>
```

The command runs as root and reads an already supplied root:root 0400 public
regular file or sealed memfd through the existing authority I/O rules. It writes
one unsigned canonical set to the supervising process's root-owned pipe, not a
file or terminal. The parent must reject partial output and bound filesystem
stalls. No private key, signature, installation, startup window or running guest
is created; this static preparation does not extend any commissioning deadline.

The matching Rust `native_custody_closure::closure_set::ValidatedSet::from_bytes`
requires both expected roots and validates the existing full manifests. Its
`require_member` compares the complete selected manifest, not a caller-supplied
leaf hash. These are static preflight APIs, not live admission constructors.

This prerequisite does not by itself resolve the separately documented
measured-configuration/scope-bound object preparation dependency, nor connect
the required versioned assignment and proof-scope authorization.
