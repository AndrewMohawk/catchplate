# Native assignment and closure-set admission

The `.367` source connects explicit versioned assignment, guest-membership and
shared-proof contracts. It does not enable the held commissioning jobs or prove a
running pilot. That checkpoint had **36/46 source checkpoints**, **0/6 production gates**
and **3/60 supervisor jobs**; the later [endpoint composers](native-pilot-supervisor-endpoints.md)
extend job coverage to 7/60 without changing production acceptance. Exact commit `d5d0746b` passed isolated offline
Rust 1.88 Cargo checking; this is not linking, runtime or production evidence.

## Separate common roots from actual guest leaves

| Original | Explicit contract |
| --- | --- |
| Assignment/v2 | Existing ten-field signed envelope, with API and signature domain `catchplate.policyShadowAssignment/v2`; the native payload adds required `nativeClosureSet` |
| `nativeClosureSet` | Exactly `setRootSha256` and `seccompSetRootSha256`, independently authorized by the assignment signature |
| Closure/v3 | Exactly `apiVersion`, `manifest`, `authorization`, `closureSet`; embeds the complete fixed eleven-member set and the selected guest's manifest |
| Closure authorization/v3 | Purpose `shadow-custody-closure-set-member`, profile `native-multi-guest-closure-set-v1`; adds `guestRole`, both common roots and `leafSha256` |

The assignment's existing `custodyAuthority.executionClosureManifestSha256` and
`structurallyVerifiedSeccompPolicySha256` remain **bridge leaf anchors**. Neither
is reinterpreted as an aggregate. The [static set](native-pilot-closure-set.md)
contains the ten existing endpoint v1 manifests and the bridge v2 manifest in
fixed role order. Its two roots and each role's membership are checked together.

The native owner selects the actual service role, verifies its signed membership,
and retains the existing image, executable, runtime, seccomp, key, trusted-time
and lifetime checks. Guest/key-admission leaf commitments still describe that
individual guest. A common root is not a substitute for its live measurements.
The complete live closure original remains bounded to **1 MiB**, including its
embedded set; the standalone set helper's larger bound does not enlarge intake.

## Existing authority commands, explicit successor inputs

`scripts/authority/sign_native_pilot_assignment.py` consumes exact
`catchplate.nativePilotAssignmentAuthorityInput/v1` fields `apiVersion`,
`trustOriginal`, `trustSha256`, `payloadOriginal`, and `closureSetOriginal`.
The independently pinned trust original selects the matching existing assignment
key. All payload decisions, timestamps and complete manifests are supplied;
the issuer neither chooses authority nor creates provenance.

`scripts/authority/sign_native_pilot_closure.py` retains its legacy bridge input.
Explicit `catchplate.nativePilotClosureAuthorityInput/v2` additionally supplies
`guestRole` and `closureSetOriginal`; `controlOriginal` is present only for the
bridge. Endpoint configuration/window/observation originals come from the actual
cohort. Issuance follows actual guest observation and signed C9 delivery, before
launch installation. The signed member domain is
`catchplate.nativeCustodyClosureAssignment.signature/v3`.

Both commands take only `--input-fd` and `--authority-key-fd` under `python3 -I -B`:
a complete approved public original and a distinct, already provisioned protected
key. Inputs are at most 8 MiB; outputs are canonical originals without LF. These
commands do not approve their own inputs, generate keys, install files, renew
startup windows or retry. The independent supervisor must reject partial output
and bound filesystem/cryptographic stalls.

## Measured configuration and shared receipts

[Recipe/v2](native-pilot-measured-configuration.md) has the old ten fields plus
`closureSetOriginal`. Its retained pre-spawn owner authenticates Assignment/v2,
the whole set and bridge membership, then uses the actual owned bootstrap
observation. Configuration binding/v2 preserves all 24 old fields and adds
`nativeClosureSet` as field 25, under
`catchplate.policyShadowProductionCustodyConfiguration/v2`.

Shared proof scope/v2 preserves the fourteen old fields and adds exactly:

- `api_version`: `catchplate.policyShadowProductionCustodyProofScope/v2`
- `execution_closure_set_root_sha256`
- `structurally_verified_seccomp_set_root_sha256`

Its framed `/v2` digest appends the two common roots to the old eleven-value
tuple. Its canonical authority receipt is the eight-element array
`[domain/v2, scopeBinding, bridgeManifest, bridgePolicy, setRoot, seccompSetRoot,
signerRole, receiptSha256]`, with domain
`catchplate.policyShadowAssignmentBoundCustodyReceipt/v2`.

Retrieval, persistence, spool, opening and checkpoint paths use this transcript.
Python service intake requires the exact assignment payload bound by the actual
signed key authorization. The conductor passes its already pinned assignment to
the retained endpoint owner and persistence intake; it does not reconstruct it
from hashes. Native membership admission remains mandatory.

## Independently configured activation pins

`catchplate/app.py` selects the successor activation-receipt transcript only with
all three independent settings:

```text
CATCHPLATE_POLICY_SHADOW_ACTIVATION_PROOF_SCOPE_VERSION=v2
CATCHPLATE_POLICY_SHADOW_ACTIVATION_EXECUTION_CLOSURE_SET_ROOT_SHA256
CATCHPLATE_POLICY_SHADOW_ACTIVATION_SECCOMP_SET_ROOT_SHA256
```

Both roots must be explicit nonzero `sha256:` digests. Existing public-key,
signing-key/SPKI, proof-scope-binding, execution-closure and seccomp-policy pins
remain required; the last two still pin the bridge leaf. Pins are not selected
from the arriving receipt. Missing/malformed successor pins, unknown versions,
or roots supplied with v1 refuse verification. The default remains v1 with no
set roots, preserving the legacy receipt bytes. Generic legacy assignment DB
admission is not expanded by this native successor.

## Next connection, not a readiness claim

`CommissioningSupervisor` still composes only `driver-bootstrap`,
`cohort-precreation` and `install-precreation`; its complete-coverage guard
refuses before spawn. The next implementation seam is to bind the approved v2
recipe in that actual supervisor, derive it from the genuine pending bootstrap
result, and carry its retained result into the `endpoint-inputs` decision and
the first three C9 delivery composers. The admitted policy must authorize the
static originals and their dynamic derivation, not future guessed identities.

Scope-bound nonempty retrieval originals, their genuine receipt authority and
protected storage still need an actual provisioning path. This batch creates
none of them. Remaining job decisions, protected installation and the connected
application allow/deny/cleanup run stay open; no signing, launch, cloud operation
or acceptance result is claimed here.
