# Bridge prerequisites: current-head authority and initial histories

The `.384` batch connects prerequisite producers and readers, not a bridge
supervisor composer or a runnable pilot. Coverage remains **127/136**, with
**9 missing** and **108 key selectors**. Source checkpoints stay **36/46** and
production acceptance **0/6**. The [focused checks and native compile](#focused-verification)
pass; live bridge operation remains unverified.

## One separately approved current-head signature

[The profile](../catchplate/native_pilot_current_head_profile.py) and
[one-key signer](../catchplate/native_pilot_current_head_authority.py) implement
the existing native current-head attestation wire. The complete input is
`catchplate.nativePilotCurrentHeadAuthorityInput/v1`, bounded to 16 MiB, with
exactly twelve fields:

`apiVersion`, `serviceRole`, `driverConfigurationOriginal`,
`driverWindowOriginal`, `launchOriginal`, `configurationOriginal`,
`preparationOriginal`, `resourcesOriginal`, `initialHistoryOriginal`,
`rootAuthority`, `requestOriginal`, and `currentness`.

The original signed bootstrap window, approved launch/cold inputs, preparation,
resource observations, initial wrapper, checkpoint and three-party history
anchor are authenticated together. The service's checkpoint key signs; root,
service-signing, C9 or bootstrap keys cannot substitute. No key, authority
history, resource observation, receipt or request is generated.

`currentness` is an independently approved checkpoint-authority **decision**,
not evidence derived from that history. Its exact six fields are `profile`
(`initial-checkpoint-current-for-exact-request-v1`), `initialHistorySha256`,
`checkpointSha256`, `requestSha256`, `requestNonceSha256`, and
`issuedAtBoottimeNanos`. The issuer requires all literal bindings and the
original boot, request/checkpoint validity and startup deadline. It does not
infer that no newer checkpoint exists. The authority operator must establish
currentness and genuine retained-request provenance before approving the input.

The trust request uses the existing native `current-endpoint-trust` operation,
including the exact serde field `body.accepted_floor`. Its consume cursor is
required supplied data, not a manufactured initial receipt. Its nonce and
domain-framed request digest are distinct from the later service-handshake
digest, which includes the complete signed head. Equating those two digests
would create a hash/signature cycle.

The output is the existing signed five-field current-head object, bounded to
64 KiB. Pure `prepare_input` and `checked_result` helpers check bytes, signatures
and supplied clocks; they do not establish live ownership or approval. The
real signer brackets exactly one signature with actual boot/monotonic checks.

The fixed [authority command](../scripts/authority/sign_native_pilot_current_head.py)
uses the existing protected-FD machinery:

```text
python3 -I -B scripts/authority/sign_native_pilot_current_head.py --input-fd N --input-sha256 SHA --authority-key-fd N
```

The input is root-owned `0400`; the existing checkpoint key is a sealed 32-byte
memfd. The command retains exact bytes and identities, requires complete output
**and** successful exit, and grants no retry after partial or uncertain output.
A supplied digest is not independent approval. Software key copies are not
hardware custody or guaranteed erasure. No automatic supervisor currentness
decision or new job/key selector is added by this command.

## Explicit initial-history bridge runtime

`catchplate.policyCustodyProductionRpcRuntime/v10` retains v9's active-effect
behavior and adds `ordinaryInitialHistories`: exactly the five ordinary roles,
each containing literal `runtimeOriginal` and `generationGrantOriginal`.
Existing history credential names, root pins and semantic manifest digests
remain required. The new launch profile is `nativeProofBridgeLaunch/v6`;
legacy launch/v5 still requires runtime/v9.

The native adapter authenticates the actual wrapper with its ordinary runtime,
root-signed generation grant, approved exact grant hash and real admitted bridge
guest/configuration. It checks all five scopes for exact equality and joins the
available assignment, configuration, driver, protocol, envelope, trust and
original interval facts. It does not strip a wrapper into an unauthenticated raw
manifest, derive expected facts solely from the wrapper, or admit new fields
under legacy runtime versions. Actual empty-directory admission stays with the
ordinary service's receiving owner.

Later native generation guards still bind retained descriptors, driver receipt
and current trusted time before requests. History loading does not replace
those guards or claim service readiness.

## Version-specific transport bounds

The new [runtime profile](../catchplate/native_pilot_bridge_runtime.py) centralizes
the public shape/version limits. These are not signature or deployment approval.

| Material | Legacy limit retained | Explicit v10 path |
| --- | --- | --- |
| Complete bridge runtime | 64 KiB | 4 MiB, matching the native configuration ceiling |
| Embedded Head / Current / Cleanup grants | 64 KiB each | Head 64 KiB; Current and Cleanup 128 KiB each |
| Complete bridge installation/C9 input | Existing purpose-specific limit | 16 MiB, with branch-specific legacy refusal |
| Phase-two public bundle | 1 MiB | 16 MiB; native admission still requires configuration/scope v4 |

The fixed outgoing, C9, launch and scope readers must agree on the actual new
version and original digest; a larger parser buffer alone does not authorize
legacy input growth. Existing aggregate retained-resource limits remain.

## Remaining integration and verification

Genuine request/currentness acquisition, complete transport peer expectations,
four independently operated external signers, bridge-specific authorization
producers, the retained bridge composer and executable supervisor packaging
remain. See the [assembly map](native-pilot-bridge-assembly.md). No source-only
adapter or synthetic signature is service, hardware, provider or release
acceptance.

Fresh trust-request acquisition is a distinct remaining producer, not just an
export of the old systemd trust client. That client's authenticated startup
floor requires a signed consume head with a positive consumer sequence. The
fresh ordinary runtime instead binds an independently approved zero-consumed
cursor; an initial-history commitment is not a consume receipt. The next
initial-request owner must authenticate those actual originals under an
explicit fresh profile, preserving the old floor checks. The separate
currentness decision remains required. See the [source map](native-pilot-bridge-assembly.md#handshakes-need-a-genuine-current-head-producer).

## Focused verification

The first snapshot, `da5385a6`, stopped during preflight: an existing bridge
resource reader was absent from both Make inventories, and the exact compiler
image was no longer locally cached. No test suite or compiler ran in that
attempt. `fc919348` adds the missing inventory entries; the same pinned compiler
image was restored without changing the dependency candidate.

Exact source `fc919348b41ba98c8e20f204e3795da2bb248031` passed **157 controls in
19 suites**, nineteen-file Python 3.11 grammar/both Make inventories, and **50
relative documentation links**. The isolated CPU-0 Python **3.11.15** run exited
**0**, from `2026-10-01T01:44:33.432686972Z` to
`2026-10-01T01:45:23.762254335Z`. The nine new current-head controls use real
signatures over synthetic initial-history/request/currentness fixtures; the
seven runtime controls cover public grammar, exact versions and bounds, not
authenticated native history admission or genuine process ownership.

The first native compile found a missing `InitialHistoryBridge` arm in the
parent's exhaustive selection. `c54f343031ff6cdb04713070d094970d5c481a37` makes
the single-line routing correction to the existing proof inspector. It changes
no Python, Make inventory or checked documentation bytes; those checks were
not repeated. The corrected source passed
`cargo check --offline --locked --frozen -j 1 --bin catchplate-decision-gate`
in the pinned Rust 1.88 container, network disabled, one CPU and 8 GiB memory.
Exit was **0**, from `2026-10-01T01:46:14.900419557Z` to
`2026-10-01T01:47:15.023094764Z`; Cargo reported **57.67 seconds**. The result is
not warning-free: 312 library and 2,428 binary warnings were reported, including
duplicates. No warning cleanup or release-artifact rebuild was included.

All three source archives, original failed attempts, successful logs, exact
harness/commands, structured result and 21-file checksums are retained at
`codex-offload/catchplate/engineering-builds/c54f3430-bridge-prerequisites-2Yj6qc/`.
The final archive is **85,616,640 bytes**, SHA-256
`3778a05e669062c448b0ed18fec7b175f7a7b4f7d190460c72a6cccd76c705a8`.
Every retained checksum passed. These are engineering checks using the existing
unpublished dependency candidate, not release qualification. No DB/app/authority-store
modules, protected signing command, live owner, installer, service, provider or
hardware was invoked. No cloud resources or paid actions were used.
