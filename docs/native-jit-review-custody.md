# Native JIT review custody: implemented boundary and remaining work

The protected proxy path now has a purpose-specific source integration for
sealing and signing a review request. It **still refuses before creating a
pending approval or releasing a credential**. This page describes that boundary,
not a deployment runbook or evidence of successful native startup.

## What the new profile selects

`--native-jit-review-startup-v26` selects the closed
`serverware.nativeStartupConfiguration/v26` contract. It keeps the encrypted
service-token, secret-broker, currentness, measured-audit, guest-cohort and cgroup
prerequisites. It adds `measuredJitReview` and a distinct
`postbootJitReviewVsockPort`; it does not enable static credential creation,
rotation or OAuth. Existing startup profiles do not acquire JIT authority.

The complete original startup configuration remains measured. Its public
configuration object validates syntax, not authority. After exporting the
actual response-proof identity, startup receives a separate signed JIT
assignment over the bounded postboot channel. That transport is not trusted
because it came from the parent: the retained native custody owner verifies the
purpose-specific signature and joins the assignment to the actual identity,
proof key, executable and configuration. Service-token installation must have
completed before it configures JIT on that same broker.

The independently root-selected control-plane field
`nativeJitReviewCustodyPolicy` pins the installed operation manifest, exact
reservation TTL, sealing limit, attempt capacity, deployment, Nitro trust roots,
assignment authorizer and fixed target. The signed postboot assignment supplies
the dynamic boot/key/CA/configuration identity; it is not a reused static or
currentness assignment. Generator and service configuration validation admit
this optional field: omission preserves existing configurations, while explicit
`null` is rejected. Adding the field does not enable the writer.

## Request and ownership path

1. The actual buffered CONNECT request retains its connection, request, route,
   policy snapshot and original deadline. Before the authenticated
   `native-jit-prepare` HTTP exchange, it freezes a BOOTTIME deadline; elapsed
   network work cannot create a fresh request window.
2. The consumer checks the signed preparation response and its exact runtime,
   parent `release.reserve` and child `jit.request` originals. The retained JIT
   owner additionally requires the cold-selected manifest and exact reservation
   TTL before calling the real broker's private `seal-release-pair` channel.
3. The same broker produces the private `PreparedReleasePair`. The custody
   runtime obtains that value itself, rechecks owner identity and liveness,
   signs the purpose-specific statement with its actual native key, and obtains
   a fresh quote bound to the challenge, statement and signature. There is no
   public raw-pair signing API or caller-supplied success flag.
4. The caller rechecks its original request after proof creation, retains the
   originals and literal evidence, and terminates with refusal. It does not
   fall back to the old reserve path, publish an approval or persist ciphertext.

The compound pair's AEAD domains bind the complete canonical parent request as
well as the child and original private documents. Both encrypted items retain
their wrapped keys, nonces, full scope and commitments. Standalone and compound
profiles are distinct; the broker's shared spent-child fence prevents sealing
the child again through another parent or the standalone command. Assignment,
broker, key and request deadlines only narrow the sealing interval, which is at
most 30 seconds. The separate pending-document lifetime does not extend that
interval. Broker errors or uncertain exchanges poison the owned operation
instead of granting a retry.

## Independent proof verification

`authority_native_jit_review_custody.verify_original` reconstructs both requests
from the original private envelope, checks the complete encrypted pair and
owner-scope/capacity commitments, and enforces the selected TTL and assignment.
It verifies the independent assignment signature, statement signature and fresh
Nitro evidence against this purpose's trust roots. Its before/after checks keep
the caller's original deadline and clip it to the seal expiry. It returns
`None`, not a transferable verified object, SQL capability or review-open right.

This verifier is **not yet invoked by the service or planner write path**.
Independent planner configuration validation and original-evidence invocation
remain part of that integration, not something supplied by service-side policy
registration.

## Where to continue

The first missing write boundary is one admitted parent operation that atomically
retains the encrypted pair, admission evidence, pending child, capacity and audit,
then returns the committed approval ID without releasing the credential. The
service's `Private JIT release custody and atomic retention are unavailable`
refusal remains. Removing it alone would leave the planner/executor guards and
release transition unable to perform that write. A separate `jit.request` call
would not make the parent and child atomic.

After that, the complete flow still needs authenticated current-reviewer opening
of this native pair and an exact, one-use approved-request continuation. The
legacy approval reader cannot open this ciphertext. Ordinary approval UI or
notification success does not prove any of these native boundaries.

### Source map and evidence limits

- [Startup contract](../data-plane/decision-gate-rs/src/native_startup_config/jit_review.rs),
  [assignment admission](../data-plane/decision-gate-rs/src/native_jit_review_assignment.rs)
  and [retained purpose owner](../data-plane/decision-gate-rs/src/native_jit_review_v1.rs).
- [Buffered preparation caller](../data-plane/decision-gate-rs/src/native_release_jit_preparation.rs),
  [actual owner join](../data-plane/decision-gate-rs/src/native_jit_review.rs)
  and [native signing/quote join](../data-plane/decision-gate-rs/src/native_jit_review_custody.rs).
- [Python assignment verification](../serverware/authority_native_jit_review_assignment.py)
  and [custody verification](../serverware/authority_native_jit_review_custody.py).
- [Preceding component evidence and atomic-write map](native-buffered-release-context.md#next-real-integration-boundary).

Source integration is not successful hardware execution. Synthetic cryptographic
controls, compile-time API checks and ordinary CI must keep their own receipt
scope; none alone proves native startup, PostgreSQL atomic retention, private
review opening, provider behavior or a live deployment. This change does not
turn v26 into a combined all-purpose operator workspace.

### Focused Python verification

The frozen Python implementation passed 25 synthetic cryptographic controls in
`jit-custody-focused.FDfuCeek` and 57 configuration/private-ingress controls in
`jit-registration-focused.hjEkX1Fv`, with no skips or retries. The former uses
actual cryptographic verification of synthetic signatures, certificates, quotes
and encrypted pairs. The latter runs the actual generator and signed loader,
but deliberately stops service loading before runtime admission. Both isolated
containers exited zero, were removed, and retained unchanged imported-source
hashes. Their result SHA-256 values are respectively
`afdabf59a8babef326b0d3807b4dd6f92d0ca80cd341c2da711ed2d135497340`
and `521ffbdc9138960aeb756cf0f5cff3b54e402ea3d3bb99a65005e2558a2b31f2`.

The ordinary CI roster now includes both new suites. Its 12 orchestration
controls also passed; this does not run or verify the full ordinary suite.
At exact source `fb370844`, the Rust library-test build and all 30 selected
library controls passed. The subsequent binary-test compilation stopped with
five `E0425` errors: the new binary module and its tests referenced a BOOTTIME
helper in the wrong module. The correction uses the existing checked
`native_canary_transport::boottime_ns()` reader, preserving the same deadline
ordering and error propagation; corrected compilation has not yet run.
The 161 binary controls and 14 external API controls remain unexecuted.

The retained attempt is `native-jit-purpose-rust.ipFFLqFI`, with source-pins
SHA-256 `45058f352b6155bb7143b2d7d551c16e439796daead31f6814762ea68208e2d8`.
It reused an independent warm cache, launched no normal build or deployment,
and preserved the failed compiler evidence. A passed library test does not
establish successful binary compilation or native approval execution.
