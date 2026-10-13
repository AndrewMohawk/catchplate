> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Native JIT review custody: implemented boundary and remaining work

The source now connects the protected proxy request to native sealing,
signing/fresh quote, authenticated submission, independent service/planner
admission and a pending-only atomic transition. A successful submission means
**review pending, not credential release**. This integration is not deployed or
accepted end to end; it does not establish native startup or working approvals.

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
`null` is rejected. Adding the field alone cannot bypass the independently
configured planner, admitted operation or existing writer checks.

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
4. After rechecking its original request, the caller submits five literal JSON
   originals to the distinct authenticated `native-jit-submit` endpoint. The
   bounded HTTP adapter rejoins the current route, credential generation,
   actor, policy and release defaults before dispatching one `release.reserve`.
5. Service and planner independently verify the evidence before witness or
   persisted-plan/SQL work. The pending kernel and executor retain the sealed
   pair, pending child, capacity and audit in the parent transaction; neither
   grants access nor consumes a credential, grant, quota or budget reservation.
6. The Rust consumer requires the signed response's exact pending identity,
   original document expiry and release binding. Its `PendingOnly` guard cannot
   dispatch or run legacy reservation cleanup. Lost acknowledgments are outcome
   unknown, not permission to retry or fall back to ordinary reservation.

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

Both actual service and measured-planner paths invoke this verifier through
`authority_native_jit_submission.verify_submission`, each with its own admitted
configuration/root and unchanged invocation deadline. A service-side result is
not a planner verdict. Fresh submission must pass fresh admission even when an
earlier attempt might have committed; committed execution-owner replay remains
inside the existing executor.

## What is retained

The private `runtimeOriginal` is transient, separate from BusinessIntent and the
signed plan. Only `parentOriginal`, `childOriginal`, `pairOriginal` and
`evidenceOriginal` enter `nativeJitPending`. The executor joins those exact
strings to the locked original planner bytes and rechecks the clipped deadline.
The original seven-field parent request is not rewritten to carry evidence.

The insert-only, 20-column `policy_authority_native_jit_review_pairs` contract
retains the full pair/proof originals and their parent, child, owner, key and
expiry commitments. The same pending transition includes the approval, pending
capacity and audit; a missing route is inserted before the approval's foreign
key. Existing matching grants and conflicting retained rows refuse this fresh
pending branch. Approval private fields contain opaque `native-jit:v1:`
references, not plaintext or open capabilities. Legacy private readers reject
that reserved namespace; metadata/history can remain readable.

## Where to continue

Complete runtime verification of this connected source: authenticated
root/capability/ACL writer admission and compilation/execution of the new Rust
submission remain separate gates. The existing two-second HTTP send cap also
needs measured native verification/SQL latency; component checks do not establish
that runtime budget.
The SQL root-transition payload roster omission was corrected in source
(`root_transition_sql.py` SHA-256 `82e6fe7f…`) and its isolated PostgreSQL
component checks passed; that is not a committed native-request proof.
The old private channel still refuses; only the independently admitted new
channel selects the pending transition.

The next missing product boundary is authenticated current-reviewer opening of
this native pair, followed by an exact, one-use approved-request continuation.
The legacy approval reader cannot open it. A pending ID, ordinary approval UI
or notification success does not prove review, approval or provider execution.

### Source map and evidence limits

- [Startup contract](../data-plane/decision-gate-rs/src/native_startup_config/jit_review.rs),
  [assignment admission](../data-plane/decision-gate-rs/src/native_jit_review_assignment.rs)
  and [retained purpose owner](../data-plane/decision-gate-rs/src/native_jit_review_v1.rs).
- [Buffered preparation caller](../data-plane/decision-gate-rs/src/native_release_jit_preparation.rs),
  [actual owner join](../data-plane/decision-gate-rs/src/native_jit_review.rs)
  and [native signing/quote join](../data-plane/decision-gate-rs/src/native_jit_review_custody.rs).
- [Python assignment verification](../serverware/authority_native_jit_review_assignment.py)
  and [custody verification](../serverware/authority_native_jit_review_custody.py).
- [HTTP submission](../serverware/native_release_jit_submission.py),
  [independent admission channel](../serverware/authority_native_jit_submission.py),
  [pending kernel](../serverware/authority_transition_native_jit_pending.py) and
  [locked-plan retention](../serverware/authority_store/native_jit_retention.py),
  with the [SQL payload guard](../serverware/authority_store/root_transition_sql.py).
- [Rust pending submission](../data-plane/decision-gate-rs/src/native_release_jit_submission.rs).
- [Preceding component evidence and atomic-write map](native-buffered-release-context.md#next-real-integration-boundary).

Source integration is not successful hardware execution. Synthetic cryptographic
controls, compile-time API checks and ordinary CI must keep their own receipt
scope; none alone proves native startup, authenticated native-to-PostgreSQL
retention, private review opening, provider behavior or a live deployment. This change does not
turn v26 into a combined all-purpose operator workspace.

### Current component verification

Hosted [CI 38465762551](https://github.com/example/private-deployment)
passed at exact `aca8e74e`: **74 suites, 737 Python tests, 210 Node groups,
zero skips**, including the actual 32 npm groups and two SQLite bootstrap tests.
Artifact receipts were joined to the checkout, all test scripts and
`requirements.lock`; this is not an imported-source closure audit, Rust
acceptance or deployment evidence. The retained `ordinary-ci-aca8e74e.yRbYZGBs`
verification SHA-256 is
`485ac69dbcb7f126076613efa62422e14b278ed59c1365ae4f743c4c54df1180`;
its result SHA-256 is
`744c440f892ed82b9a0268b631b5ad13bbfe20219a03585f8b0545b61cb2d855`.

The separate Rust batch at exact `aca8e74e` passed **30 freshly executed library
tests, 170 binary tests and all 14 API checks**, with no test-result reuse.
All 58 owned containers were removed and six maintenance locks released.
That verification phase built test artifacts only; it establishes no
native/provider admission or deployment. Durable evidence is
`native-jit-submission-rust.skpaNdl9`; result SHA-256 is
`96d8dea3a72065011d86c113a91e0ee434f952870e6162bc4aa02dddf7323601`,
and its `phase-receipts.tar.gz` SHA-256 is
`3ccacb0947a9adc6b3d11133ba044f14c9168ef8e63770c99c61f2f2bfc1537e`.
The earlier failed Rust stages below remain historical evidence.

A separate normal build at exact `aca8e74e` then passed in 239.302 seconds
(`cargoFresh: false`), producing a 42,396,848-byte ELF with SHA-256
`5d3803b24722b6e4f6683f824d50922360a4e5c381a3944fe710bf526cbe7867`.
Independent audit joined all 526 compiler inputs to the selected source bytes
and exact Git commit. The compiler container exited zero without OOM, was
removed, and its scoped inventory was empty; the maintenance lock was released.
The retained `normal-compiler-inputs.json` receipt has SHA-256
`1f359a592ecc5be96e99effd34a9d05aa62c9bc5a4f1c98f29465eaca2bdcb3b`
and `normal-cleanup-join.json` has SHA-256
`5d661de26e79b8c38210c0e9be2d0a2668c78c6668925db14c67ec576f40fc8c`.
The normal executable has not been run or deployed; the 30/170/14 checks used
separate test artifacts.

Separately, the [ordinary SQLite migration](operator-authority-contract-migration.md#verified-migration-controls)
passed 12 synthetic tests with genuine old-source initialization, the actual
migration, two target cold starts, seven rollback points and a postcommit
unknown outcome control. This is not retained-data or native admission proof;
retained-copy rehearsal and deployment remain pending.

The earlier isolated stages remain separate, with their failures preserved:

- `native-jit-integration-corrected.u5Ku9AJf` passed its first nine suites /
  130 tests, then failed the new ingress suite. The generic name guard rejected
  the legitimate `requireAttestationTrusted` policy setting. Its narrow fix
  validates the closed grammar before projecting only that boolean out of the
  name check; signed originals are unchanged. The failed aggregate is retained.
- `native-jit-targeted.fR3faRvB` then passed 57 Python tests: 27 corrected ingress,
  12 legacy private-ingress and 18 HTTP controls. The actual npm child and strict
  runner parser passed 32 groups, but the wrapper expected a stale 63 and
  refused the aggregate. That failed wrapper receipt was not rewritten.
- `native-jit-sqlite-corrected.vIY8TDAo` passed two actual isolated SQLite tests,
  including two starts and installed constraints with rollback-only fixture
  rows. This is development-schema evidence, not PostgreSQL or native admission.
- `native-jit-runner-final.3aUJps1w` passed all 12 runner controls after the
  explicit roster reached 74 suites. That earlier run exercised runner controls only.
- `native-jit-storage-postgres-corrected.Pz4gxn` passed 10 isolated PostgreSQL
  controls with zero skips: composed DDL/immutability, the actual pending kernel,
  production CAS/application order, SERIALIZABLE commit/rollback, foreign keys,
  lifetimes and exact SQL payload/duplicate checks. Synthetic keys/clocks remain;
  authenticated root/capability/ACL admission, hardware, private opening and
  deployed restart are excluded. Normal teardown/shutdown passed and the exact
  container was removed; the earlier teardown failure remains preserved.

The targeted result SHA-256 is
`7734117a78290c478d9c26b672b91389aeb095e23a12b6d8b7cd8348542196d4`;
the SQLite result is
`fbfd636d4a782b1925ad516a6ac46fba3c10b2ced9742cc4921402ecbbd0d296`.
The PostgreSQL execution receipt SHA-256 is
`5c4f3dc6dc2c63c402657b9eb4b33ac222d5338930595f4cafa45eb119fbcf7b`.
These synthetic crypto/kernel, writer-boundary, no-lifespan ASGI and local-schema
checks do not establish a committed native request, private opening or provider
execution. Original failures remain distinct from the corrected child results.

### Earlier verification checkpoints

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

Those two suites entered the ordinary CI roster. Its 12 orchestration controls
also passed; those receipts do not cover the later submission/retention source.
At exact source `fb370844`, the Rust library-test build and all 30 selected
library controls passed. The subsequent binary-test compilation stopped with
five `E0425` errors: the new binary module and its tests referenced a BOOTTIME
helper in the wrong module. The correction uses the existing checked
`native_canary_transport::boottime_ns()` reader, preserving the same deadline
ordering and error propagation.

The failed attempt is retained as `native-jit-purpose-rust.ipFFLqFI`, with source-pins
SHA-256 `45058f352b6155bb7143b2d7d551c16e439796daead31f6814762ea68208e2d8`.
It reused an independent warm cache, launched no normal build or deployment,
and preserved the failed compiler evidence.

### Corrected Rust checkpoint — `429dee2a`

The binary-test compilation passed in 226.082 seconds (`cargoFresh: false`),
producing test ELF SHA-256
`76531a6ec840564de146c7d19482f0f6881ec7d219f7dc9cab63aa821022ea08`.
All 161 selected binary tests passed across 35 filters. The earlier 30 library
passes are carried from their unchanged source, not newly executed. The corrected
run's source-pins SHA-256 is
`20d6f8b153376c2fea40d5c6736dc5ddc9bcbc47f13cdb233ac75ae7c5a7f5c8`.

API probes 0–10 were accepted. Probe 11, `pair_construct.rs`, correctly produced
`E0451` for the private `pair_original` and `proof_original` fields on source
line 3, but with two primary diagnostic spans where the harness required one.
The aggregate therefore failed; probes 12–13 did not run. No API visibility
regression was observed, but this is not complete API or overall acceptance.

No normal binary was built or deployed. This historical checkpoint does not
cover the later `aca8e74e` pending-submission batch verified above.
