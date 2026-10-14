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

### Opening integration contract

The next implementation must keep the private review inside the native browser
and recheck the reviewer before disclosure. The following flow is the agreed
integration target, not an enabled capability:

1. A distinct opening owner is admitted at cold startup from independently
   signed configuration and the actual native assignment. Sealing permission,
   a configured hostname or an environment flag cannot select this owner.
2. The native TLS owner creates a one-use challenge, browser cookie and
   recipient key. The portal relays the literal public challenge through
   `jit.review-open.authorize`; it cannot choose the challenge or supply a
   reviewer identity. The authority derives the reviewer from the original
   active OIDC session and authenticates the pending approval, retained pair,
   bound credential, trust publication, RBAC and current policy in one bounded
   read transaction.
3. The native broker verifies the authorization and exact retained originals.
   The native owner prepares an immutable private view but withholds it. Only
   a signed preparation proof leaves native custody. The proof binds the
   displayed document digest, approval, reviewer, session, challenge, pair,
   native identity and original expiry; it does not assert that a human read it.
4. `jit.review-open.receipt.issue` independently rechecks those current authority
   rows and atomically records the opening receipt and audit event. The actual
   commit owner returns a signed acknowledgment bound to the original challenge,
   authorization, preparation proof, review digest and committed roots.
5. The native owner accepts that exact acknowledgment only for its retained
   one-use cookie, recipient and private view, then sends the view over its own
   TLS connection. Failure or uncertain output cannot rearm the attempt.

The receipt commit is the authorization point. It does not promise instantaneous
revocation after commit. Challenge, preparation and disclosure remain within
their original bounded intervals, clipped to session, assignment, approval and
document expiry. Replaying a receipt neither renews those intervals nor produces
a fresh disclosure acknowledgment for a revoked reviewer.

The portal must authenticate the exact HTTPS route, OIDC cookie and CSRF state
before reading its bounded request body. One monotonic deadline spans body
reading and the worker handoff. It may relay ciphertext and signed public
originals, never decrypted review content, native popup cookie secrets or
recipient private keys. Its own original OIDC cookie is transient authority
authentication input, never JavaScript, a retained plan or an audit field.
Capability reads and ordinary page loads do not create an opening owner.

Historical pairs retain their literal parent, child, pair and proof strings and
the original sealed manifest. A new opening manifest cannot rewrite their
identities, rerun the expired sealing window or reseal private material. A
fixed historical-format validator checks storage consistency only; the opening
authority must separately authenticate the selected row and current reviewer.
The existing assertion reader's fixed row schedule and aggregate bounds cannot
be relabeled as this new read operation.

Opening receipts must not enable the legacy approve, deny or WebAuthn-options
paths. Those paths require explicit native-family refusal until native decision
and exact approved-request continuation are implemented. The shared workspace
must keep `can_decide` false; hiding its controls alone is insufficient.

### Implementation constraints for opening

The authorize read needs nine authenticated rows: OIDC session, its bound
WebAuthn credential, current trust high-water and matching published bundle,
RBAC authority and user binding, current policy high-water, pending approval,
and retained pair. Derive dependent selectors only after authenticating their
source row. Hash the original session token inside the measured owner; do not
accept a caller-supplied reviewer or successful-authentication flag. Preserve
the portal's exact activation trust generation and authenticator-class checks.
Unsigned current-root observations are not independent current-root admission.

Receipt issuance repeats those checks and adds the deterministic receipt,
receipt-capacity, audit and audit-capacity selections: thirteen logical rows
across twelve tables. It needs a separate fixed read schedule and byte budget.
The generic reader's 1 MiB row limit and the old compound reader's fixed
seven-row schedule plus derived receipt query and 4 MiB selected aggregate
cannot cover the permitted retained originals and trust bundle together.
Bound the complete acquisition, replay and commit path; raising one collector
limit is insufficient.

Registering the new purposes changes the installed manifest used by fresh
sealing. Extend the historical validator with an explicit frozen profile for
that new sealing format while retaining v349 unchanged. Test a newly produced
pending request as well as old retained originals; do not infer compatibility
from an old-format fixture or reconstruct historical requests with current IDs.

Native attempts must survive distinct actual TLS connections while retaining
the same cookie, recipient and immutable prepared view. The transport's
per-connection response fence is not the attempt's one-use disclosure fence.
Portal routes must establish their authenticated owner before reading the body;
the older static-credential wrapper's body-first ordering is not a template.
The acknowledgment must follow actual commit and current-root completion,
not a generic verifier-signed response or a reserved-writer acknowledgment.

### Source map and evidence limits

- [Startup contract](../data-plane/decision-gate-rs/src/native_startup_config/jit_review.rs),
  [assignment admission](../data-plane/decision-gate-rs/src/native_jit_review_assignment.rs)
  and [retained purpose owner](../data-plane/decision-gate-rs/src/native_jit_review_v1.rs).
- [Buffered preparation caller](../data-plane/decision-gate-rs/src/native_release_jit_preparation.rs),
  [actual owner join](../data-plane/decision-gate-rs/src/native_jit_review.rs)
  and [native signing/quote join](../data-plane/decision-gate-rs/src/native_jit_review_custody.rs).
- [Python assignment verification](../serverware/authority_native_jit_review_assignment.py)
  and [custody verification](../serverware/authority_native_jit_review_custody.py).
- [Fixed historical storage validator](../serverware/authority_native_jit_retained_history.py)
  preserves v349 originals and expiry; it grants no opening authority.
- [Private native browser transport](../data-plane/decision-gate-rs/src/native_browser_transport_v1.rs)
  owns the actual TLS/VSOCK connection without adding review or decision authority.
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

At exact `0eba227d`, the fixed historical validator, explicit HTTP/kernel native
decision refusals and private TLS transport extraction are implemented without
enabling opening or decisions. Genuine pending rows use a SHA URL; decision-only
SQL derives a refusal bit from the stored references without returning those
private values. Ordinary metadata reads remain unchanged.

The isolated Python batch passed **12 suites / 189 tests / zero skips** in
80.843 seconds. It covers historical originals, fresh SQLite metadata and the
four ASGI decision routes, legacy approval/denial, receipts, pending retention,
submission, custody and regression-runner controls. All 5,537 frozen source files
and 1,962 dependency files were unchanged; the owned container exited zero and
was removed. No dependency installation, real provider, PostgreSQL, native
hardware or live deployment was involved. Evidence is private under
`/srv/catchplate-archive/homelab_data/serverware-native-jit-python.aO1M816l`;
`results/result.json` SHA-256 is
`0a9c32ae6258c7aa91fae0aec54a4fedd161c26f01463ee0222276dca3c4324c`.

The same frozen commit passed fresh Rust normal-library and test-library
compilation in 611.536 seconds, then **seven tests and two external API compile
checks**, with zero skips. The private transport import failed with the required
`E0603`; the public creation/rotation API compiled. The emitted library and test
dep-info joined 213 and 222 own-crate inputs to the frozen source. Both containers
were removed, and the retained build cache was unchanged. This was not a proxy
binary build or an actual native TLS connection test. Evidence is private under
`/srv/catchplate-archive/homelab_data/serverware-native-tls-tests.ohSn7EDJ`;
`result.json` SHA-256 is
`a469394fc51cede993cff0f895428b5966cefd4db86699981bec9c199d42e4d0`.

Hosted [CI 38501166733](https://github.com/example/private-deployment)
at `1353068b` passed 87/88 suites. Its sole failing suite extracted the actual
approval route without its new decision guard. The test-only repair at
`96a7ca9e` includes that guard, updates the decision-metadata expectation and
checks that native requests cannot reach grant publication. Production guards
are unchanged. The focused publication, HTTP decision-fence and denial suites
passed **36 tests / zero skips** in 24.742 seconds. This check used the retained
read-only `0eba227d` source with the single reviewed test overlay, not a fresh
whole-tree or dependency rehash. Selected pins were unchanged and the isolated
container was removed. The original hosted failure remains preserved; this
focused result is not full successor CI acceptance. Private receipt:
`/srv/catchplate-archive/homelab_data/serverware-grant-publication-fix.xFo0wj7q/results/result.json`,
SHA-256 `5600a329b4abcc5abb84eca6bfbd84f6ad96c725c9e6ecc854f4ecc82b0030ac`.

The exact successor `7191646d` then passed hosted
[CI 38503173102](https://github.com/example/private-deployment):
**88/88 suites, 955 Python executions, 250 Node groups and zero skips**, in
791.495 seconds. All 88 test-script hashes, both dependency locks and individual
receipts were joined to that Git object. The original failed run remains
preserved. The private result under `serverware-hosted-ci-38503173102.NFD0Mays`
has SHA-256 `9fa8a5be4217c7d2917be18f583de0fa06bc8467659ecf2482c2e1d5001dda62`;
its verification receipt has SHA-256
`be48cb6f9a11787ed56a1d4820f63ec9ba3e8450d42520960400c46a25a10ad0`.
This CI result covers the prerequisite commit, not the later opening components.

### Protected review components

The new source separates read authorization, private preparation and committed
disclosure. The portal establishes its session, origin and CSRF checks before
reading the body, retains literal signed originals across the browser exchange,
and keeps its original 64-byte session token outside JavaScript and stored
plans. The reader authenticates nine rows for authorization and thirteen for
receipt issuance, including independent current-root observations before and
after the read. Independent replay derives the four receipt/audit mutations.
Purpose-specific signer custody requires the actual measured role, retained
root-owned read-only descriptor and independently configured key.

The native v27 profile combines sealing and opening through separate assignments,
channels and listeners. Its retained attempt spans TLS connections and consumes
disclosure before private output. The broker returns the encrypted review only
to the native recipient. Neither a preparation proof nor a component test says
that a human read the review or that a receipt committed.

**Opening is still unavailable.** The service selector returns `None`, and the
new read/replay components are excluded from the executable planning inventory.
The remaining connection needs a bounded streamed receipt plan, protected
successor custody and SQL execution, actual commit-marker/full-root readback,
current-root completion and only then a purpose-signed disclosure acknowledgment.
Its 32 MiB selected-row and 96 MiB original limits cannot be routed through the
old 4 MiB plan / 64 MiB packet by increasing a generic limit. Tokens must remain
transient, and uncertain commits must not generate fresh disclosure authority.
Native decisions and exact approved-request continuation remain separate work.
Fresh database creation uses the current v350 revision constraints. This does
not define an upgrade of an existing v349 store: that needs an explicit
preservation-aware migration, including unchanged historical native-pair rows.
Do not rebuild current-only constraints around old rows or rewrite signed
historical identities. The running instance is unchanged by this source batch.

### Opening component checkpoint and startup repair

The source batch was committed and pushed as `950701ae`. Separately frozen
local batches passed 44 registry/broker/codec tests, 70 reader/kernel/launcher/
private-request tests, 31 portal/runner Python tests, 15 inert JavaScript groups
and 22 purpose-signer tests. The signer lane used actual file-descriptor and
cryptographic controls with synthetic admission observations, not native
admission. These are results across multiple snapshots, not one complete run
of the final checkout. The original import, codec-fixture, reader-fixture and
portal-completion failures remain preserved.

Hosted [run 38510282856](https://github.com/example/private-deployment)
at that exact commit completed in 739.026 seconds: **84/96 suites passed and
12 failed**, with no budget non-runs or observed skips. Its 81 Python suites
reported 1,023 executions including failures; all 15 Node suites passed 265
groups. The separate signer step was skipped after the ordinary step failed.
Eight failing suites show the actual app import error at the closed API
classification guard. Four expose only parent assertions, so the same cause
is not established for those four. The capability suite also has a stale
source assertion that excludes the new observational availability call.

The repair adds exactly the two review purposes to the dedicated-workflow
classification. The generic handlers still reject them, the completeness
guard remains strict and the opening selector still returns `None`. Seven
classification controls, including actual app import and actual handler
refusals, are now registered alongside the existing two ordinary HTTP startup
checks. The capability source check permits only the exact availability
observer, not startup, private reads or authority dispatch.

The focused continuation also exposed older verifier, ACL, schema and
revocation-fixture drift outside ordinary CI. Their fixed inventories and
guards have been updated against unchanged production counterparts, retaining
all 116 test IDs. The schema test explicitly distinguishes the installed
eight-operation marker roster from the declared native receipt and requires
the unfinished review components to remain non-plannable. This does not install
the missing receipt bridge. Those four suites are now CI gates. Follow-up
classification, fixture and runner changes have source review but not yet a
successful execution result.

The final local 171-test attempt never started: Docker creation exceeded its
270-second setup ceiling, and only its owned CLI was terminated. Exact-name
and label checks found no container; late daemon completion remains uncertain.
The pending Rust verification likewise has not compiled or executed anything.
Its existing 846-file, 26,564,282-byte source export passed exact Git/blob and
frozen-metadata readback after a filesystem-wide flush timed out. No second
source copy or dependency installation was needed. Source receipt SHA-256:
`32022082aba8c2be12dd83803881f5fe1f35a9d6849deb93b2ffab7e043bd369`.
The old flush child was still waiting for writeback at the last observation;
its cleanup and source durability are not established. Keep these test-only
host failures separate from the unchanged application deployment.

The hosted artifact digest, all 96 script hashes, both dependency locks and
individual receipts were verified against the immutable Git commit. The first
local extraction timed out during per-file writeback; its partial evidence is
preserved. The bounded continuation used NVMe without a durability claim:
`/srv/catchplate-fast/tmp/serverware-hosted-ci-38510282856-cont.0JpZb3eH`.
Its aggregate result SHA-256 is
`6162273f9a3a66eb9bcfe499ce77254afe055a866c8ec144351ebb857b6f7b2d`.
The local batches remain under `serverware-native-review-*` and
`serverware-review-signers-direct.00dvooTf` in the operator evidence root;
the signer result SHA-256 is
`efa73e7807cba73ab7661e7487fc30c4b9490dde2421deccf9184c602ce59397`.

The following older checkpoints retain their original source and evidence scope.

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
The same 526-input closure was subsequently joined to the frozen 5,497-file
`c456d399` snapshot. Its `source-c456-snapshot.JBZPONuR/result.json` SHA-256 is
`294ba172d69ecabc25b8fe96a76ad06001732fcc63fb879c4bb46856d79587cc`.

Separately, the [ordinary SQLite migration](operator-authority-contract-migration.md#verified-migration-controls)
passed 12 synthetic tests with genuine old-source initialization, the actual
migration, two target cold starts, seven rollback points and a postcommit
unknown outcome control. A separate [retained-copy rehearsal](operator-authority-contract-migration.md#retained-copy-rehearsal-at-c456d399)
at `c456d399` then passed all ten roles and two genuine startup validations,
preserving old rows, ordered audit, quota and custody through the additive
transition. Its historical capture/environment are not a current promotion
backup. Fresh capture, promotion, paired rollout and browser/proxy verification
remain pending; neither run establishes native admission or normal-binary
execution.

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
