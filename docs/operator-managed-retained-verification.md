# Private managed retained-state rehearsals

## npm candidate: two retained cold starts passed

On October 10, 2026, the stock-client-passing app snapshot
`3724110941888e753bc194459e14170bc2a28916` and actual gate executable
`82a99cf00a7763dd1187f86607ffe2415487e98734f4b7d585f44909150e7b85`
passed two cold process starts on fresh isolated copies of the historical
managed `9222b4c0` store. This is **not a live deployment**. The running demo
continues to use its previously deployed pair.

The immutable app has 4,952 manifest-verified files. The existing compiler-input
equality receipt joins it to the genuine `b55f3024` build: 499 compiler inputs,
745 crate files, Git modes and Cargo files match. No new Rust build or Rust test
run was performed. The input was `managed-rollout.wB0mAsgW/after-app`, captured
after the `9222b4c0` app had stopped during the earlier rollout. It is a historical
recovery set, not a fresh snapshot of today's live store. Original archives,
live data and native pilot state were not changed.

Both starts strictly completed app health and a read-only publication check
before starting the gate. That check used the original shared lock and required
the canonical and exported policy, unconfigured managed manifest and empty
provider custody to agree. The subsequent actual pair observation joined the
same app container/process and file identities, checked the real executable,
curated gate mounts, loaded policy and complete audit chain. The second start
reused the same containers with new app/gate processes and the original keeper.

Both stopped-state comparisons passed with 1,335 schema objects, 210 non-audit
tables, all 204 audit events, eight credentials/applications/rules and 108 nonces
preserved. Credential generations, application token state, signed policy and
high-water state, original CA/key and shared lock remained intact. No gate export
entries were added. The only admitted exceptions were three migration timestamps
and two derived CA-publication inode changes with identical contents. No expired
application token was renewed.

Each runtime check reported catalog revision 13, active/loaded policy sequence 9,
Google unconfigured, and a running notification worker with four independently
disabled, unconfigured destinations. Action-required alerts and audit-log
delivery remained separate. Notification tables remained absent and both
custody directories stayed empty. No native observation source was configured
and no message was sent.

The keeper ran from **19:45:14 to 19:46:28 UTC**, within its original 600-second
lifetime; work and cleanup retained their 480/60-second bounds. The fixture had
only loopback networking, no external route, host ports, upstream listener,
provider exchange or native action. App/gate stopped deliberately with exit 143;
the keeper exited 0, with no OOM or automatic restart. The runner exited 0 and
cleanup succeeded. All private service/helper containers were removed; all
remaining-container, helper and network listings were empty. Private recovery
copies and evidence remain retained.

Evidence is in `../catchplate-operator-workspace-evidence/npm-retained-372.8WNw8TNL/`:
the two pre-gate publication observations, pair observations, stopped inspections,
preservation comparisons and cold-process identity join. Result SHA-256:
`912491b78f58d279d47231bbc0d21aa80ee297f2da121a84d95697686c1560cb`.
Terminal receipt SHA-256:
`c7d8398dbe18be28dbddda2ddbc21ddcc839a880085518fb37963c87f36f3bb6`.
The one-shot fixture is terminal and must not be replayed.

Live rollout still requires an explicit candidate Compose selection and retained
reviewer support for the existing rich compiler-equality receipt, followed by
current configuration review, a fresh stopped-consistent backup and the normal
paired runtime/browser gates. Do not flatten that receipt into the older
eight-field format or imply that the app and compiler commits are identical.
The earlier deployed selection remains unchanged until those gates pass.

## Earlier managed-Google introduction rehearsal

On October 10, 2026, the managed-capable app and actual decision gate passed an
initial cold start and a second cold process start using an isolated copy of the
retained operator-demo store. Both stopped-state preservation comparisons passed.
Google remained **unconfigured**. This is not a live deployment, browser session,
provider exchange, proxy-forwarding test or physical-key acceptance.

## Exact candidate and retained input

The app source was `9222b4c090d77aa983d3c01be34e0a2ba79f8e6c`: 4,910 files checked
against Git blobs and frozen nonwritable. The source-manifest file SHA-256 was
`b724e252161476dbd5106aadbb71c4229afb36e47c1528e4678e166333f7a3da`.
The actual gate executable SHA-256 was
`333ff7a3db00ab2bf03644fc965aed9b691bdd6ddc4ec651273e6d0c36f053e0`.
Its existing offline Rust build was joined to 494 exact compiler inputs plus
Cargo.toml/Cargo.lock in the candidate. No new build or whole-tree equivalence
is claimed.

The input was the historical `destinations-rollout.ArihVAhH/after` recovery set,
whose data archive SHA-256 was
`eb3199352ac628bce1183316aa935636dd5d3feaec5941550b21e91835446c00` and inventory
SHA-256 was `190226ef332549fa97f7b06e9120913b8f21ec852e45c4e55766573c474a3e87`.
The original recovery set and live directories were not mutated. A fresh
stopped-consistent live backup is still required before any live rollout.

## Runtime and preservation results

The prepared recipe ran only the copied app, actual gate and a bounded network
keeper. It had no external Docker network, host ports, default route, upstream
listener, provider connection or real notification receiver. The keeper dropped
privileges and capabilities after assigning loopback addresses, and was stopped
within its original 600-second lifetime. Both app/gate observations joined the
actual source, executable, namespace, original shared file identities and
SQL-bound public policy/configuration. The gate saw only the curated public
runtime tree and separately mounted required original files, not the app database,
provider custody or app master/signing keys.

Both runtime observations returned catalog revision 13 with eight credentials,
eight applications and eight access rules. Active/loaded policy sequence 9 matched
`sha256:25a129a2beba61130532345fc5dd23829a48c2f0a45f91da4a4685cb68cce568`.
The audit-chain API verified the complete retained SQLite chain. The read-only
Google configuration GET after the second start returned `unconfigured`,
`pair_ready: true`, `consent_ready: false` and an eligible setup review. That
review did not apply its proposed destinations: the effective allowlist stayed
at `https://demo-upstream:8443`. No Prepare, consent or token issuance occurred.

Notifications were enabled with their worker running. All four destinations
remained independently available, disabled and unconfigured:

- `action_required.slack` and `action_required.webhook` for required human action.
- `audit_log.slack` and `audit_log.webhook` for audit events.

Neither notification nor provider custody gained a file. Native hardware
observation remained unconfigured. These reads verify retained unconfigured
availability, not Slack/webhook delivery or a real YubiKey prompt.

After each process pair stopped, comparisons on further private copies verified:

- All 1,335 schema objects and 210 non-audit authority tables were preserved;
  all 204 audit rows remained the exact prior prefix, with no new rows.
- Credential generations, application token verifiers/expiries, nonces, signed
  policy/high-water, original CA/key material and original shared lock identities
  were preserved. Expired application tokens were not renewed.
- The first start added exactly eight approved derived gate-runtime entries;
  the second added none. Provider custody stayed empty with the same identity.
- Three migration `applied_at` timestamps changed on each start. Two derived
  `decision-gate-ca-{cert,key}.pem` files were republished with new inodes but
  identical bytes, ownership and modes. These are explicit narrow exceptions,
  not whole-database byte equality or permission to replace original CA files.

The same app/gate containers were stopped and started, producing new process IDs;
container recreation was not tested. The second gate start was issued while the
app's health-wait command was still outstanding, so it does not establish the
strict app-healthy-before-gate-start ordering required for live maintenance.
Both were subsequently healthy and passed the complete pair checks.

## Evidence, corrections and cleanup

Private receipts are retained beside the checkout at
`../catchplate-operator-workspace-evidence/managed-retained.qBkamJ3p/`:
`source-verification.json`, `compiled-source-join.json`, both `*-pair.json`
observations, `retained-google-configuration.json`, both `*-preservation.json`
comparisons and stopped-state archive/inventory sets. The comparisons intentionally
do not claim to observe process termination themselves; separate
`first-stopped-containers.json` and `retained-stopped-containers.json` establish
that prerequisite.

Initial verification-helper failures are retained: compiler depfile paths needed
bounded lexical normalization; SQLite sort operations needed a bounded writable
`/tmp` in the read-only comparison helper; Docker capability names needed exact
comparison after normalizing the `CAP_` prefix. Corrected helper runs passed with
the same frozen candidate. No product guard was weakened to accommodate them.
The candidate, preservation observer and recipe/checker suites passed 8, 28 and
16 tests respectively. Independent source/receipt review found no blocker for
this private, unconfigured lane.

All three private containers were stopped and removed by exact ID. App/gate
exited 143 after deliberate SIGTERM; the keeper exited 0. None was OOM-killed or
automatically restarted. `removed-container-ids.txt` records those IDs; the
remaining-container/network receipts are empty. Private data, source and recovery
evidence remain available. The live demo, edge, fixture and waiting native pilot
were not changed.

Live deployment must still follow the
[maintenance and preservation gate](../docker/catchplate-operator-demo/README.md#approval-and-state-preservation-gate),
including current configuration review, a fresh backup, strict startup ordering,
retained-state checks and protected-route/browser verification. This rehearsal
does not authorize Google consent, real destinations, new tokens or native Start.
