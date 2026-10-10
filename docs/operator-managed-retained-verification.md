# Private managed-Google retained-state rehearsal

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
`../serverware-operator-workspace-evidence/managed-retained.qBkamJ3p/`:
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
[maintenance and preservation gate](../docker/serverware-operator-demo/README.md#approval-and-state-preservation-gate),
including current configuration review, a fresh backup, strict startup ordering,
retained-state checks and protected-route/browser verification. This rehearsal
does not authorize Google consent, real destinations, new tokens or native Start.
