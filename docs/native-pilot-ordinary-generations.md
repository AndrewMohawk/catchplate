> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Ordinary generation grants and retained installation window

The `.375` source connects five ordinary generation decisions after the five
[authenticated deliveries](native-pilot-ordinary-deliveries.md). The supervisor
at that checkpoint composed **42 of 85** fixed jobs; **43 remained**, beginning
with `native-delivery-generationInstall`. The subsequent
[native-delivery connection](native-pilot-native-deliveries.md) reaches **49/85**;
startup still refuses before spawn.
Source checkpoints remain **36/46**, production acceptance **0/6**. Source
connection does not prove a running pilot or independent deployment approval.

## Explicit approval, observed inputs

Commissioning policy/v6 retains the thirteen v5 fields and adds exactly
`ordinaryGenerationsOriginal`. Its purpose is
`initial-driver-bootstrap-precreation-endpoints-and-ordinary-generations`.
The new value is literal canonical ASCII JSON with exactly three fields:

```json
{
  "apiVersion": "catchplate.nativePilotOrdinaryGenerationPolicy/v1",
  "installationIssuedAtUnixNanos": 1,
  "installationExpiresAtUnixNanos": 2
}
```

The numbers above show field types only; they are expired, non-operational
examples. Real values are independently approved positive signed-64-bit UNIX
nanoseconds. The interval must be current, inside the authenticated originals'
validity bounds and no longer than the assignment's maximum evidence age.
Neither BOOTTIME conversion nor a new request clock selects a replacement
interval. Legacy v5 does not authorize generation decisions.

The existing 57 key selectors are unchanged. Each `ordinary-generation-<role>`
selector must identify that role's independently selected initial-history root
public key, not its service or delivery key. No private material is generated.

The common eighteen-field grant scope is derived from the original measured
configuration and proof scope, authenticated assignment/trust, genuine earlier
bootstrap admission and the actual driver's generation recipe. That recipe's
driver receipt is the earlier bootstrap-admission hash, not a future service
effect. Dispatch, driver, descriptor, operation-coverage and authority pins are
cross-checked against their original sources. This commissioning policy selects
initial installation explicitly: `previousConfigurationBindingSha256` is null.

Each role's existing grant payload binds its actual signed delivery/Guest13,
complete runtime hash, authenticated inner history manifest, common scope and
original BOOTTIME lifetime. The outer history wrapper remains byte-for-byte
unchanged; its semantic history/root is obtained through the wrapper validator,
not by treating the wrapper itself as a legacy history document.

## Ordered composition and result verification

Only the actual pending service jobs 31–35 enter the retained generation
composer. Job 31 obtains all five verified deliveries from the preceding owner.
Subsequent decisions recheck that opened read-only boundary, exact approved
inputs, genuine process/policy/window and prior signed outputs. The public
installer may be rechecked but cannot be prepared again or fed arbitrary bytes.

The composer creates the existing `nativePilotServiceAuthorityInput/v1`
generation input. The separate purpose-specific issuer signs it. Each returned
grant must match the complete approved payload, fixed publication slot and
authenticated history root. An approval, reply or matching outer digest alone
is not a verified grant.

At job 36 the read-only handoff authenticates the fifth result and returns all
five grant/delivery/runtime/history originals. It does not authorize the next
native delivery. Failure retains ownership until the genuine coordinator has a
known terminal cleanup result; it does not renew windows or permit retry.

## Native caller uses the same interval

The native factory retains the complete identical scope from the five existing
pinned generation originals, joining it to its actual configuration, manifest,
driver, bootstrap receipt, authority keys and current trust checkpoint. Native
Recover/Prepare uses that original installation interval, rechecking freshness
and exact predecessor/successor associations. Previously the caller sampled a
new interval that could never equal the already signed grant.

Host-backed callers keep their existing behavior. Native historical predecessor
bindings are preserved; only the new commissioning policy selects initial null.
Native receiver signature, Guest13, resource-owner, checkpoint and actual
service-admission checks remain required. This fixes the caller's time binding,
not deployment, attestation or installation completion.

## Focused verification

Exact source `22e4ca2fe50030521b72e6d59b2707050c18bbd7` passed **55 focused
Python 3.11.15 controls** (42 preceding controls and 13 new controls), grammar
checks for twelve Python files, both Make source inventories and **48 relative
documentation links**. The run used a cleared environment, a private network
namespace, CPU 0 and `-I -S -B`; it started at
`2026-09-30T22:47:20.936970319Z`, finished at
`2026-09-30T22:47:24.626188444Z` and exited **0**.

One cached, offline Rust 1.88 `cargo check --offline --locked --bin
catchplate-decision-gate -j1` also exited **0**, reporting **54.91 seconds**.
Its retained run started at `2026-09-30T22:47:22.684846251Z` and finished at
`2026-09-30T22:48:18.889653491Z`. The limits were no network, one CPU, 8 GiB,
128 PIDs and a 1,200-second timeout. The missing cached image reference was
restored to the same pinned digest; its layers were already local. The logs
retain **312 library warnings and 2,439 binary warnings**. No Rust tests or
project service binaries were run.

Evidence location:
`/home/catchplate/codex-offload/catchplate/engineering-builds/22e4ca2f-generation-commissioning-Jm6lTz/`.
All eleven copied files were byte-compared; `SHA256SUMS` verifies the ten listed
original/result files. Both retained sessions ended with exit **0**.
The exact-source archive is **84,858,880 bytes**, SHA256
`d26fcebe92682a8e7a948586844f436ebbbddd4c104dcfe155901fcd90d30a42`.

No DB, app or `authority_store` module was imported. No live owner, installer,
issuer, service, cloud or paid operation ran. These focused checks leave
coverage at **42/85**, **43 jobs missing**, source checkpoints **36/46** and
production acceptance **0/6**. Complete job coverage, supervisor
entrypoint/package, provisioned authorities and connected application
allow/deny/cleanup acceptance remain required.
